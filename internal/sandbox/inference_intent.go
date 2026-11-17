package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const inferenceIntentName = "inference.binding.json"

type inferenceIntent struct {
	Protocol string           `json:"protocol"`
	Binding  inferenceBinding `json:"binding"`
}

func openInferenceIntentDirectory(workdir string) (*os.File, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(workdir) || filepath.Clean(workdir) != workdir {
		return nil, errors.New("inference binding intent requires a managed root workdir")
	}
	directory, err := os.OpenFile(workdir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := directory.Stat()
	if err != nil || !inferenceOwned(info) || info.Mode().Perm()&0o022 != 0 {
		directory.Close()
		return nil, errors.New("untrusted inference binding workdir")
	}
	return directory, nil
}

func inferenceIntentPath(directory *os.File, name string) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(directory.Fd()), 10) + "/" + name
}

func readInferenceIntentAt(directory *os.File) (inferenceBinding, error) {
	file, err := os.OpenFile(inferenceIntentPath(directory, inferenceIntentName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return inferenceBinding{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !inferencePrivateFile(info) || info.Size() > 4096 {
		return inferenceBinding{}, errors.New("invalid inference binding intent file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	var intent inferenceIntent
	if err != nil || len(data) > 4096 || decodeInferenceJSON(data, &intent) != nil || intent.Protocol != "osv-sandbox-inference-intent/v1" || !intent.Binding.valid() {
		return inferenceBinding{}, errors.New("invalid inference binding intent")
	}
	return intent.Binding, nil
}

// Called while holding the VM's boot mutex and exclusive managed run_root.
// The durable intent precedes bind, including when that RPC loses its ACK.
func bindVMInference(ctx context.Context, workdir, egressSocket string, binding inferenceBinding) error {
	if !binding.valid() || egressSocket == "" || !validJobInstanceID(filepath.Base(workdir)) || !strings.HasPrefix(filepath.Base(workdir), "job-"+binding.VMID+"-") {
		return errors.New("invalid VM inference grant")
	}
	directory, err := openInferenceIntentDirectory(workdir)
	if err != nil {
		return err
	}
	defer directory.Close()
	prior, err := readInferenceIntentAt(directory)
	if err == nil && prior != binding {
		return errors.New("VM inference binding intent already belongs to another task")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		data, err := json.Marshal(inferenceIntent{Protocol: "osv-sandbox-inference-intent/v1", Binding: binding})
		if err != nil {
			return err
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		temporary := inferenceIntentPath(directory, ".inference-binding-"+id)
		file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close(); _ = os.Remove(temporary) }()
		if n, err := file.Write(data); err != nil || n != len(data) || file.Sync() != nil {
			return errors.New("cannot persist VM inference binding intent")
		}
		if err := os.Rename(temporary, inferenceIntentPath(directory, inferenceIntentName)); err != nil || directory.Sync() != nil {
			return errors.New("cannot commit VM inference binding intent")
		}
	}
	_, err = newInferenceRootClient(egressSocket).task(ctx, "bind", binding)
	return err
}

// Absence keeps old profiles independent of egress. A present intent must be
// acknowledged closed before either VM teardown or orphan recovery deletes it.
func closeVMInference(workdir, egressSocket string) error {
	// Avoid opening or tightening legacy workdirs that never had an intent.
	if _, err := os.Lstat(filepath.Join(workdir, inferenceIntentName)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	directory, err := openInferenceIntentDirectory(workdir)
	if err != nil {
		return err
	}
	defer directory.Close()
	binding, err := readInferenceIntentAt(directory)
	if err != nil {
		return err
	}
	if !validJobInstanceID(filepath.Base(workdir)) || !strings.HasPrefix(filepath.Base(workdir), "job-"+binding.VMID+"-") {
		return errors.New("inference binding intent does not match its physical VM workdir")
	}
	if egressSocket == "" {
		return errors.New("inference binding recovery requires its egress service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = newInferenceRootClient(egressSocket).task(ctx, "close", binding)
	return err
}
