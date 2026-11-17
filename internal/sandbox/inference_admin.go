package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

type InferenceBillAdminRequest struct {
	Operation string
	Tenant    string
	TaskID    string
	Path      string
}

type InferenceBillAdminReport struct {
	Protocol  string `json:"protocol"`
	Operation string `json:"operation"`
	Tenant    string `json:"tenant"`
	TaskID    string `json:"task_id"`
	SHA256    string `json:"sha256"`
	Verified  bool   `json:"verified"`
	Retired   bool   `json:"retired"`
}

type inferenceBillArchive struct {
	Protocol string          `json:"protocol"`
	SHA256   string          `json:"sha256"`
	Record   json.RawMessage `json:"record"`
}

func validateInferenceArchive(archive inferenceBillArchive) (inferenceBinding, error) {
	var record inferenceTaskRecord
	if archive.Protocol != "osv-sandbox-inference-archive/v1" || !validSHA256Hex(archive.SHA256) ||
		len(archive.Record) > inferenceLedgerFileLimit || decodeInferenceJSON(archive.Record, &record) != nil || !record.Closed {
		return inferenceBinding{}, errors.New("invalid closed inference archive")
	}
	if _, err := record.bill(); err != nil {
		return inferenceBinding{}, errors.New("invalid inference archive accounting")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, archive.Record) || inferenceDigest(canonical) != archive.SHA256 {
		return inferenceBinding{}, errors.New("inference archive digest or canonical record mismatch")
	}
	return record.Binding, nil
}

func inferenceAdminDirectory(path string, create bool) (*os.File, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == path {
		return nil, "", errors.New("archive path must be an absolute canonical file path")
	}
	parent := filepath.Dir(path)
	if create {
		if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, "", errors.New("cannot create archive directory")
		}
	}
	directory, err := os.OpenFile(parent, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", errors.New("cannot open archive directory")
	}
	info, err := directory.Stat()
	if err != nil || !inferenceOwned(info) || info.Mode().Perm()&0o022 != 0 {
		directory.Close()
		return nil, "", errors.New("archive directory must be root-owned and not writable by group or other")
	}
	return directory, filepath.Base(path), nil
}

func inferenceAdminPath(directory *os.File, name string) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(directory.Fd()), 10) + "/" + name
}

func saveInferenceArchive(path string, archive inferenceBillArchive) error {
	if _, err := validateInferenceArchive(archive); err != nil {
		return err
	}
	directory, name, err := inferenceAdminDirectory(path, true)
	if err != nil {
		return err
	}
	defer directory.Close()
	id, err := randomID()
	if err != nil {
		return err
	}
	temporary := inferenceAdminPath(directory, ".bill-export-"+id)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("cannot create private archive temporary file")
	}
	defer func() { _ = file.Close(); _ = os.Remove(temporary) }()
	data, err := marshalInferenceJSON(archive)
	if err != nil {
		return err
	}
	if n, err := file.Write(data); err != nil || n != len(data) || file.Sync() != nil {
		return errors.New("cannot persist inference archive")
	}
	// Publish without replacing an existing file. Retire repeats validation and
	// file/directory sync, including recovery after an interrupted publication.
	if err := os.Link(temporary, inferenceAdminPath(directory, name)); err != nil {
		return errors.New("cannot publish inference archive; destination must not exist")
	}
	if os.Remove(temporary) != nil || directory.Sync() != nil {
		return errors.New("inference archive publication acknowledgement uncertain; verify the existing archive")
	}
	return nil
}

func readInferenceArchive(path string, durable bool) (inferenceBillArchive, inferenceBinding, error) {
	var archive inferenceBillArchive
	directory, name, err := inferenceAdminDirectory(path, false)
	if err != nil {
		return archive, inferenceBinding{}, err
	}
	defer directory.Close()
	file, err := os.OpenFile(inferenceAdminPath(directory, name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return archive, inferenceBinding{}, errors.New("cannot open inference archive")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !inferenceOwned(info) || info.Mode().Perm()&0o077 != 0 || info.Size() > inferenceLedgerFileLimit+(64<<10) {
		return archive, inferenceBinding{}, errors.New("inference archive must be a private root-owned regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, inferenceLedgerFileLimit+(64<<10)+1))
	if err != nil || len(data) > inferenceLedgerFileLimit+(64<<10) || decodeInferenceJSON(data, &archive) != nil {
		return archive, inferenceBinding{}, errors.New("invalid bounded inference archive")
	}
	binding, err := validateInferenceArchive(archive)
	if err != nil {
		return archive, binding, err
	}
	if durable && (file.Sync() != nil || directory.Sync() != nil) {
		return archive, binding, errors.New("cannot confirm durable inference archive")
	}
	return archive, binding, nil
}

// RunInferenceBillAdmin implements the shipped root-only maintenance commands.
// It never opens the live ledger or replays a model.
func RunInferenceBillAdmin(ctx context.Context, config EgressServiceConfig, request InferenceBillAdminRequest) (InferenceBillAdminReport, error) {
	report := InferenceBillAdminReport{Protocol: "osv-sandbox-inference-admin/v1", Operation: request.Operation}
	if os.Geteuid() != 0 {
		return report, errors.New("inference bill maintenance requires root")
	}
	if request.Operation != "bill-verify" && (config.Inference == nil || !config.GuestProxy || !filepath.IsAbs(config.SocketPath)) {
		return report, errors.New("inference bill maintenance requires configured inference service")
	}
	client := newInferenceRootClient(config.SocketPath)
	var archive inferenceBillArchive
	var binding inferenceBinding
	var err error
	switch request.Operation {
	case "bill-export":
		if !safeTenantID(request.Tenant) || !canonicalJobID(request.TaskID) {
			return report, errors.New("bill-export requires tenant and canonical task ID")
		}
		data, err := client.exchange(ctx, "inspect", inferenceRootRequest{Binding: inferenceBinding{Tenant: request.Tenant, TaskID: request.TaskID}})
		if err != nil {
			return report, err
		}
		var inspected inferenceRootReply
		if decodeInferenceJSON(data, &inspected) != nil || inspected.Protocol != inferenceRootProtocol || inspected.Bill == nil || !inspected.Bill.Closed {
			return report, errors.New("only a closed inference bill can be exported")
		}
		binding = inferenceBinding{Tenant: inspected.Bill.Tenant, TaskID: inspected.Bill.TaskID, VMID: inspected.Bill.VMID, LeaseID: inspected.Bill.LeaseID}
		if binding.Tenant != request.Tenant || binding.TaskID != request.TaskID || validateInferenceBill(*inspected.Bill, binding) != nil {
			return report, errors.New("invalid inference bill owner response")
		}
		data, err = client.exchange(ctx, "export", inferenceRootRequest{Binding: binding})
		if err != nil {
			return report, err
		}
		var exported inferenceRootReply
		if decodeInferenceJSON(data, &exported) != nil || exported.Protocol != inferenceRootProtocol || len(exported.Record) == 0 {
			return report, errors.New("invalid inference export response")
		}
		archive = inferenceBillArchive{Protocol: "osv-sandbox-inference-archive/v1", SHA256: exported.SHA256, Record: exported.Record}
		if actual, err := validateInferenceArchive(archive); err != nil || actual != binding {
			return report, errors.New("inference export digest or owner mismatch")
		}
		if err := saveInferenceArchive(request.Path, archive); err != nil {
			return report, err
		}
	case "bill-verify", "bill-retire":
		archive, binding, err = readInferenceArchive(request.Path, true)
		if err != nil {
			return report, err
		}
		if request.Operation == "bill-retire" {
			data, err := client.exchange(ctx, "retire", inferenceRootRequest{Binding: binding, ExportedSHA256: archive.SHA256})
			if err != nil {
				return report, err
			}
			var reply inferenceRootReply
			if decodeInferenceJSON(data, &reply) != nil || reply.Protocol != inferenceRootProtocol || !reply.Retired {
				return report, errors.New("inference retirement acknowledgement unavailable")
			}
			report.Retired = true
		}
	default:
		return report, errors.New("unknown inference bill maintenance operation")
	}
	report.Tenant, report.TaskID, report.SHA256, report.Verified = binding.Tenant, binding.TaskID, archive.SHA256, true
	return report, nil
}
