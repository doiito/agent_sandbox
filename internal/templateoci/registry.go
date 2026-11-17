package templateoci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// PublicationUnconfirmed preserves the immutable operation identity after the
// registry may have accepted the manifest. It never embeds remote response data.
type PublicationUnconfirmed struct{ Digest string }

func (e *PublicationUnconfirmed) Error() string {
	return "registry manifest publication unconfirmed; verify immutable digest " + e.Digest
}

func verifyBlob(ctx context.Context, root string, d Descriptor) error {
	f, err := openRegular(root, blobName(d))
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() != d.Size {
		return errors.New("local OCI blob size mismatch")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(contextReader{ctx, f}, d.Size+1))
	if err != nil {
		return err
	}
	if n != d.Size || fmt.Sprintf("sha256:%x", h.Sum(nil)) != d.Digest {
		return errors.New("local OCI blob digest mismatch")
	}
	return nil
}

func verifyTransportLayout(ctx context.Context, root string, set artifactSet, o VerifyOptions, work string) (result error) {
	for _, role := range roles {
		if err := verifyBlob(ctx, root, set.files[role]); err != nil {
			return err
		}
	}
	if work == "" {
		work = filepath.Dir(root)
	}
	view, err := os.MkdirTemp(work, ".osv-oci-verify-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(view); err != nil {
			result = errors.Join(result, errors.New("could not remove private OCI verification view"))
		}
	}()
	for _, role := range roles {
		d := set.files[role]
		name := d.Annotations[titleKey]
		target := filepath.Join(view, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.Link(filepath.Join(root, blobName(d)), target); err != nil {
			if !errors.Is(err, syscall.EXDEV) && !os.IsPermission(err) {
				return err
			}
			if err := copyFile(ctx, root, blobName(d), view, name, d); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyDirectory(view, set, o); err != nil {
		return err
	}
	return ctx.Err()
}

type uploadReader struct {
	mu     sync.Mutex
	reader io.Reader
	hash   hash.Hash
	size   int64
}

func (r *uploadReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.reader.Read(p)
	if n > 0 {
		r.hash.Write(p[:n])
		r.size += int64(n)
	}
	return n, err
}
func (r *uploadReader) matches(d Descriptor) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size == d.Size && fmt.Sprintf("sha256:%x", r.hash.Sum(nil)) == d.Digest
}

func (r *Registry) pushBlob(ctx context.Context, root, repository string, d Descriptor) error {
	response, err := r.request(ctx, http.MethodHead, r.endpoint(repository, "blobs", d.Digest), nil, 0, "")
	if err != nil {
		return err
	}
	status := response.StatusCode
	if status == http.StatusOK {
		defer response.Body.Close()
		return responseDescriptor(response, d)
	}
	response.Body.Close()
	if status != http.StatusNotFound {
		return fmt.Errorf("registry blob lookup returned HTTP %d", status)
	}
	response, err = r.request(ctx, http.MethodPost, r.endpoint(repository, "blobs/uploads", ""), nil, 0, "application/octet-stream")
	if err != nil {
		return err
	}
	if err := responseStatus(response, http.StatusAccepted); err != nil {
		response.Body.Close()
		return err
	}
	location := r.uploadLocation(response)
	response.Body.Close()
	if location == nil {
		return errUnsafeLocation
	}
	// Preserve opaque upload state encoding and order exactly as returned.
	if location.RawQuery != "" {
		location.RawQuery += "&"
	}
	location.RawQuery += "digest=" + url.QueryEscape(d.Digest)
	input, err := openRegular(root, blobName(d))
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || info.Size() != d.Size {
		return errors.New("local upload blob size changed")
	}
	body := &uploadReader{reader: io.LimitReader(contextReader{ctx, input}, d.Size+1), hash: sha256.New()}
	response, err = r.request(ctx, http.MethodPut, location, body, d.Size, "application/octet-stream")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := responseStatus(response, http.StatusCreated); err != nil {
		return err
	}
	if !body.matches(d) {
		return errors.New("local upload blob content changed")
	}
	if value := response.Header.Get("Docker-Content-Digest"); value != "" && value != d.Digest {
		return errors.New("registry uploaded blob digest header mismatch")
	}
	return nil
}

// Push verifies all local artifacts before contacting the registry, uploads
// blobs first, then publishes and reads back the immutable manifest identity.
// reference may be a tag or the same expected digest; it never selects input.
func (r *Registry) Push(ctx context.Context, source, expectedDigest, repository, reference string, o VerifyOptions) (Descriptor, error) {
	if !repositoryOK(repository) || !validDigest(expectedDigest) {
		return Descriptor{}, errors.New("valid repository and explicit OCI SHA256 digest are required")
	}
	if reference == "" {
		reference = expectedDigest
	}
	if !referenceOK(reference, expectedDigest) {
		return Descriptor{}, errors.New("publication reference must be a tag or the same immutable digest")
	}
	set, result, err := loadLayout(source, expectedDigest, o)
	if err != nil {
		return Descriptor{}, err
	}
	if err := verifyTransportLayout(ctx, source, set, o, r.workDir); err != nil {
		return Descriptor{}, err
	}
	raw, err := readBlob(source, result, ManifestMediaType, metadataLimit)
	if err != nil {
		return Descriptor{}, err
	}
	envelope, _, err := parseEnvelope(raw)
	if err != nil {
		return Descriptor{}, err
	}
	if err := r.pushBlob(ctx, source, repository, envelope.Config); err != nil {
		return Descriptor{}, err
	}
	for _, role := range roles {
		if err := r.pushBlob(ctx, source, repository, set.files[role]); err != nil {
			return Descriptor{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Descriptor{}, err
	}
	response, err := r.request(ctx, http.MethodPut, r.endpoint(repository, "manifests", reference), bytes.NewReader(raw), int64(len(raw)), ManifestMediaType)
	if err != nil {
		return result, &PublicationUnconfirmed{result.Digest}
	}
	if err := responseStatus(response, http.StatusCreated); err != nil {
		response.Body.Close()
		return Descriptor{}, err
	}
	ack := response.Header.Get("Docker-Content-Digest")
	response.Body.Close()
	if ack != "" && ack != result.Digest {
		return result, &PublicationUnconfirmed{result.Digest}
	}
	readback, got, err := r.manifest(ctx, repository, result.Digest)
	if err != nil || got.Digest != result.Digest || !bytes.Equal(raw, readback) {
		return result, &PublicationUnconfirmed{result.Digest}
	}
	return result, nil
}

func (r *Registry) downloadBlob(ctx context.Context, repository, root string, d Descriptor) error {
	if _, err := os.Lstat(filepath.Join(root, blobName(d))); err == nil {
		return verifyBlob(ctx, root, d)
	} else if !os.IsNotExist(err) {
		return err
	}
	response, err := r.request(ctx, http.MethodGet, r.endpoint(repository, "blobs", d.Digest), nil, 0, "")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := responseStatus(response, http.StatusOK); err != nil {
		return err
	}
	if err := responseDescriptor(response, d); err != nil {
		return err
	}
	target := filepath.Join(root, blobName(d))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	defer output.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(output, h), io.LimitReader(contextReader{ctx, response.Body}, d.Size+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("registry blob transfer failed")
	}
	if n != d.Size || fmt.Sprintf("sha256:%x", h.Sum(nil)) != d.Digest {
		return errors.New("registry blob size or digest mismatch")
	}
	return output.Sync()
}

func writeLayoutIndex(root string, d Descriptor) error {
	marker, _ := json.Marshal(map[string]string{"imageLayoutVersion": "1.0.0"})
	if _, err := writeFile(root, "oci-layout", marker); err != nil {
		return err
	}
	data, err := json.Marshal(index{2, IndexMediaType, []Descriptor{d}})
	if err != nil {
		return err
	}
	_, err = writeFile(root, "index.json", data)
	return err
}

// Pull publishes a complete verified OCI layout. Small authenticated metadata
// precedes all large downloads. Import remains a separate, explicit operation.
func (r *Registry) Pull(ctx context.Context, expectedDigest, repository, destination string, o VerifyOptions) (Descriptor, error) {
	if !repositoryOK(repository) || !validDigest(expectedDigest) {
		return Descriptor{}, errors.New("pull requires a valid repository and externally pinned OCI SHA256 digest")
	}
	if err := o.validate(); err != nil {
		return Descriptor{}, err
	}
	var result Descriptor
	err := publish(ctx, destination, func(stage string) error {
		raw, d, err := r.manifest(ctx, repository, expectedDigest)
		if err != nil {
			return err
		}
		envelope, files, err := parseEnvelope(raw)
		if err != nil {
			return err
		}
		if _, err := writeFile(stage, blobName(d), raw); err != nil {
			return err
		}
		if err := writeLayoutIndex(stage, d); err != nil {
			return err
		}
		if err := r.downloadBlob(ctx, repository, stage, envelope.Config); err != nil {
			return err
		}
		for _, role := range []string{"manifest", "signature"} {
			if err := r.downloadBlob(ctx, repository, stage, files[role]); err != nil {
				return err
			}
		}
		// loadLayout needs only the metadata above, and authenticates descriptor
		// sizes/hashes against the original trusted key before any large GET.
		set, _, err := loadLayout(stage, expectedDigest, o)
		if err != nil {
			return err
		}
		for _, role := range []string{"sbom", "kernel", "image"} {
			if err := r.downloadBlob(ctx, repository, stage, set.files[role]); err != nil {
				return err
			}
		}
		if err := verifyTransportLayout(ctx, stage, set, o, stage); err != nil {
			return err
		}
		result = d
		return ctx.Err()
	})
	if err != nil {
		return Descriptor{}, err
	}
	return result, nil
}
