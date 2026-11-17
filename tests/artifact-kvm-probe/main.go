// Probe native archive RPCs against an installed API and an actual existing VM.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	controlv1 "github.com/doiito/agent_sandbox/api/control/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type report struct {
	Passed    bool     `json:"passed"`
	SessionID string   `json:"session_id"`
	Cases     []string `json:"cases"`
	Failure   string   `json:"failure,omitempty"`
}

func (r *report) check(name string, condition bool, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !condition {
		return errors.New(name)
	}
	r.Cases = append(r.Cases, name)
	fmt.Println("PASS grpc-artifact-" + name)
	return nil
}

func main() {
	root := flag.String("root", "", "isolated installed fixture root")
	session := flag.String("session", "", "existing actual KVM session")
	output := flag.String("output", "", "new result path")
	flag.Parse()
	if *root == "" || *session == "" || *output == "" {
		flag.Usage()
		os.Exit(2)
	}
	r := report{SessionID: *session}
	err := run(*root, &r)
	r.Passed = err == nil
	if err != nil {
		r.Failure = err.Error()
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	file, writeErr := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if writeErr == nil {
		_, writeErr = file.Write(append(data, '\n'))
		writeErr = errors.Join(writeErr, file.Close())
	}
	if err != nil || writeErr != nil {
		fmt.Fprintln(os.Stderr, errors.Join(err, writeErr))
		os.Exit(1)
	}
}

func run(root string, r *report) error {
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(root, name)) }
	config, err := read("config.production.json")
	if err != nil {
		return err
	}
	var settings struct{ Listen string }
	if err := json.Unmarshal(config, &settings); err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(settings.Listen)
	if err != nil {
		return err
	}
	ca, err := read("tls/ca.crt")
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("invalid fixture CA")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(root, "tls/client.crt"), filepath.Join(root, "tls/client.key"))
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(net.JoinHostPort("localhost", port), grpc.WithNoProxy(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13,
			RootCAs: pool, Certificates: []tls.Certificate{pair}})))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	tokens := make([]context.Context, 0, 2)
	for _, name := range []string{"secrets/token", "secrets/token-b"} {
		token, err := read(name)
		if err != nil {
			return err
		}
		tokens = append(tokens, metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+strings.TrimSpace(string(token))))
	}
	client := controlv1.NewControlClient(conn)
	sid := r.SessionID
	create := &controlv1.CreateSessionArtifactRequest{Id: proto.String(sid), Body: &controlv1.SessionArtifactCreateRequestInput{Path: proto.String("/workspace/export")}}
	info, err := client.CreateSessionArtifact(tokens[0], create)
	if err := r.check("typed-create-bound-metadata", info.GetSessionId() == sid && info.GetFormat() == "tar" && info.GetSize() > 512<<10, err); err != nil {
		return err
	}
	request := &controlv1.ReadSessionArtifactRequest{Id: proto.String(sid), Artifact: info.Id,
		Body: &controlv1.SessionArtifactReadRequestInput{Length: proto.Uint64(512 << 10), Offset: proto.Uint64(0)}}
	remove := &controlv1.DeleteSessionArtifactRequest{Id: proto.String(sid), Artifact: info.Id}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(tokens[0]), 4*time.Second)
		defer stop()
		_, _ = client.DeleteSessionArtifact(cleanup, remove)
	}()
	hash := sha256.New()
	for offset := uint64(0); offset < info.GetSize(); {
		request.Body.Offset = proto.Uint64(offset)
		chunk, err := client.ReadSessionArtifact(tokens[0], request)
		if err != nil {
			return err
		}
		data := chunk.GetDataBase64()
		wanted := min(uint64(512<<10), info.GetSize()-offset)
		sum := sha256.Sum256(data)
		if chunk.GetSessionId() != sid || chunk.GetId() != info.GetId() || chunk.GetOffset() != offset ||
			chunk.GetTotalSize() != info.GetSize() || chunk.GetArchiveSha256() != info.GetSha256() ||
			uint64(len(data)) != wanted || hex.EncodeToString(sum[:]) != chunk.GetDataSha256() ||
			chunk.GetEof() != (offset+wanted == info.GetSize()) {
			return errors.New("native binary chunk identity, size or digest changed")
		}
		_, _ = hash.Write(data)
		offset += wanted
	}
	if err := r.check("raw-protobuf-binary-multichunk-full-sha256", hex.EncodeToString(hash.Sum(nil)) == info.GetSha256(), nil); err != nil {
		return err
	}
	request.Body.Offset = info.Size
	chunk, err := client.ReadSessionArtifact(tokens[0], request)
	if err := r.check("empty-eof", chunk.GetEof() && len(chunk.GetDataBase64()) == 0, err); err != nil {
		return err
	}
	request.Body.Offset = proto.Uint64(info.GetSize() + 1)
	_, err = client.ReadSessionArtifact(tokens[0], request)
	if err := r.check("range-is-out-of-range", status.Code(err) == codes.OutOfRange, nil); err != nil {
		return err
	}
	request.Body.Offset = proto.Uint64(0)
	for name, call := range map[string]func() error{
		"foreign-create-hidden": func() error { _, e := client.CreateSessionArtifact(tokens[1], create); return e },
		"foreign-read-hidden":   func() error { _, e := client.ReadSessionArtifact(tokens[1], request); return e },
		"foreign-delete-hidden": func() error { _, e := client.DeleteSessionArtifact(tokens[1], remove); return e },
	} {
		if err := r.check(name, status.Code(call()) == codes.NotFound, nil); err != nil {
			return err
		}
	}
	_, err = client.DeleteSessionArtifact(tokens[0], remove)
	if err := r.check("typed-delete", err == nil, err); err != nil {
		return err
	}
	_, err = client.ReadSessionArtifact(tokens[0], request)
	return r.check("deleted-read-is-not-found", status.Code(err) == codes.NotFound, nil)
}
