package sandbox

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestSessionFileInfoRejectsForgedBindingAndMode(t *testing.T) {
	base := SessionFileInfo{Name: "item", Path: "/workspace/item", Type: "file",
		Size: 3, Mode: 0o100600, Permissions: "rw-------", Owner: "agent",
		Group: "agent", ModifiedTimeMS: 1_800_000_000_000}
	if !validSessionFileInfo(base, "/workspace/item", "item") {
		t.Fatal("valid file metadata rejected")
	}
	for name, mutate := range map[string]func(*SessionFileInfo){
		"path escape":         func(info *SessionFileInfo) { info.Path = "/etc/passwd" },
		"type mismatch":       func(info *SessionFileInfo) { info.Type = "directory" },
		"mode mismatch":       func(info *SessionFileInfo) { info.Mode = 0o040600 },
		"permission mismatch": func(info *SessionFileInfo) { info.Permissions = "rwxrwxrwx" },
		"future time":         func(info *SessionFileInfo) { info.ModifiedTimeMS = 4_102_444_800_001 },
		"control owner":       func(info *SessionFileInfo) { info.Owner = "bad\nname" },
		"unbound target":      func(info *SessionFileInfo) { target := "/etc/passwd"; info.SymlinkTarget = &target },
		"invalid xattr key":   func(info *SessionFileInfo) { info.Metadata = map[string]string{"bad key": "v"} },
		"control xattr value": func(info *SessionFileInfo) { info.Metadata = map[string]string{"key": "bad\nvalue"} },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if validSessionFileInfo(value, "/workspace/item", "item") {
				t.Fatal("forged metadata accepted")
			}
		})
	}
	other := base
	other.Name, other.Path = "other", "/workspace/other"
	if !validateSessionFileInfoList("/workspace", []string{"item", "other"}, []SessionFileInfo{base, other}) {
		t.Fatal("ordered list metadata rejected")
	}
	if validateSessionFileInfoList("/workspace", []string{"item", "other"}, []SessionFileInfo{other, base}) {
		t.Fatal("reordered metadata accepted")
	}
	target := "/etc/passwd"
	link := base
	link.Name, link.Path, link.Type = "link", "/workspace/link", "symlink"
	link.Mode, link.Permissions, link.Size, link.SymlinkTarget = 0o120777, "rwxrwxrwx", int64(len(target)), &target
	if !validSessionFileInfo(link, "/workspace/link", "link") {
		t.Fatal("bound symlink metadata rejected")
	}
	link.SymlinkTarget = nil
	if validSessionFileInfo(link, "/workspace/link", "link") {
		t.Fatal("symlink without target accepted")
	}
	withMetadata := base
	withMetadata.Metadata = map[string]string{"label": "proof"}
	if !validSessionFileInfo(withMetadata, "/workspace/item", "item") {
		t.Fatal("valid E2B xattr metadata rejected")
	}
}

func TestSessionRequestEnforcesTemplateResourcesAndCommandPolicy(t *testing.T) {
	config := Config{Backend: "firecracker-linux", AllowedEntrypoints: []string{"/bin/sh"}}
	config.ApplyDefaults()
	create := SessionCreateRequest{Backend: "firecracker-linux", ArtifactManifestSHA256: strings.Repeat("a", 64)}
	create.Normalize(config)
	if err := create.Validate(config); err != nil {
		t.Fatalf("valid session was rejected: %v", err)
	}
	create.Network = "all"
	if err := create.Validate(config); err == nil {
		t.Fatal("session gained an unsupported network mode")
	}
	create.Network = "none"
	create.TTLMS = sessionMinTTLMS - 1
	if err := create.Validate(config); err == nil {
		t.Fatal("session accepted a sub-second TTL")
	}
	create.TTLMS = sessionMaxTTLMS + 1
	if err := create.Validate(config); err == nil {
		t.Fatal("session exceeded host TTL")
	}
	command := SessionCommandRequest{Entrypoint: "/bin/sh", Args: []string{"-c", "true"}}
	command.Normalize(config)
	if err := command.Validate(config, 128, 1); err != nil {
		t.Fatalf("valid session command was rejected: %v", err)
	}
	command.Entrypoint = "/bin/id"
	if err := command.Validate(config, 128, 1); err == nil {
		t.Fatal("session command bypassed backend entrypoint policy")
	}
}

func TestSessionFileRequestBoundsAndPath(t *testing.T) {
	valid := SessionFileRequest{Action: "read", Path: "/workspace/a/b"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid read rejected: %v", err)
	}
	if err := (SessionFileRequest{Action: "info", Path: "/workspace"}).Validate(); err != nil {
		t.Fatalf("root inode info rejected: %v", err)
	}
	for _, path := range []string{"/tmp/a", "/workspace/../a", "/workspace/a//b", "/workspace/a/./b", "/workspace/link\\x", "/workspace/"} {
		if err := (SessionFileRequest{Action: "read", Path: path}).Validate(); !errors.Is(err, ErrInvalidFilePath) {
			t.Fatalf("unsafe path %q accepted or misclassified: %v", path, err)
		}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte{0, 1, 255})
	if err := (SessionFileRequest{Action: "write", Path: "/workspace/data", DataBase64: &encoded}).Validate(); err != nil {
		t.Fatalf("binary write rejected: %v", err)
	}
	if err := (SessionFileRequest{Action: "write", Path: "/workspace/data", DataBase64: &encoded,
		Metadata: map[string]string{"label": "proof"}}).Validate(); err != nil {
		t.Fatalf("bounded E2B metadata write rejected: %v", err)
	}
	if err := (SessionFileRequest{Action: "write", Path: "/workspace/data", DataBase64: &encoded,
		Metadata: map[string]string{"bad key": "proof"}}).Validate(); err == nil {
		t.Fatal("unsafe E2B metadata key accepted")
	}
	if err := (SessionFileRequest{Action: "info", Path: "/workspace/data",
		Metadata: map[string]string{"label": "proof"}}).Validate(); err == nil {
		t.Fatal("read-only info accepted a metadata mutation")
	}
	noncanonical := "AA==\n"
	if err := (SessionFileRequest{Action: "write", Path: "/workspace/data", DataBase64: &noncanonical}).Validate(); err == nil {
		t.Fatal("noncanonical base64 accepted")
	}
	tooLarge := base64.StdEncoding.EncodeToString(make([]byte, sessionFileLimit+1))
	if err := (SessionFileRequest{Action: "write", Path: "/workspace/data", DataBase64: &tooLarge}).Validate(); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("oversized file accepted or misclassified: %v", err)
	}
	for _, action := range []string{"list", "stat"} {
		if err := (SessionFileRequest{Action: action, Path: "/workspace"}).Validate(); err != nil {
			t.Fatalf("%s root rejected: %v", action, err)
		}
	}
	for _, action := range []string{"list", "stat", "delete", "mkdir"} {
		if err := (SessionFileRequest{Action: action, Path: "/workspace/sub/item"}).Validate(); err != nil {
			t.Fatalf("%s child rejected: %v", action, err)
		}
		if err := (SessionFileRequest{Action: action, Path: "/workspace/../escape"}).Validate(); !errors.Is(err, ErrInvalidFilePath) {
			t.Fatalf("%s traversal accepted: %v", action, err)
		}
	}
	if err := (SessionFileRequest{Action: "delete", Path: "/workspace"}).Validate(); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("root delete accepted: %v", err)
	}
	deep := "/workspace/" + strings.Repeat("d/", 16) + "d"
	if err := (SessionFileRequest{Action: "mkdir", Path: deep}).Validate(); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("deep mkdir accepted: %v", err)
	}
	if err := (SessionFileRequest{Action: "mkdir", Path: "/workspace/a", DataBase64: &encoded}).Validate(); err == nil {
		t.Fatal("mkdir accepted data_base64")
	}
	if err := (SessionFileRequest{Action: "list", Path: "/workspace", DataBase64: &encoded}).Validate(); err == nil {
		t.Fatal("list accepted data_base64")
	}
}

func TestWorkspaceMutationRequestsAndErrors(t *testing.T) {
	destination := "/workspace/new"
	if err := (SessionFileRequest{Action: "rename", Path: "/workspace/old", Destination: &destination}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/workspace", "/etc/out", "/workspace/../out"} {
		if err := (SessionFileRequest{Action: "rename", Path: "/workspace/old", Destination: &target}).Validate(); !errors.Is(err, ErrInvalidFilePath) {
			t.Fatalf("destination %q: %v", target, err)
		}
	}
	if err := (SessionFileRequest{Action: "rename", Path: "/workspace/old"}).Validate(); err == nil {
		t.Fatal("missing destination accepted")
	}
	if err := (SessionFileRequest{Action: "remove", Path: "/workspace/tree", Destination: &destination}).Validate(); err == nil {
		t.Fatal("remove accepted destination")
	}
	if err := (SessionFileRequest{Action: "remove", Path: "/workspace"}).Validate(); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatal("workspace root removal accepted")
	}
	for _, err := range []error{ErrFileConflict, ErrFileOperationLimit} {
		message, code := launcherSessionErrorFields(err)
		if got := launcherSessionError(launcherSessionResponse{Error: message, Code: code}); !errors.Is(got, err) {
			t.Fatalf("error roundtrip %v -> %v", err, got)
		}
	}
}

func TestSessionFileEntriesRequireBoundedSortedNames(t *testing.T) {
	if err := validateSessionFileEntries([]string{"a", "sub"}); err != nil {
		t.Fatalf("valid entries rejected: %v", err)
	}
	for _, entries := range [][]string{{"z", "a"}, {"a", "a"}, {"../escape"}, {"a\\b"}, {"x\x00y"}} {
		if err := validateSessionFileEntries(entries); err == nil {
			t.Fatalf("unsafe list accepted: %q", entries)
		}
	}
	many := make([]string, sessionFileListLimit+1)
	for i := range many {
		many[i] = string(rune(i + 0x100))
	}
	if err := validateSessionFileEntries(many); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("oversized list accepted: %v", err)
	}
}
