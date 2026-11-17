package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const inferenceLedgerFileLimit = 1 << 20

type inferenceBinding struct {
	Tenant  string `json:"tenant"`
	TaskID  string `json:"task_id"`
	VMID    string `json:"vm_id"`
	LeaseID string `json:"lease_id"`
}

func (b inferenceBinding) valid() bool {
	return safeTenantID(b.Tenant) && canonicalJobID(b.TaskID) && canonicalJobID(b.VMID) && canonicalJobID(b.LeaseID)
}

type InferenceInvocationReceipt struct {
	ID             string         `json:"id"`
	Endpoint       string         `json:"endpoint"`
	State          string         `json:"state"`
	Epoch          string         `json:"epoch"`
	Price          InferencePrice `json:"price"`
	InputBytes     uint64         `json:"input_bytes"`
	MaxOutputBytes uint64         `json:"max_output_bytes"`
	OutputBytes    uint64         `json:"output_bytes"`
	Dispatched     bool           `json:"dispatched"`
	HTTPStatus     int            `json:"http_status"`
	Code           string         `json:"code,omitempty"`
	ReservedUnits  InferenceUnits `json:"reserved_units"`
	SettledUnits   InferenceUnits `json:"settled_units"`
	StartedAt      time.Time      `json:"started_at"`
	FinishedAt     *time.Time     `json:"finished_at,omitempty"`
	DurationMS     uint64         `json:"duration_ms"`
}

type InferenceBill struct {
	Protocol       string                       `json:"protocol"`
	Tenant         string                       `json:"tenant"`
	TaskID         string                       `json:"task_id"`
	VMID           string                       `json:"vm_id"`
	LeaseID        string                       `json:"lease_id"`
	Closed         bool                         `json:"closed"`
	Unit           string                       `json:"unit"`
	MaxInvocations int                          `json:"max_invocations"`
	BudgetUnits    *InferenceUnits              `json:"budget_units,omitempty"`
	SettledUnits   InferenceUnits               `json:"settled_units"`
	HeldUnits      InferenceUnits               `json:"held_units"`
	Invocations    []InferenceInvocationReceipt `json:"invocations"`
}

type inferenceTaskRecord struct {
	Version        int                          `json:"version"`
	Binding        inferenceBinding             `json:"binding"`
	Closed         bool                         `json:"closed"`
	MaxInvocations int                          `json:"max_invocations"`
	BudgetUnits    *InferenceUnits              `json:"budget_units,omitempty"`
	Invocations    []InferenceInvocationReceipt `json:"invocations"`
}

func inferenceSum(a, b InferenceUnits) (InferenceUnits, error) {
	if uint64(b) > math.MaxUint64-uint64(a) {
		return 0, errors.New("inference units overflow")
	}
	return a + b, nil
}
func inferenceBudget(a, b *InferenceUnits) *InferenceUnits {
	if a == nil && b == nil {
		return nil
	}
	value := b
	if a != nil && (b == nil || *a < *b) {
		value = a
	}
	copy := *value
	return &copy
}

func (r *inferenceTaskRecord) bill() (InferenceBill, error) {
	result := InferenceBill{Protocol: "osv-sandbox-inference-bill/v1", Unit: "microcredits", Tenant: r.Binding.Tenant,
		TaskID: r.Binding.TaskID, VMID: r.Binding.VMID, LeaseID: r.Binding.LeaseID, Closed: r.Closed,
		MaxInvocations: r.MaxInvocations, BudgetUnits: inferenceBudget(r.BudgetUnits, nil),
		Invocations: append([]InferenceInvocationReceipt{}, r.Invocations...)}
	if r.Version != 1 || !r.Binding.valid() || r.MaxInvocations < 1 || r.MaxInvocations > 256 || len(r.Invocations) > r.MaxInvocations {
		return result, errors.New("invalid inference task record")
	}
	ids := map[string]bool{}
	for _, invocation := range r.Invocations {
		if !canonicalJobID(invocation.ID) || ids[invocation.ID] || !canonicalJobID(invocation.Epoch) ||
			!inferenceEndpointName.MatchString(invocation.Endpoint) || invocation.InputBytes > egressRequestLimit ||
			invocation.MaxOutputBytes < 1 || invocation.MaxOutputBytes > egressResponseLimit ||
			invocation.OutputBytes > invocation.MaxOutputBytes+1 || invocation.HTTPStatus != 0 && (invocation.HTTPStatus < 100 || invocation.HTTPStatus > 599) ||
			invocation.StartedAt.IsZero() || invocation.DurationMS > 300000 || invocation.Code != "" && !safeEgressCode(invocation.Code) {
			return result, errors.New("invalid inference invocation record")
		}
		ids[invocation.ID] = true
		reserved, err := invocation.Price.cost(invocation.InputBytes, invocation.MaxOutputBytes)
		if err != nil || reserved != invocation.ReservedUnits || invocation.SettledUnits > reserved {
			return result, errors.New("invalid inference reservation")
		}
		var held InferenceUnits
		switch invocation.State {
		case "reserved":
			if r.Closed || invocation.FinishedAt != nil || invocation.SettledUnits != 0 || invocation.Dispatched || invocation.HTTPStatus != 0 || invocation.OutputBytes != 0 || invocation.Code != "" {
				return result, errors.New("invalid pending inference")
			}
			held = reserved
		case "uncertain":
			if invocation.FinishedAt == nil || invocation.SettledUnits != 0 || invocation.Code == "" {
				return result, errors.New("invalid uncertain inference")
			}
			held = reserved
		case "succeeded", "failed":
			var expected InferenceUnits
			if invocation.Dispatched {
				expected, err = invocation.Price.cost(invocation.InputBytes, min(invocation.OutputBytes, invocation.MaxOutputBytes))
			} else if invocation.OutputBytes != 0 || invocation.HTTPStatus != 0 {
				return result, errors.New("unstarted inference has output")
			}
			if err != nil || expected != invocation.SettledUnits || invocation.FinishedAt == nil ||
				invocation.State == "succeeded" && (!invocation.Dispatched || invocation.OutputBytes > invocation.MaxOutputBytes || invocation.HTTPStatus < 200 || invocation.HTTPStatus > 299 || invocation.Code != "") ||
				invocation.State == "failed" && invocation.Code == "" {
				return result, errors.New("invalid settled inference")
			}
		default:
			return result, errors.New("invalid inference state")
		}
		if invocation.FinishedAt != nil && invocation.FinishedAt.Before(invocation.StartedAt) {
			return result, errors.New("invalid inference timestamps")
		}
		result.SettledUnits, err = inferenceSum(result.SettledUnits, invocation.SettledUnits)
		if err != nil {
			return result, err
		}
		result.HeldUnits, err = inferenceSum(result.HeldUnits, held)
		if err != nil {
			return result, err
		}
	}
	used, err := inferenceSum(result.SettledUnits, result.HeldUnits)
	if err != nil || r.BudgetUnits != nil && used > *r.BudgetUnits {
		return result, errors.New("inference budget record overflow")
	}
	return result, nil
}

// InferenceLedger holds a single writer lock on a private persistent directory.
// Only currently operated task records are loaded; history is bounded on disk.
// The caller must join outbound operations before closing the ledger.
type InferenceLedger struct {
	mu                  sync.Mutex
	directory, lock     *os.File
	epoch               string
	tasks, maximumTasks int
	closed              bool
	failed              error
	fault               func(string) error // deterministic durability fault boundary for tests
}

func OpenInferenceLedger(path string, maximumTasks int) (*InferenceLedger, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximumTasks < 1 || maximumTasks > 65536 {
		return nil, errors.New("invalid inference ledger configuration")
	}
	status, err := os.Lstat(path)
	if err != nil || !status.IsDir() || status.Mode().Perm()&0o077 != 0 || !inferenceOwned(status) {
		return nil, errors.New("inference ledger requires a private service-owned directory")
	}
	directory, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("cannot open inference ledger directory")
	}
	l := &InferenceLedger{directory: directory, maximumTasks: maximumTasks}
	ok := false
	defer func() {
		if !ok {
			_ = l.Close()
		}
	}()
	l.lock, err = os.OpenFile(l.path(".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("cannot open inference ledger lock")
	}
	lockInfo, err := l.lock.Stat()
	if err != nil || !inferencePrivateFile(lockInfo) || syscall.Flock(int(l.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, errors.New("inference ledger lock is unavailable")
	}
	l.epoch, err = randomID()
	if err != nil {
		return nil, errors.New("inference ledger epoch unavailable")
	}
	pending := 0
	for {
		entries, readErr := directory.ReadDir(128)
		if readErr != nil && readErr != io.EOF {
			return nil, errors.New("cannot enumerate inference ledger")
		}
		for _, entry := range entries {
			if entry.Name() == ".lock" {
				continue
			}
			if strings.HasPrefix(entry.Name(), ".pending-") && canonicalJobID(strings.TrimPrefix(entry.Name(), ".pending-")) {
				info, err := os.Lstat(l.path(entry.Name()))
				pending++
				if err != nil || !inferencePrivateFile(info) || pending > 16 || os.Remove(l.path(entry.Name())) != nil {
					return nil, errors.New("invalid orphan inference write")
				}
				continue // A pending rename never authorizes an outbound request.
			}
			if !strings.HasSuffix(entry.Name(), ".json") || !canonicalJobID(strings.TrimSuffix(entry.Name(), ".json")) || !entry.Type().IsRegular() {
				return nil, errors.New("unexpected inference ledger entry")
			}
			l.tasks++
			if l.tasks > maximumTasks {
				return nil, errors.New("inference ledger task limit exceeded")
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	if err := directory.Sync(); err != nil {
		return nil, errors.New("cannot sync inference ledger recovery")
	}
	ok = true
	return l, nil
}

func inferenceOwned(info os.FileInfo) bool {
	value, ok := info.Sys().(*syscall.Stat_t)
	return ok && value.Uid == uint32(os.Geteuid())
}
func inferencePrivateFile(info os.FileInfo) bool {
	value, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 && value.Nlink == 1 && inferenceOwned(info)
}
func (l *InferenceLedger) path(name string) string {
	return fmt.Sprintf("/proc/self/fd/%d/%s", l.directory.Fd(), name)
}
func (l *InferenceLedger) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.check()
}
func (l *InferenceLedger) check() error {
	if l.closed {
		return errors.New("inference ledger closed")
	}
	return l.failed
}
func (l *InferenceLedger) latch() error {
	l.failed = errors.New("inference ledger unavailable; recovery required")
	return l.failed
}
func (l *InferenceLedger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var a, b error
	if l.lock != nil {
		a = l.lock.Close()
	}
	if l.directory != nil {
		b = l.directory.Close()
	}
	return errors.Join(a, b)
}

func (l *InferenceLedger) save(record *inferenceTaskRecord) error {
	if _, err := record.bill(); err != nil {
		return l.latch()
	}
	data, err := json.Marshal(record)
	if err != nil || len(data) > inferenceLedgerFileLimit {
		return l.latch()
	}
	id, err := randomID()
	if err != nil {
		return l.latch()
	}
	temporary := l.path(".pending-" + id)
	f, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return l.latch()
	}
	defer func() { _ = f.Close(); _ = os.Remove(temporary) }()
	step := func(name string) error {
		if l.fault != nil {
			return l.fault(name)
		}
		return nil
	}
	if step("before_write") != nil {
		return l.latch()
	}
	if n, err := f.Write(data); err != nil || n != len(data) || f.Sync() != nil || step("before_rename") != nil {
		return l.latch()
	}
	if err := os.Rename(temporary, l.path(record.Binding.TaskID+".json")); err != nil || step("after_rename") != nil || l.directory.Sync() != nil {
		return l.latch()
	}
	return nil
}

func (l *InferenceLedger) load(taskID string) (*inferenceTaskRecord, error) {
	if !canonicalJobID(taskID) {
		return nil, errors.New("invalid inference task ID")
	}
	f, err := os.OpenFile(l.path(taskID+".json"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, l.latch()
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !inferencePrivateFile(info) || info.Size() > inferenceLedgerFileLimit {
		return nil, l.latch()
	}
	data, err := io.ReadAll(io.LimitReader(f, inferenceLedgerFileLimit+1))
	var record inferenceTaskRecord
	if err != nil || decodeInferenceJSON(data, &record) != nil || record.Binding.TaskID != taskID {
		return nil, l.latch()
	}
	if _, err := record.bill(); err != nil {
		return nil, l.latch()
	}
	return &record, nil
}

func (l *InferenceLedger) recover(record *inferenceTaskRecord) error {
	changed := false
	for index := range record.Invocations {
		entry := &record.Invocations[index]
		if entry.State == "reserved" && entry.Epoch != l.epoch {
			now := time.Now().UTC()
			if now.Before(entry.StartedAt) {
				now = entry.StartedAt
			}
			entry.State, entry.Code, entry.FinishedAt = "uncertain", "inference_restarted", &now
			changed = true
		}
	}
	if changed {
		if err := l.save(record); err != nil {
			return err
		}
	}
	return nil
}

func (l *InferenceLedger) reserve(binding inferenceBinding, id string, permit inferencePermit, inputBytes uint64) (InferenceInvocationReceipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var empty InferenceInvocationReceipt
	if err := l.check(); err != nil {
		return empty, err
	}
	if !binding.valid() || !canonicalJobID(id) || !inferenceEndpointName.MatchString(permit.endpoint) ||
		permit.maxInvocations < 1 || permit.maxInvocations > 256 || permit.maxRequest < 1 || permit.maxRequest > egressRequestLimit ||
		inputBytes > permit.maxRequest || permit.maxResponse < 1 || permit.maxResponse > egressResponseLimit {
		return empty, inferenceError(400, "inference_request")
	}
	record, err := l.load(binding.TaskID)
	newTask := errors.Is(err, os.ErrNotExist)
	if newTask {
		if l.tasks >= l.maximumTasks {
			return empty, inferenceError(507, "inference_store_capacity")
		}
		record = &inferenceTaskRecord{Version: 1, Binding: binding, MaxInvocations: permit.maxInvocations,
			BudgetUnits: inferenceBudget(permit.budget, nil), Invocations: []InferenceInvocationReceipt{}}
	} else if err != nil {
		return empty, err
	}
	if record.Binding != binding {
		return empty, inferenceError(409, "inference_binding")
	}
	if record.Closed {
		return empty, inferenceError(409, "inference_task_closed")
	}
	if err := l.recover(record); err != nil {
		return empty, err
	}
	for _, entry := range record.Invocations {
		if entry.ID == id {
			return empty, inferenceError(409, "inference_replay")
		}
	}
	maximum := min(record.MaxInvocations, permit.maxInvocations)
	if len(record.Invocations) >= maximum {
		return empty, inferenceError(429, "inference_quota")
	}
	bill, err := record.bill()
	if err != nil {
		return empty, l.latch()
	}
	reservation, err := permit.price.cost(inputBytes, permit.maxResponse)
	if err != nil {
		return empty, err
	}
	used, err := inferenceSum(bill.SettledUnits, bill.HeldUnits)
	if err != nil {
		return empty, err
	}
	used, err = inferenceSum(used, reservation)
	budget := inferenceBudget(record.BudgetUnits, permit.budget)
	if err != nil || budget != nil && used > *budget {
		return empty, inferenceError(429, "inference_budget")
	}
	entry := InferenceInvocationReceipt{ID: id, Endpoint: permit.endpoint, State: "reserved", Epoch: l.epoch,
		Price: permit.price, InputBytes: inputBytes, MaxOutputBytes: permit.maxResponse, ReservedUnits: reservation, StartedAt: time.Now().UTC()}
	// Tightened limits must not make previous durable history malformed. Enforce
	// them for this admission; keep the task's original caps for historical bills.
	record.Invocations = append(record.Invocations, entry)
	if err := l.save(record); err != nil {
		return empty, err
	}
	if newTask {
		l.tasks++
	}
	return entry, nil
}

type inferenceOutcome struct {
	state       string
	code        string
	status      int
	dispatched  bool
	outputBytes uint64
	durationMS  uint64
}

func (l *InferenceLedger) finish(binding inferenceBinding, id string, result inferenceOutcome) (InferenceBill, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var empty InferenceBill
	if err := l.check(); err != nil {
		return empty, err
	}
	record, err := l.load(binding.TaskID)
	if err != nil {
		return empty, err
	}
	if record.Binding != binding {
		return empty, errors.New("inference task owner mismatch")
	}
	if err := l.recover(record); err != nil {
		return empty, err
	}
	for index := range record.Invocations {
		entry := &record.Invocations[index]
		if entry.ID != id {
			continue
		}
		if entry.State != "reserved" || entry.Epoch != l.epoch {
			return empty, errors.New("inference invocation already final or belongs to an older process")
		}
		if result.state != "succeeded" && result.state != "failed" && result.state != "uncertain" || result.outputBytes > entry.MaxOutputBytes+1 || result.durationMS > 300000 {
			return empty, errors.New("invalid inference result")
		}
		now := time.Now().UTC()
		if now.Before(entry.StartedAt) {
			now = entry.StartedAt
		}
		entry.State, entry.Code, entry.HTTPStatus, entry.Dispatched = result.state, result.code, result.status, result.dispatched
		entry.OutputBytes, entry.DurationMS, entry.FinishedAt = result.outputBytes, result.durationMS, &now
		if result.state != "uncertain" && result.dispatched {
			entry.SettledUnits, err = entry.Price.cost(entry.InputBytes, min(entry.OutputBytes, entry.MaxOutputBytes))
			if err != nil {
				return empty, err
			}
		}
		if _, err := record.bill(); err != nil {
			return empty, errors.New("invalid inference result state or billing proof")
		}
		if err := l.save(record); err != nil {
			return empty, err
		}
		return record.bill()
	}
	return empty, errors.New("inference invocation not found")
}

func (l *InferenceLedger) bill(tenant, taskID string) (InferenceBill, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.check(); err != nil {
		return InferenceBill{}, err
	}
	record, err := l.load(taskID)
	if err != nil {
		return InferenceBill{}, err
	}
	if record.Binding.Tenant != tenant {
		return InferenceBill{}, os.ErrNotExist
	}
	if err := l.recover(record); err != nil {
		return InferenceBill{}, err
	}
	return record.bill()
}

func (l *InferenceLedger) closeTask(binding inferenceBinding) (InferenceBill, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.check(); err != nil {
		return InferenceBill{}, err
	}
	record, err := l.load(binding.TaskID)
	if err != nil {
		return InferenceBill{}, err
	}
	if record.Binding != binding {
		return InferenceBill{}, errors.New("inference task owner mismatch")
	}
	if err := l.recover(record); err != nil {
		return InferenceBill{}, err
	}
	for _, entry := range record.Invocations {
		if entry.State == "reserved" {
			return InferenceBill{}, errors.New("inference task still has active invocations")
		}
	}
	if !record.Closed {
		record.Closed = true
		if err := l.save(record); err != nil {
			return InferenceBill{}, err
		}
	}
	return record.bill()
}

func (l *InferenceLedger) exportTask(binding inferenceBinding) ([]byte, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.check(); err != nil {
		return nil, "", err
	}
	record, err := l.load(binding.TaskID)
	if err != nil {
		return nil, "", err
	}
	if record.Binding != binding || !record.Closed {
		return nil, "", errors.New("only a closed owned inference bill can be exported")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, "", err
	}
	return data, inferenceDigest(data), nil
}

func (l *InferenceLedger) retireTask(binding inferenceBinding, exportedDigest string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.check(); err != nil {
		return err
	}
	record, err := l.load(binding.TaskID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil || record.Binding != binding || !record.Closed || inferenceDigest(data) != exportedDigest {
		return errors.New("inference retirement requires an exact exported closed bill")
	}
	if os.Remove(l.path(binding.TaskID+".json")) != nil || l.directory.Sync() != nil {
		return l.latch()
	}
	l.tasks--
	return nil
}

func inferenceDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
