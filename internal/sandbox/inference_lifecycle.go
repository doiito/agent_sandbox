package sandbox

import (
	"context"
	"errors"
	"os"
)

// ensureTask persists the root grant, or a closed tombstone when close wins a
// race with a late bind. No caller can reopen a closed record.
func (l *InferenceLedger) ensureTask(binding inferenceBinding, maximum int, budget *InferenceUnits, closing bool) (InferenceBill, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.check(); err != nil {
		return InferenceBill{}, err
	}
	if !binding.valid() || maximum < 1 || maximum > 256 {
		return InferenceBill{}, inferenceError(400, "inference_binding")
	}
	record, err := l.load(binding.TaskID)
	created := errors.Is(err, os.ErrNotExist)
	if created {
		if l.tasks >= l.maximumTasks {
			return InferenceBill{}, inferenceError(507, "inference_store_capacity")
		}
		record = &inferenceTaskRecord{Version: 1, Binding: binding, MaxInvocations: maximum,
			BudgetUnits: inferenceBudget(budget, nil), Invocations: []InferenceInvocationReceipt{}}
	} else if err != nil {
		return InferenceBill{}, err
	}
	if record.Binding != binding {
		return InferenceBill{}, inferenceError(409, "inference_binding")
	}
	if err := l.recover(record); err != nil {
		return InferenceBill{}, err
	}
	if !closing && record.Closed {
		return InferenceBill{}, inferenceError(409, "inference_task_closed")
	}
	if closing {
		for _, entry := range record.Invocations {
			if entry.State == "reserved" {
				return InferenceBill{}, inferenceError(409, "inference_task_active")
			}
		}
	}
	changed := closing && !record.Closed
	if closing {
		record.Closed = true
	}
	if created || changed {
		if err := l.save(record); err != nil {
			return InferenceBill{}, err
		}
		if created {
			l.tasks++
		}
	}
	return record.bill()
}

func (l *InferenceLedger) boundTask(binding inferenceBinding, open bool) (InferenceBill, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.check(); err != nil {
		return InferenceBill{}, err
	}
	if !binding.valid() {
		return InferenceBill{}, inferenceError(400, "inference_binding")
	}
	record, err := l.load(binding.TaskID)
	if err != nil {
		return InferenceBill{}, err
	}
	if record.Binding != binding {
		return InferenceBill{}, inferenceError(409, "inference_binding")
	}
	if err := l.recover(record); err != nil {
		return InferenceBill{}, err
	}
	if open && record.Closed {
		return InferenceBill{}, inferenceError(409, "inference_task_closed")
	}
	return record.bill()
}

type inferenceDrain struct {
	binding inferenceBinding
	done    chan struct{}
	bill    InferenceBill
	err     error
}

func (e *inferenceEngine) bindTask(ctx context.Context, binding inferenceBinding) (InferenceBill, error) {
	_, complete, err := e.begin(ctx)
	if err != nil {
		return InferenceBill{}, err
	}
	defer complete()
	tenant, err := e.tenant(binding)
	if err != nil {
		return InferenceBill{}, err
	}
	if err := e.health(); err != nil {
		return InferenceBill{}, err
	}
	e.mu.Lock()
	draining := e.draining[binding.TaskID] != nil
	e.mu.Unlock()
	if draining {
		return InferenceBill{}, inferenceError(409, "inference_task_closed")
	}
	bill, err := e.ledger.ensureTask(binding, tenant.inference.policy.MaxInvocations, tenant.inference.policy.BudgetUnits, false)
	if err != nil {
		return InferenceBill{}, e.lifecycleFailure(err)
	}
	if err := e.lifecycleAudit("infer.bind", binding); err != nil {
		return InferenceBill{}, err
	}
	return bill, nil
}

// closeTask is independent of model slots. Once accepted, it finishes sealing
// the grant even if the root caller disconnects and loses its acknowledgement.
func (e *inferenceEngine) closeTask(ctx context.Context, binding inferenceBinding) (InferenceBill, error) {
	_, complete, err := e.begin(ctx)
	if err != nil {
		return InferenceBill{}, err
	}
	defer complete()
	if !binding.valid() {
		return InferenceBill{}, inferenceError(400, "inference_binding")
	}
	if _, err := e.ledger.boundTask(binding, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return InferenceBill{}, e.lifecycleFailure(err)
	}
	e.mu.Lock()
	if existing := e.draining[binding.TaskID]; existing != nil {
		e.mu.Unlock()
		if existing.binding != binding {
			return InferenceBill{}, inferenceError(409, "inference_binding")
		}
		<-existing.done
		return existing.bill, existing.err
	}
	drain := &inferenceDrain{binding: binding, done: make(chan struct{})}
	e.draining[binding.TaskID] = drain
	var pending []<-chan struct{}
	for call := range e.active {
		if call.binding != nil && *call.binding == binding {
			call.cancel()
			pending = append(pending, call.done)
		}
	}
	e.mu.Unlock()
	for _, done := range pending {
		<-done
	}
	maximum := 128
	var budget *InferenceUnits
	// Root must be able to close history after a tenant/policy is revoked.
	if tenant := e.tenants[binding.Tenant]; tenant != nil && tenant.inference != nil {
		maximum, budget = tenant.inference.policy.MaxInvocations, tenant.inference.policy.BudgetUnits
	}
	bill, err := e.ledger.ensureTask(binding, maximum, budget, true)
	if err == nil {
		err = e.lifecycleAudit("infer.close", binding)
	} else {
		err = e.lifecycleFailure(err)
	}
	e.mu.Lock()
	drain.bill, drain.err = bill, err
	delete(e.draining, binding.TaskID)
	close(drain.done)
	e.mu.Unlock()
	return bill, err
}

func (e *inferenceEngine) lifecycleFailure(err error) error {
	if e.ledger.Err() != nil {
		e.fail()
		return inferenceError(503, "inference_store")
	}
	if errors.Is(err, os.ErrNotExist) {
		return inferenceError(404, "inference_not_found")
	}
	var failure *InferenceError
	if errors.As(err, &failure) {
		return failure
	}
	return inferenceError(409, "inference_state")
}

func (e *inferenceEngine) lifecycleAudit(event string, binding inferenceBinding) error {
	id, err := randomID()
	if err != nil {
		return inferenceError(503, "inference_unavailable")
	}
	return e.appendAudit(EgressAuditEvent{Event: event, RequestID: id, Tenant: binding.Tenant,
		TaskID: binding.TaskID, VMID: binding.VMID, LeaseID: binding.LeaseID})
}
