package sandbox

import (
	"encoding/json"
	"os"
	"testing"
)

func TestInferenceBillRejectsSuccessfulOverLimitBody(t *testing.T) {
	data, err := os.ReadFile("../../tests/fixtures/inference-sdk.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Bill InferenceBill `json:"bill"`
	}
	if json.Unmarshal(data, &fixture) != nil || fixture.Bill.ValidateForTask(fixture.Bill.TaskID) != nil {
		t.Fatal("invalid known-good bill fixture")
	}
	// This matches the arithmetic at the reservation boundary but cannot be a
	// successful bounded model response: one extra byte is a failed response.
	entry := &fixture.Bill.Invocations[0]
	entry.OutputBytes = entry.MaxOutputBytes + 1
	entry.SettledUnits = entry.ReservedUnits
	fixture.Bill.SettledUnits = entry.ReservedUnits
	if fixture.Bill.ValidateForTask(fixture.Bill.TaskID) == nil {
		t.Fatal("over-limit response was accepted as successful metering")
	}
}
