package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFixedBOMIncludesFinalNestedComponents(t *testing.T) {
	document := bom{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1,
		Metadata:   metadata{Timestamp: "2026-11-16T00:00:00Z"},
		Components: []component{{Name: "base"}, {Name: "template", Components: []component{{Name: "last runtime component"}}}}}
	first, err := encodeBOM(document, true)
	second, secondErr := encodeBOM(document, true)
	if err != nil || secondErr != nil || !bytes.Equal(first, second) {
		t.Fatal("fixed BOM is not reproducible", err, secondErr)
	}
	var original bom
	if err := json.Unmarshal(first, &original); err != nil {
		t.Fatal(err)
	}
	document.Components[1].Components[0].Version = "changed"
	changed, err := encodeBOM(document, true)
	var parsed bom
	if err != nil || json.Unmarshal(changed, &parsed) != nil || original.SerialNumber == parsed.SerialNumber {
		t.Fatal("final nested component not bound to serial", err)
	}
	left, _ := encodeBOM(document, false)
	right, _ := encodeBOM(document, false)
	if bytes.Equal(left, right) {
		t.Fatal("legacy random serial behavior lost")
	}
}
