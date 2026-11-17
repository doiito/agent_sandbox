package controlv1

import _ "embed"

//go:embed wire-mapping.json
var wireMapping []byte

// WireMapping returns the generated field and operation semantics. Callers get
// their own bytes; mutable application state cannot change the shared contract.
func WireMapping() []byte { return append([]byte(nil), wireMapping...) }
