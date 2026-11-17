// Package apicontract builds the offline HTTP contract. It is linked only into
// development tooling, never the API daemon or launcher request path.
package apicontract

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

type object = map[string]any

type schemaBuilder struct {
	components object
}

func newSchemaBuilder() *schemaBuilder { return &schemaBuilder{components: object{}} }

func nullable(schema object) object {
	return object{"anyOf": []any{schema, object{"type": "null"}}}
}

func (b *schemaBuilder) ref(value any, input bool) object {
	return b.schema(reflect.TypeOf(value), input)
}

func (b *schemaBuilder) schema(t reflect.Type, input bool) object {
	if t == nil {
		panic("wire schema has no type")
	}
	if t.Kind() == reflect.Pointer {
		return nullable(b.schema(t.Elem(), input))
	}
	if t == reflect.TypeOf(time.Time{}) {
		return object{"type": "string", "format": "date-time"}
	}
	if t == reflect.TypeOf(json.RawMessage{}) {
		return object{"description": "Arbitrary JSON owned by the workload/provider; size and policy remain bounded by the enclosing protocol."}
	}
	if t == reflect.TypeOf(sandbox.InferenceUnits(0)) {
		return object{"type": "string", "pattern": "^(0|[1-9][0-9]{0,19})$", "maxLength": 20,
			"format": "osv-uint64-decimal", "description": "Canonical uint64 decimal string; never a floating-point JSON number."}
	}
	if t == reflect.TypeOf(sandbox.CodeEvent{}) {
		name := "CodeEventOutput"
		b.components[name] = codeEventSchema()
		return object{"$ref": "#/components/schemas/" + name}
	}
	if t.Implements(reflect.TypeOf((*json.Marshaler)(nil)).Elem()) || reflect.PointerTo(t).Implements(reflect.TypeOf((*json.Marshaler)(nil)).Elem()) {
		panic("explicit wire schema required for JSON marshaler " + t.String())
	}
	switch t.Kind() {
	case reflect.Struct:
		name := t.Name() + "Output"
		if input {
			name = t.Name() + "Input"
		}
		if t.Name() == "" {
			panic("HTTP wire structs must be named")
		}
		if _, found := b.components[name]; !found {
			b.components[name] = object{} // Reserve before descending through references.
			properties, required := b.fields(t, input)
			definition := object{"type": "object", "properties": properties, "additionalProperties": !input}
			if len(required) != 0 {
				sort.Strings(required)
				definition["required"] = required
			}
			b.overlay(t.Name(), definition, input)
			b.components[name] = definition
		}
		return object{"$ref": "#/components/schemas/" + name}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return nullable(object{"type": "string", "format": "byte", "contentEncoding": "base64"})
		}
		value := object{"type": "array", "items": b.schema(t.Elem(), input)}
		if t.Kind() == reflect.Slice {
			return nullable(value)
		}
		value["minItems"], value["maxItems"] = t.Len(), t.Len()
		return value
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			panic("non-string JSON dictionary " + t.String())
		}
		return nullable(object{"type": "object", "additionalProperties": b.schema(t.Elem(), input)})
	case reflect.String:
		return object{"type": "string"}
	case reflect.Bool:
		return object{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bits := t.Bits()
		return object{"type": "integer", "minimum": -(int64(1) << (bits - 1)), "maximum": int64((uint64(1) << (bits - 1)) - 1)}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		maximum := ^uint64(0)
		if t.Bits() != 64 {
			maximum = 1<<t.Bits() - 1
		}
		return object{"type": "integer", "minimum": 0, "maximum": maximum}
	case reflect.Float32, reflect.Float64:
		return object{"type": "number"}
	default:
		panic("unsupported JSON wire type " + t.String())
	}
}

func (b *schemaBuilder) fields(t reflect.Type, input bool) (object, []string) {
	properties := object{}
	var required []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		tag := strings.Split(field.Tag.Get("json"), ",")
		if tag[0] == "-" {
			continue
		}
		if field.Anonymous && tag[0] == "" {
			typeOf := field.Type
			if typeOf.Kind() == reflect.Pointer {
				typeOf = typeOf.Elem()
			}
			if typeOf.Kind() != reflect.Struct {
				panic("non-struct anonymous JSON field")
			}
			embedded, keys := b.fields(typeOf, input)
			for key, value := range embedded {
				if _, found := properties[key]; found {
					panic("ambiguous embedded JSON field " + key)
				}
				properties[key] = value
			}
			required = append(required, keys...)
			continue
		}
		name := tag[0]
		if name == "" {
			name = field.Name
		}
		if _, found := properties[name]; found {
			panic("ambiguous JSON field " + name)
		}
		property := b.schema(field.Type, input)
		if input && field.Type.Kind() != reflect.Pointer && field.Type.Kind() != reflect.Map && field.Type.Kind() != reflect.Slice && field.Type.Kind() != reflect.Struct {
			// encoding/json accepts null for a scalar and leaves its zero value;
			// actual semantic required fields are tightened by overlay below.
			property = nullable(property)
		}
		properties[name] = property
		if !input && !strings.Contains(","+field.Tag.Get("json")+",", ",omitempty,") {
			required = append(required, name)
		}
	}
	return properties, required
}

func require(def object, names ...string) {
	def["required"] = names
}

func stringSchema() object { return object{"type": "string"} }
func identifier() object   { return object{"type": "string", "pattern": "^[a-f0-9]{24}$"} }
func digestSchema() object { return object{"type": "string", "pattern": "^[a-f0-9]{64}$"} }
func integer(minimum, maximum uint64) object {
	return object{"type": "integer", "minimum": minimum, "maximum": maximum}
}
func enumeration(values ...string) object { return object{"type": "string", "enum": values} }
func defaultInteger(maximum uint64, description string) object {
	return nullable(object{"type": "integer", "minimum": 0, "maximum": maximum, "description": description})
}

func (b *schemaBuilder) overlay(name string, def object, input bool) {
	p := def["properties"].(object)
	if !input {
		switch name {
		case "APIErrorResponse", "InferenceAPIErrorResponse", "LegacyAPIErrorResponse":
			def["additionalProperties"] = false
			if name != "LegacyAPIErrorResponse" {
				p["code"] = object{"type": "string", "minLength": 1}
			}
			if name == "InferenceAPIErrorResponse" {
				p["invocation_id"] = identifier()
			}
		case "RunResult", "SessionInfo":
			p["startup_mode"] = enumeration("cold", "warm", "snapshot")
		case "SessionOutputEvent", "SessionOutputFrame":
			p["stream"] = enumeration("stdout", "stderr")
			p["data_base64"] = object{"type": "string", "format": "osv-base64"}
		case "SessionPortInfo":
			p["status"] = enumeration("opening", "open", "cancelling", "completed", "cancelled", "failed")
		case "SessionArtifactInfo":
			p["id"], p["session_id"], p["sha256"] = identifier(), identifier(), digestSchema()
			p["source_kind"], p["format"] = enumeration("file", "directory"), enumeration("tar")
			p["size"], p["payload_bytes"] = integer(2048, 32<<20), integer(0, 32<<20)
			p["entries"], p["files"] = integer(0, 1024), integer(0, 1024)
		case "SessionArtifactChunk":
			p["id"], p["session_id"] = identifier(), identifier()
			p["offset"], p["total_size"] = integer(0, 32<<20), integer(2048, 32<<20)
			p["data_base64"] = object{"type": "string", "format": "osv-base64", "maxLength": 699052, "x-max-decoded-bytes": 524288}
			p["data_sha256"], p["archive_sha256"] = digestSchema(), digestSchema()
		}
		return
	}
	switch name {
	case "RunRequest":
		p["args"] = nullable(object{"type": "array", "maxItems": 64, "items": stringSchema()})
		for _, key := range []string{"memory_mib", "vcpus", "timeout_ms"} {
			p[key] = nullable(object{"type": "integer", "minimum": 0, "description": "Zero/null/omitted selects the configured default; live limits are in capabilities.", "x-capability-limit": key})
		}
		p["network"] = nullable(enumeration("", "none", "proxy"))
		p["input_files"] = nullable(object{"type": "array", "maxItems": 64, "items": b.ref(sandbox.InputFile{}, true)})
		p["stdin"] = nullable(object{"type": "string", "format": "byte", "contentEncoding": "base64", "x-max-decoded-bytes": 16384})
	case "InputFile":
		require(def, "path")
		p["path"] = object{"type": "string", "minLength": 1, "description": "Relative confined input path; traversal, symlinks and special files are rejected."}
	case "SessionCreateRequest":
		require(def, "backend", "artifact_manifest_sha256")
		p["backend"] = object{"type": "string", "minLength": 1}
		p["artifact_manifest_sha256"] = digestSchema()
		p["ttl_ms"] = nullable(object{"type": "integer", "anyOf": []any{object{"const": 0}, integer(1000, 300000)}, "description": "Zero/null/omitted selects the bounded configured default; never extends the guest hard lifetime."})
		p["network"] = nullable(enumeration("", "none", "proxy"))
	case "SessionCommandRequest":
		require(def, "entrypoint")
		p["entrypoint"] = object{"type": "string", "minLength": 1}
		p["args"] = nullable(object{"type": "array", "maxItems": 64, "items": stringSchema()})
	case "SessionTimeoutRequest", "PreviewCreateRequest":
		require(def, "ttl_ms")
		p["ttl_ms"] = integer(1000, 300000)
	case "SessionCommandInputRequest":
		p["data_base64"] = nullable(object{"type": "string", "format": "osv-base64", "maxLength": 21848, "x-max-decoded-bytes": 16384})
		def["allOf"] = []any{object{"if": object{"properties": object{"close": object{"const": true}}, "required": []string{"close"}},
			"then": object{"properties": object{"data_base64": object{"enum": []any{"", nil}}}}}}
	case "SessionWatchRequest":
		require(def, "path")
		p["path"] = object{"type": "string", "minLength": 1}
		p["timeout_ms"] = defaultInteger(600000, "Zero/null/omitted uses the session lifetime.")
	case "SessionArtifactCreateRequest":
		require(def, "path")
		p["path"] = object{"type": "string", "pattern": "^/workspace(?:/|$)", "minLength": 10, "x-max-utf8-bytes": 1035, "description": "Canonical workspace file/directory. Archive names, links, depth, total bytes and reserved manifest collisions are checked by the server."}
	case "SessionArtifactReadRequest":
		require(def, "offset", "length")
		p["offset"], p["length"] = integer(0, 32<<20), integer(1, 512<<10)
	case "SessionFileRequest":
		require(def, "action", "path")
		p["action"] = enumeration("read", "write", "list", "stat", "info", "delete", "mkdir", "rename", "remove")
		p["path"] = object{"type": "string", "pattern": "^/workspace(?:/|$)", "description": "Confined workspace path; /workspace itself is accepted only for list/stat/info. Components, UTF-8 bytes and traversal are checked by the server."}
		p["data_base64"] = nullable(object{"type": "string", "format": "osv-base64", "x-capability-limit": "session_file_max_bytes"})
		def["allOf"] = []any{
			object{"if": object{"properties": object{"action": object{"const": "write"}}}, "then": object{"required": []string{"data_base64"}, "properties": object{"data_base64": object{"type": "string"}}}, "else": object{"properties": object{"data_base64": object{"type": "null"}, "metadata": object{"type": "null"}}}},
			object{"if": object{"properties": object{"action": object{"const": "rename"}}}, "then": object{"required": []string{"destination"}, "properties": object{"destination": object{"type": "string", "pattern": "^/workspace/"}}}, "else": object{"properties": object{"destination": object{"type": "null"}}}},
		}
	case "CodeContextCreateRequest":
		require(def, "context_id", "language")
		p["context_id"], p["language"] = identifier(), enumeration("python", "javascript", "typescript")
		p["cwd"] = nullable(object{"type": "string", "description": "Empty/null/omitted defaults to /workspace; otherwise a canonical absolute path within /workspace.", "x-max-utf8-bytes": 1024})
	case "CodeContextDefaultRequest":
		p["language"] = nullable(enumeration("", "python", "javascript", "typescript"))
	case "CodeContextRestartRequest":
		require(def, "generation")
		p["generation"] = integer(1, 1<<53-1)
	case "CodeExecutionRequest":
		require(def, "context_id", "generation", "execution_id")
		p["context_id"], p["execution_id"], p["generation"] = identifier(), identifier(), integer(1, 1<<53-1)
		p["code"] = nullable(object{"type": "string", "x-max-utf8-bytes": 65536, "description": "UTF-8 source; NUL is rejected; empty source is valid."})
		p["timeout_ms"] = nullable(object{"type": "integer", "minimum": 0, "maximum": 300000, "default": 60000, "description": "Omitted/null defaults to 60000; explicit zero remains zero."})
	case "SessionPortLimits":
		require(def, "max_bytes", "timeout_ms", "idle_timeout_ms")
		p["max_bytes"], p["timeout_ms"], p["idle_timeout_ms"] = integer(1, 64<<20), integer(1, 300000), integer(1, 300000)
	case "NetworkFetchRequest":
		require(def, "url")
		p["url"] = object{"type": "string", "format": "uri", "description": "HTTP(S) origin allowed by current tenant/egress policy; no userinfo, fragment, rebinding or private address bypass."}
		p["body_base64"] = nullable(object{"type": "string", "format": "osv-base64", "x-capability-limit": "network_fetch_policy.max_request_bytes"})
	case "InferenceInvokeRequest":
		require(def, "id", "endpoint", "payload")
		p["id"] = identifier()
		p["endpoint"] = object{"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,31}$", "description": "Configured endpoint name, never a URL or credential."}
		p["timeout_ms"] = defaultInteger(30000, "Zero/null/omitted selects the bounded tenant endpoint timeout.")
	}
}

func codeEventSchema() object {
	var variants []any
	add := func(kind string, properties object, required ...string) {
		properties["type"] = object{"const": kind}
		variants = append(variants, object{"type": "object", "properties": properties, "required": append([]string{"type"}, required...), "additionalProperties": false})
	}
	add("started", object{})
	for _, kind := range []string{"stdout", "stderr"} {
		add(kind, object{"data": object{"type": "string", "format": "osv-base64"}}, "data")
	}
	add("result", object{"data": object{"type": "object", "minProperties": 1, "maxProperties": 16,
		"additionalProperties": object{"description": "MIME result: application/json contains bounded arbitrary JSON; other MIME values are strings."}},
		"is_main_result": object{"type": "boolean"}}, "data", "is_main_result")
	add("error", object{"name": object{"type": "string", "minLength": 1}, "value": stringSchema(), "traceback": stringSchema()}, "name", "value", "traceback")
	add("finished", object{"status": enumeration("completed", "cancelled", "timed_out", "failed"), "context_usable": object{"type": "boolean"}}, "status", "context_usable")
	return object{"oneOf": variants, "description": "Closed code-event union; fields and required false/empty values follow the actual custom JSON encoder."}
}

func generateSafely(root string) (document []byte, err error) {
	defer func() {
		if failure := recover(); failure != nil {
			err = fmt.Errorf("generate HTTP contract: %v", failure)
		}
	}()
	return generate(root)
}
