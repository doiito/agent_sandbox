// Package controlgrpc adapts the typed native protobuf control protocol to the
// existing authenticated control service. Conversion never changes REST paths.
package controlgrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"

	controlv1 "github.com/doiito/agent_sandbox/api/control/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const packageName = "sandbox.control.v1."
const maxValueDepth = 4096

var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

type fieldSpec struct {
	Type         string `json:"type"`
	Cardinality  string `json:"cardinality"`
	Oneof        string `json:"oneof"`
	Number       int32  `json:"number"`
	Nullable     bool   `json:"nullable"`
	Required     bool   `json:"required"`
	JSONEncoding string `json:"json_encoding"`
	Location     string `json:"location"`
}

type messageSpec struct {
	Kind      string               `json:"kind"`
	Fields    map[string]fieldSpec `json:"fields"`
	Constants map[string]any       `json:"constants"`
	Variants  map[string]string    `json:"variants"`
}

type operationSpec struct {
	Method          string `json:"method"`
	Path            string `json:"path"`
	Request         string `json:"request"`
	Response        string `json:"response"`
	OpenRequest     string `json:"open_request"`
	ClientStreaming bool   `json:"client_streaming"`
	ServerStreaming bool   `json:"server_streaming"`
	HTTPStatus      int    `json:"http_status"`
}

type wireSpec struct {
	Protocol   string                   `json:"protocol"`
	Package    string                   `json:"package"`
	Messages   map[string]messageSpec   `json:"messages"`
	Operations map[string]operationSpec `json:"operations"`
}

type wireCodec struct {
	spec  wireSpec
	types map[string]protoreflect.MessageType
}

func newWireCodec() (*wireCodec, error) {
	c := &wireCodec{types: make(map[string]protoreflect.MessageType)}
	if err := json.Unmarshal(controlv1.WireMapping(), &c.spec); err != nil {
		return nil, err
	}
	if c.spec.Protocol != "osv-grpc-wire-mapping/v1" || c.spec.Package != "sandbox.control.v1" || len(c.spec.Operations) != 48 {
		return nil, errors.New("invalid native gRPC contract")
	}
	for name, spec := range c.spec.Messages {
		typeOf, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(packageName + name))
		if err != nil {
			return nil, fmt.Errorf("unregistered contract type %s", name)
		}
		c.types[name] = typeOf
		fields := typeOf.Descriptor().Fields()
		if fields.Len() != len(spec.Fields) {
			return nil, fmt.Errorf("descriptor field count differs: %s", name)
		}
		for key, field := range spec.Fields {
			fd := fields.ByNumber(protoreflect.FieldNumber(field.Number))
			if fd == nil || string(fd.Name()) != key || fd.JSONName() != key ||
				fd.IsList() != (field.Cardinality == "repeated") || fd.IsMap() != (field.Cardinality == "map") {
				return nil, fmt.Errorf("descriptor field differs: %s.%s", name, key)
			}
			if field.Oneof != "" && (fd.ContainingOneof() == nil || string(fd.ContainingOneof().Name()) != field.Oneof) {
				return nil, fmt.Errorf("descriptor union differs: %s.%s", name, key)
			}
			if !fd.IsList() && !fd.IsMap() && !fd.HasPresence() {
				return nil, fmt.Errorf("descriptor loses explicit presence: %s.%s", name, key)
			}
		}
	}
	return c, nil
}

func (c *wireCodec) newMessage(name string) proto.Message {
	if typeOf := c.types[name]; typeOf != nil {
		return typeOf.New().Interface()
	}
	return nil
}

func (c *wireCodec) fromJSON(name string, data []byte) (proto.Message, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("invalid JSON value")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("trailing JSON value")
	}
	return c.fromValue(name, value, 0)
}

func (c *wireCodec) fromValue(name string, value any, depth int) (proto.Message, error) {
	if depth > maxValueDepth || c.types[name] == nil {
		return nil, errors.New("invalid message depth or type")
	}
	message := c.types[name].New()
	spec := c.spec.Messages[name]
	set := func(key string, value any) error {
		field, ok := spec.Fields[key]
		if !ok {
			return errors.New("unknown message field")
		}
		fd := message.Descriptor().Fields().ByNumber(protoreflect.FieldNumber(field.Number))
		converted, err := c.scalarFromJSON(field, fd, value, depth+1)
		if err == nil {
			message.Set(fd, converted)
		}
		return err
	}
	if spec.Kind == "json" {
		var key string
		switch typed := value.(type) {
		case nil:
			message.Set(message.Descriptor().Fields().ByName("null_value"), protoreflect.ValueOfEnum(0))
			return message.Interface(), nil
		case bool:
			key = "boolean"
		case string:
			key = "text"
		case json.Number:
			if !jsonNumber.MatchString(string(typed)) {
				return nil, errors.New("invalid JSON number")
			}
			key, value = "number", string(typed)
		case []any:
			key = "array"
		case map[string]any:
			key = "object"
		default:
			return nil, errors.New("unsupported JSON value")
		}
		if err := set(key, value); err != nil {
			return nil, err
		}
		return message.Interface(), nil
	}
	if spec.Kind == "nullable" {
		if value == nil {
			message.Set(message.Descriptor().Fields().ByName("null_value"), protoreflect.ValueOfEnum(0))
			return message.Interface(), nil
		}
		return message.Interface(), set("value", value)
	}
	if spec.Kind == "list" || spec.Kind == "json_array" {
		values, ok := value.([]any)
		if !ok {
			return nil, errors.New("expected array")
		}
		fd := message.Descriptor().Fields().ByName("values")
		list := message.Mutable(fd).List()
		for _, item := range values {
			converted, err := c.scalarFromJSON(spec.Fields["values"], fd, item, depth+1)
			if err != nil {
				return nil, err
			}
			list.Append(converted)
		}
		return message.Interface(), nil
	}
	if spec.Kind == "map" || spec.Kind == "json_object" {
		values, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("expected dictionary")
		}
		fd := message.Descriptor().Fields().ByName("values")
		dictionary := message.Mutable(fd).Map()
		for key, item := range values {
			converted, err := c.scalarFromJSON(spec.Fields["values"], fd.MapValue(), item, depth+1)
			if err != nil {
				return nil, err
			}
			dictionary.Set(protoreflect.ValueOfString(key).MapKey(), converted)
		}
		return message.Interface(), nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("expected object")
	}
	if spec.Kind == "union" {
		kind, ok := object["type"].(string)
		if !ok || spec.Variants[kind] == "" {
			return nil, errors.New("unknown code event variant")
		}
		return message.Interface(), set(kind, object)
	}
	for key, expected := range spec.Constants {
		if object[key] != expected {
			return nil, errors.New("invalid constant discriminator")
		}
	}
	groups := make(map[string]bool)
	for key, field := range spec.Fields {
		if _, present := object[key]; field.Required && !present {
			return nil, errors.New("missing required message field")
		}
	}
	for key, item := range object {
		if _, constant := spec.Constants[key]; constant {
			continue
		}
		field, exists := spec.Fields[key]
		if !exists {
			return nil, errors.New("unknown fixed object field")
		}
		if item == nil && field.Nullable {
			continue
		}
		if field.Oneof != "" {
			if groups[field.Oneof] {
				return nil, errors.New("multiple union variants")
			}
			groups[field.Oneof] = true
		}
		if err := set(key, item); err != nil {
			return nil, err
		}
	}
	return message.Interface(), nil
}

func (c *wireCodec) scalarFromJSON(field fieldSpec, fd protoreflect.FieldDescriptor, value any, depth int) (protoreflect.Value, error) {
	bad := errors.New("invalid typed field")
	switch field.Type {
	case "string":
		if text, ok := value.(string); ok {
			return protoreflect.ValueOfString(text), nil
		}
	case "bytes":
		if text, ok := value.(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(text)
			if err == nil && base64.StdEncoding.EncodeToString(decoded) == text {
				return protoreflect.ValueOfBytes(decoded), nil
			}
		}
	case "bool":
		if boolean, ok := value.(bool); ok {
			return protoreflect.ValueOfBool(boolean), nil
		}
	case "int64", "uint64", "double":
		var text string
		if field.JSONEncoding == "decimal_string" {
			text, _ = value.(string)
		} else if number, ok := value.(json.Number); ok {
			text = string(number)
		}
		if field.Type == "int64" {
			if number, err := strconv.ParseInt(text, 10, 64); err == nil {
				return protoreflect.ValueOfInt64(number), nil
			}
		} else if field.Type == "uint64" {
			if number, err := strconv.ParseUint(text, 10, 64); err == nil && (field.JSONEncoding != "decimal_string" || strconv.FormatUint(number, 10) == text) {
				return protoreflect.ValueOfUint64(number), nil
			}
		} else if number, err := strconv.ParseFloat(text, 64); err == nil && !math.IsNaN(number) && !math.IsInf(number, 0) {
			return protoreflect.ValueOfFloat64(number), nil
		}
	default:
		if field.Type == "JsonNull" {
			if value == nil {
				return protoreflect.ValueOfEnum(0), nil
			}
		} else if c.types[field.Type] != nil {
			message, err := c.fromValue(field.Type, value, depth)
			if err != nil {
				return protoreflect.Value{}, err
			}
			return protoreflect.ValueOfMessage(message.ProtoReflect()), nil
		}
	}
	return protoreflect.Value{}, bad
}

func (c *wireCodec) toJSON(message proto.Message) ([]byte, error) {
	value, err := c.toValue(message.ProtoReflect(), 0)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func (c *wireCodec) toValue(message protoreflect.Message, depth int) (any, error) {
	if !message.IsValid() || depth > maxValueDepth {
		return nil, errors.New("invalid message depth")
	}
	spec, ok := c.spec.Messages[string(message.Descriptor().Name())]
	if !ok {
		return nil, errors.New("unknown message type")
	}
	if spec.Kind == "json" || spec.Kind == "nullable" || spec.Kind == "union" {
		group := "kind"
		if spec.Kind == "nullable" {
			group = "nullable"
		} else if spec.Kind == "union" {
			group = "event"
		}
		fd := message.WhichOneof(message.Descriptor().Oneofs().ByName(protoreflect.Name(group)))
		if fd == nil {
			return nil, errors.New("missing JSON or event variant")
		}
		key := string(fd.Name())
		if key == "null_value" {
			if message.Get(fd).Enum() != 0 {
				return nil, errors.New("invalid null enum")
			}
			return nil, nil
		}
		value, err := c.scalarToJSON(spec.Fields[key], message.Get(fd), depth+1)
		if spec.Kind == "json" && key == "number" && err == nil {
			if !jsonNumber.MatchString(value.(string)) {
				return nil, errors.New("invalid JSON number")
			}
			value = json.Number(value.(string))
		}
		return value, err
	}
	if spec.Kind == "list" || spec.Kind == "json_array" {
		list := message.Get(message.Descriptor().Fields().ByName("values")).List()
		values := make([]any, 0, list.Len())
		for i := 0; i < list.Len(); i++ {
			value, err := c.scalarToJSON(spec.Fields["values"], list.Get(i), depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return values, nil
	}
	if spec.Kind == "map" || spec.Kind == "json_object" {
		dictionary := message.Get(message.Descriptor().Fields().ByName("values")).Map()
		values := make(map[string]any, dictionary.Len())
		var err error
		dictionary.Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
			values[key.String()], err = c.scalarToJSON(spec.Fields["values"], value, depth+1)
			return err == nil
		})
		return values, err
	}
	object := make(map[string]any)
	for key, value := range spec.Constants {
		object[key] = value
	}
	for key, field := range spec.Fields {
		fd := message.Descriptor().Fields().ByNumber(protoreflect.FieldNumber(field.Number))
		if !message.Has(fd) {
			if field.Required && field.Nullable {
				object[key] = nil
			} else if field.Required {
				return nil, errors.New("missing required message field")
			}
			continue
		}
		value, err := c.scalarToJSON(field, message.Get(fd), depth+1)
		if err != nil {
			return nil, err
		}
		object[key] = value
	}
	return object, nil
}

func (c *wireCodec) scalarToJSON(field fieldSpec, value protoreflect.Value, depth int) (any, error) {
	switch field.Type {
	case "string":
		return value.String(), nil
	case "bytes":
		return base64.StdEncoding.EncodeToString(value.Bytes()), nil
	case "bool":
		return value.Bool(), nil
	case "int64":
		return json.Number(strconv.FormatInt(value.Int(), 10)), nil
	case "uint64":
		text := strconv.FormatUint(value.Uint(), 10)
		if field.JSONEncoding == "decimal_string" {
			return text, nil
		}
		return json.Number(text), nil
	case "double":
		if number := value.Float(); !math.IsNaN(number) && !math.IsInf(number, 0) {
			return number, nil
		}
		return nil, errors.New("non-finite JSON number")
	default:
		return c.toValue(value.Message(), depth)
	}
}
