// Package grpcabi checks compiled protobuf compatibility against the separately
// retained initial v1 descriptor. Regenerating a mutable tag registry cannot
// silently renumber this baseline.
package grpcabi

import (
	"fmt"

	"google.golang.org/protobuf/types/descriptorpb"
)

type index struct {
	messages map[string]*descriptorpb.DescriptorProto
	enums    map[string]*descriptorpb.EnumDescriptorProto
	services map[string]*descriptorpb.ServiceDescriptorProto
}

func describe(set *descriptorpb.FileDescriptorSet) index {
	i := index{make(map[string]*descriptorpb.DescriptorProto), make(map[string]*descriptorpb.EnumDescriptorProto), make(map[string]*descriptorpb.ServiceDescriptorProto)}
	var message func(string, *descriptorpb.DescriptorProto)
	message = func(prefix string, value *descriptorpb.DescriptorProto) {
		name := prefix + "." + value.GetName()
		i.messages[name] = value
		for _, child := range value.NestedType {
			message(name, child)
		}
		for _, enum := range value.EnumType {
			i.enums[name+"."+enum.GetName()] = enum
		}
	}
	for _, file := range set.File {
		prefix := "." + file.GetPackage()
		for _, value := range file.MessageType {
			message(prefix, value)
		}
		for _, value := range file.EnumType {
			i.enums[prefix+"."+value.GetName()] = value
		}
		for _, value := range file.Service {
			i.services[prefix+"."+value.GetName()] = value
		}
	}
	return i
}

func reserved(message *descriptorpb.DescriptorProto, field *descriptorpb.FieldDescriptorProto) bool {
	name, number := false, false
	for _, text := range message.ReservedName {
		name = name || text == field.GetName()
	}
	for _, interval := range message.ReservedRange {
		number = number || interval.GetStart() <= field.GetNumber() && field.GetNumber() < interval.GetEnd()
	}
	return name && number
}

func oneof(message *descriptorpb.DescriptorProto, field *descriptorpb.FieldDescriptorProto) string {
	if field.OneofIndex == nil {
		return ""
	}
	if field.GetOneofIndex() < 0 || int(field.GetOneofIndex()) >= len(message.OneofDecl) {
		return "<invalid>"
	}
	return message.OneofDecl[field.GetOneofIndex()].GetName()
}

// Check allows additive messages/fields/methods and correctly reserved deleted
// fields. Existing fields, enum values and RPC signatures remain compatible.
func Check(before, after *descriptorpb.FileDescriptorSet) error {
	old, fresh := describe(before), describe(after)
	if len(old.services) == 0 || len(old.messages) == 0 {
		return fmt.Errorf("ABI baseline has no native control service/messages")
	}
	for name, prior := range old.messages {
		current := fresh.messages[name]
		if current == nil || current.GetOptions().GetMapEntry() != prior.GetOptions().GetMapEntry() {
			return fmt.Errorf("removed or reshaped message %s", name)
		}
		byNumber := make(map[int32]*descriptorpb.FieldDescriptorProto)
		for _, field := range current.Field {
			if byNumber[field.GetNumber()] != nil {
				return fmt.Errorf("duplicate tag %s.%d", name, field.GetNumber())
			}
			byNumber[field.GetNumber()] = field
		}
		for _, previous := range prior.Field {
			field := byNumber[previous.GetNumber()]
			if field == nil {
				if !reserved(current, previous) {
					return fmt.Errorf("removed field lacks reserved name/tag: %s.%s", name, previous.GetName())
				}
				continue
			}
			if field.GetName() != previous.GetName() || field.GetJsonName() != previous.GetJsonName() ||
				field.GetType() != previous.GetType() || field.GetTypeName() != previous.GetTypeName() ||
				field.GetLabel() != previous.GetLabel() || field.GetProto3Optional() != previous.GetProto3Optional() ||
				oneof(prior, previous) != oneof(current, field) {
				return fmt.Errorf("incompatible field %s.%s", name, previous.GetName())
			}
		}
		// A retired tag/name remains retired even after multiple generations.
		for _, field := range current.Field {
			for _, text := range prior.ReservedName {
				if field.GetName() == text {
					return fmt.Errorf("reused retired name %s.%s", name, text)
				}
			}
			for _, interval := range prior.ReservedRange {
				if interval.GetStart() <= field.GetNumber() && field.GetNumber() < interval.GetEnd() {
					return fmt.Errorf("reused retired number %s.%d", name, field.GetNumber())
				}
			}
		}
	}
	for name, previous := range old.enums {
		current := fresh.enums[name]
		if current == nil {
			return fmt.Errorf("removed enum %s", name)
		}
		for _, value := range previous.Value {
			found := false
			for _, candidate := range current.Value {
				if candidate.GetName() == value.GetName() && candidate.GetNumber() == value.GetNumber() {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("changed enum %s.%s", name, value.GetName())
			}
		}
	}
	for name, previous := range old.services {
		current := fresh.services[name]
		if current == nil {
			return fmt.Errorf("removed service %s", name)
		}
		for _, method := range previous.Method {
			found := false
			for _, candidate := range current.Method {
				if candidate.GetName() == method.GetName() && candidate.GetInputType() == method.GetInputType() &&
					candidate.GetOutputType() == method.GetOutputType() && candidate.GetClientStreaming() == method.GetClientStreaming() &&
					candidate.GetServerStreaming() == method.GetServerStreaming() {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("changed RPC %s/%s", name, method.GetName())
			}
		}
	}
	return nil
}
