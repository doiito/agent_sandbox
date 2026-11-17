package grpcabi

import (
	"os"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestCompiledDescriptorCompatibility(t *testing.T) {
	data, err := os.ReadFile("../../api/control/v1/abi-baseline.pb")
	if err != nil {
		t.Fatal(err)
	}
	before := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(data, before); err != nil {
		t.Fatal(err)
	}
	if err := Check(before, proto.Clone(before).(*descriptorpb.FileDescriptorSet)); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name string
		edit func(*descriptorpb.FileDescriptorSet)
	}{
		{"renumber", func(value *descriptorpb.FileDescriptorSet) {
			value.File[0].MessageType[0].Field[0].Number = proto.Int32(1000)
		}},
		{"rename", func(value *descriptorpb.FileDescriptorSet) {
			value.File[0].MessageType[0].Field[0].Name = proto.String("other")
		}},
		{"wire-type", func(value *descriptorpb.FileDescriptorSet) {
			value.File[0].MessageType[0].Field[0].Type = descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum()
		}},
		{"remove-presence", func(value *descriptorpb.FileDescriptorSet) {
			value.File[0].MessageType[0].Field[0].Proto3Optional = proto.Bool(false)
		}},
		{"delete-unreserved", func(value *descriptorpb.FileDescriptorSet) {
			value.File[0].MessageType[0].Field = value.File[0].MessageType[0].Field[1:]
		}},
		{"method-output", func(value *descriptorpb.FileDescriptorSet) {
			value.File[0].Service[0].Method[0].OutputType = proto.String(".other.Type")
		}},
		{"stream-shape", func(value *descriptorpb.FileDescriptorSet) {
			value.File[0].Service[0].Method[0].ClientStreaming = proto.Bool(true)
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			after := proto.Clone(before).(*descriptorpb.FileDescriptorSet)
			change.edit(after)
			if err := Check(before, after); err == nil {
				t.Fatal("incompatible compiled ABI accepted")
			}
		})
	}
	after := proto.Clone(before).(*descriptorpb.FileDescriptorSet)
	message := after.File[0].MessageType[0]
	deleted := message.Field[0]
	message.Field = message.Field[1:]
	message.ReservedName = append(message.ReservedName, deleted.GetName())
	message.ReservedRange = append(message.ReservedRange, &descriptorpb.DescriptorProto_ReservedRange{
		Start: proto.Int32(deleted.GetNumber()), End: proto.Int32(deleted.GetNumber() + 1)})
	if err := Check(before, after); err != nil {
		t.Fatalf("correctly reserved removal rejected: %v", err)
	}
	message.Field = append(message.Field, &descriptorpb.FieldDescriptorProto{Name: proto.String("addition"), Number: proto.Int32(2000),
		Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()})
	if err := Check(before, after); err != nil {
		t.Fatalf("additive field rejected: %v", err)
	}
}
