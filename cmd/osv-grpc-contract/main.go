// Command osv-grpc-contract checks compiled protobuf ABI compatibility. It is a
// development tool and is not linked into the daemon request path.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/doiito/agent_sandbox/internal/grpcabi"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Initial typed v1 contract. Later release descriptors are checked in addition
// to this anchor; generators never overwrite the initial descriptor.
const initialV1SHA256 = "95feed209b773a110c06a65c3a51f24bd96a4233aea80d4b3e218d483d6f56bf"

func main() {
	baseline := flag.String("baseline", "api/control/v1/abi-baseline.pb", "initial compiled descriptor")
	current := flag.String("current", "api/control/v1/control.descriptor.pb", "current compiled descriptor")
	flag.Parse()
	before, digest, err := read(*baseline)
	if err == nil && digest != initialV1SHA256 {
		err = fmt.Errorf("initial v1 ABI anchor changed")
	}
	if err == nil {
		var after *descriptorpb.FileDescriptorSet
		after, _, err = read(*current)
		if err == nil {
			err = grpcabi.Check(before, after)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Compiled native gRPC v1 ABI remains compatible")
}

func read(path string) (*descriptorpb.FileDescriptorSet, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(data)
	value := &descriptorpb.FileDescriptorSet{}
	err = proto.Unmarshal(data, value)
	return value, hex.EncodeToString(digest[:]), err
}
