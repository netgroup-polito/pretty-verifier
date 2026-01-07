package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/netgroup-polito/pretty-verifier/lib/go"
)

func main() {
	bytecodePath := "test.bpf.o"
	sourcePath := "test.bpf.c"

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	}

	spec, err := ebpf.LoadCollectionSpec(bytecodePath)
	if err != nil {
		log.Fatalf("Failed to read BPF object: %v", err)
	}

	_, err = ebpf.NewCollectionWithOptions(spec, opts)

	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {

			rawLog := fmt.Sprintf("%+v", ve)

			pvOpts := &prettyverifier.Options{
				SourcePaths:  sourcePath,
				BytecodePath: bytecodePath,
				Enumerate:    false,
			}

			formattedOutput, pvErr := prettyverifier.Format(rawLog, pvOpts)

			if pvErr == nil {
				// PV_SUCCESS
				fmt.Println(formattedOutput)
			} else if errors.Is(pvErr, prettyverifier.ErrNotFound) {
				// PV_ERR_NOT_FOUND
				fmt.Fprintf(os.Stderr, "Error: 'pretty-verifier' tool not found in PATH.\n")
			} else {
				// Generic Error
				fmt.Fprintf(os.Stderr, "Error formatting log: %v\n", pvErr)
			}

		} else {
			log.Fatalf("Failed to load resources: %v", err)
		}
	} else {
		fmt.Println("Program loaded successfully.")
	}
}