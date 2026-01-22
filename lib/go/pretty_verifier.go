/*
Copyright 2024-2025 Politecnico di Torino

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package prettyverifier

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var (
	ErrNotFound = errors.New("pretty-verifier executable not found")
	ErrNoAccess = errors.New("permission denied for pretty-verifier executable")
)

type Options struct {
	SourcePaths  string
	BytecodePath string
	Enumerate    bool
}


func Format(rawLog string, opts *Options) (string, error) {
	var args []string

	if opts != nil {
		if opts.SourcePaths != "" {
			args = append(args, "-c", opts.SourcePaths)
		}
		if opts.BytecodePath != "" {
			args = append(args, "-o", opts.BytecodePath)
		}
		if opts.Enumerate {
			args = append(args, "-n")
		}
	}

	cmd := exec.Command("pretty-verifier", args...)

	cmd.Stdin = strings.NewReader(rawLog)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()

	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode := exitError.ExitCode()
			switch exitCode {
			case 127:
				return "", ErrNotFound
			case 126:
				return "", ErrNoAccess
			default:
				return "", fmt.Errorf("process failed with code %d: %s", exitCode, strings.TrimSpace(errBuf.String()))
			}
		}
		return "", fmt.Errorf("execution error: %w", err)
	}

	return outBuf.String(), nil
}