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