package executor

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

func Execute(ctx context.Context, workingDir string, command string, args ...string) (stdout []byte, stderr []byte, rc int, err error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = workingDir

	var stdoutBytes, stderrBytes bytes.Buffer
	cmd.Stdout = &stdoutBytes
	cmd.Stderr = &stderrBytes
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdoutBytes.Bytes(), stderrBytes.Bytes(), exitErr.ExitCode(), nil
		}
		return stdoutBytes.Bytes(), stderrBytes.Bytes(), -1, err
	}
	return stdoutBytes.Bytes(), stderrBytes.Bytes(), 0, nil
}
