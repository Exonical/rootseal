// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package cmd same as exec module but with reaper.
package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/armon/circbuf"

	"github.com/siderolabs/go-cmd/pkg/cmd/proc/reaper"
)

type stdinCtxKey string

// ExitError wraps any exit error (reaper or exec).
type ExitError struct {
	Output   []byte
	ExitCode int
}

// Error implements error interface.
func (exitError *ExitError) Error() string {
	return fmt.Sprintf("exit status %d: %s", exitError.ExitCode, exitError.Output)
}

// MaxStderrLen is maximum length of stderr output captured for error message.
const (
	MaxStderrLen = 4096

	stdin stdinCtxKey = "stdin"
)

// WithStdin creates a new context from the existing context
// and sets stdin value.
func WithStdin(ctx context.Context, stdinData io.Reader) context.Context {
	return context.WithValue(ctx, stdin, stdinData)
}

// Run executes a command.
//
// Deprecated: Use RunContext instead, which allows passing a context.
func Run(name string, args ...string) (string, error) {
	return RunContext(context.Background(), name, args...)
}

// RunContext executes a command with context.
//
// Deprecated: use RunWithOptions instead, which allows passing options properly.
func RunContext(ctx context.Context, name string, args ...string) (string, error) {
	var opts []Option

	if stdin := ctx.Value(stdin); stdin != nil {
		stdinReader, ok := stdin.(io.Reader)
		if !ok {
			return "", fmt.Errorf("failed to read stdin object from the context")
		}

		opts = append(opts, WithStandardInput(stdinReader))
	}

	return RunWithOptions(ctx, name, args, opts...)
}

// Options are used to configure the command execution.
type Options struct {
	Stdin             io.Reader
	CaptureFullStdout bool
}

// Option is a function that applies a configuration to the Options struct.
type Option func(*Options)

// WithStandardInput returns an Option that sets the stdin for the command.
func WithStandardInput(stdin io.Reader) Option {
	return func(opts *Options) {
		opts.Stdin = stdin
	}
}

// WithFullStdoutCapture returns an Option that enables capturing the full stdout output.
func WithFullStdoutCapture() Option {
	return func(opts *Options) {
		opts.CaptureFullStdout = true
	}
}

// RunWithOptions executes a command with context and options.
func RunWithOptions(ctx context.Context, name string, args []string, options ...Option) (string, error) {
	var opts Options

	for _, option := range options {
		option(&opts)
	}

	cmd := exec.CommandContext(ctx, name, args...)

	var stdout interface {
		io.Writer
		String() string
	}

	if opts.CaptureFullStdout {
		stdout = new(bytes.Buffer)
	} else {
		var err error

		stdout, err = circbuf.NewBuffer(MaxStderrLen)
		if err != nil {
			return stdout.String(), err
		}
	}

	stderr, err := circbuf.NewBuffer(MaxStderrLen)
	if err != nil {
		return stdout.String(), err
	}

	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = opts.Stdin

	notifyCh := make(chan reaper.ProcessInfo, 8)
	usingReaper := reaper.Notify(notifyCh)

	if usingReaper {
		defer reaper.Stop(notifyCh)
	}

	if err = cmd.Start(); err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}

	if err = reaper.WaitWrapper(usingReaper, notifyCh, cmd); err != nil {
		var (
			reaperErr *reaper.ExitError
			execErr   *exec.ExitError
		)

		switch {
		case errors.As(err, &reaperErr):
			return stdout.String(), &ExitError{
				ExitCode: reaperErr.ExitCode,
				Output:   stderr.Bytes(),
			}
		case errors.As(err, &execErr) && execErr.ExitCode() != -1:
			return stdout.String(), &ExitError{
				ExitCode: execErr.ExitCode(),
				Output:   stderr.Bytes(),
			}
		}

		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}

	return stdout.String(), nil
}
