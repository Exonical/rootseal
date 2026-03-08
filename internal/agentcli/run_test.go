package agentcli

import (
	"testing"
)

func TestRun_TooFewArgs(t *testing.T) {
	err := Run([]string{"rootseal"})
	if err == nil {
		t.Fatal("expected error for too few args")
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	err := Run([]string{"rootseal", "notacommand"})
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestRun_KnownCommands_FlagParseError(t *testing.T) {
	// Each handler will return an error because required flags are missing,
	// but they should not panic — the command dispatch itself should reach them.
	commands := []string{"postimaging", "bind", "unlock", "unseal"}
	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			// Pass no flags; handler returns an error (missing required flags)
			err := Run([]string{"rootseal", cmd})
			// We expect an error (missing flags), NOT a panic
			if err == nil {
				t.Errorf("%s: expected error for missing flags, got nil", cmd)
			}
		})
	}
}
