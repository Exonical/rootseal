package agentcli

import (
	"fmt"
)

// Run is the main entry point for the agent CLI
func Run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: %s <command> [args]\nCommands: postimaging, bind, unlock, unseal", args[0])
	}

	switch args[1] {
	case "postimaging":
		return HandlePostImaging(args[2:])
	case "bind":
		return HandleBind(args[2:])
	case "unlock":
		return HandleUnlock(args[2:])
	case "unseal":
		return HandleUnseal(args[2:])
	default:
		return fmt.Errorf("unknown command: %s", args[1])
	}
}
