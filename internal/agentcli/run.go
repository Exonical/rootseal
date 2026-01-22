package agentcli

import (
	"fmt"
	"log"
)

// Run is the main entry point for the agent CLI
func Run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: %s <command> [args]\nCommands: postimaging, bind, unlock", args[0])
	}

	switch args[1] {
	case "postimaging":
		return HandlePostImaging(args[2:])
	case "bind":
		return HandleBind(args[2:])
	case "unlock":
		return HandleUnlock(args[2:])
	default:
		log.Fatalf("Unknown command: %s", args[1])
		return nil
	}
}
