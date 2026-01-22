package main

import (
"log"
"os"

"rootseal/internal/agentcli"
)

func main() {
if err := agentcli.Run(os.Args); err != nil {
log.Fatalf("Command failed: %v", err)
}
}
