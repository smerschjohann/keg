package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	secretPath := os.Getenv("AI_SECRET_KEY")
	if secretPath == "" {
		secretPath = "/run/secrets/ai_secret_key"
	}

	fmt.Printf("[pi-agent] Starting agent...\n")
	fmt.Printf("[pi-agent] Reading secret from: %s\n", secretPath)

	for i := 0; i < 3; i++ {
		data, err := os.ReadFile(secretPath)
		if err != nil {
			log.Printf("[pi-agent] Warning reading secret: %v\n", err)
		} else {
			token := strings.TrimSpace(string(data))
			fmt.Printf("[pi-agent] Current active token (%s): %s\n", time.Now().Format("15:04:05"), token)
		}
		if i < 2 {
			time.Sleep(2 * time.Second)
		}
	}

	fmt.Println("[pi-agent] Completed successfully.")
}
