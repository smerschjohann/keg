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

	var lastToken string
	// Observe the secret over 12 seconds (with interval: 5s, we see token refreshes live)
	for i := 0; i < 6; i++ {
		data, err := os.ReadFile(secretPath)
		if err != nil {
			log.Printf("[pi-agent] Warning reading secret: %v\n", err)
		} else {
			token := strings.TrimSpace(string(data))
			if token != lastToken {
				if lastToken == "" {
					fmt.Printf("[pi-agent] [%s] Initial token loaded: %s\n", time.Now().Format("15:04:05"), token)
				} else {
					fmt.Printf("[pi-agent] [%s] 🔄 Token refreshed: %s\n", time.Now().Format("15:04:05"), token)
				}
				lastToken = token
			} else {
				fmt.Printf("[pi-agent] [%s] Token unchanged: %s\n", time.Now().Format("15:04:05"), token)
			}
		}
		if i < 5 {
			time.Sleep(2 * time.Second)
		}
	}

	fmt.Println("[pi-agent] Completed successfully.")
}
