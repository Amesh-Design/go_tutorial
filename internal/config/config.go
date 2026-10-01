package config

import (
	"bufio"
	"os"
	"strings"
)

// Config holds all application configuration settings loaded from environment or .env file.
type Config struct {
	Port        string
	AppEnv      string
	DatabaseURL string
}

// Load reads the .env file (if present) and populates the Config struct from environment variables.
func Load() *Config {
	// Attempt to load .env file if it exists (for local development)
	loadDotEnv(".env")

	return &Config{
		Port:        getEnv("PORT", "8080"),
		AppEnv:      getEnv("APP_ENV", "development"),
		DatabaseURL: getEnv("DB_URL", ""),
	}
}

// getEnv retrieves an environment variable or returns a fallback default value.
func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// loadDotEnv parses a local .env file line by line without requiring third-party libraries.
func loadDotEnv(filepath string) {
	file, err := os.Open(filepath)
	if err != nil {
		// It's completely normal for .env to not exist in production (container/cloud env vars used instead)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip blank lines and comments
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Remove quotes if present
			value = strings.Trim(value, `"'`)

			// Only set if not already set in system environment
			if os.Getenv(key) == "" {
				os.Setenv(key, value)
			}
		}
	}
}
