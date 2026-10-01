package validator

import (
	"errors"
	"net/mail"
	"strings"
)

// ValidateRegisterInput validates user registration fields.
func ValidateRegisterInput(name, email, password string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name is required")
	}

	if len(strings.TrimSpace(name)) < 2 {
		return errors.New("name must be at least 2 characters long")
	}

	if strings.TrimSpace(email) == "" {
		return errors.New("email is required")
	}

	// Validate email format using standard library mail.ParseAddress
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("invalid email address format")
	}

	if len(password) < 6 {
		return errors.New("password must be at least 6 characters long")
	}

	return nil
}
