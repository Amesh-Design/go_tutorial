package model

import "time"

// User represents the stored user entity.
type User struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // "-" prevents the hash from ever being exposed in JSON responses
	CreatedAt    time.Time `json:"created_at"`
}

// RegisterRequest defines the expected JSON payload for user registration.
type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserResponse is the safe representation returned to clients upon successful registration.
type UserResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// ToResponse converts a User entity into a safe UserResponse DTO.
func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:        u.ID,
		Name:      u.Name,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
	}
}

// LoginRequest defines the payload for authenticating an existing user.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents the response sent after successful login.
type LoginResponse struct {
	Message string       `json:"message"`
	User    UserResponse `json:"user"`
}

