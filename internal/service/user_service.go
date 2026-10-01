package service

import (
	"errors"
	"fmt"
	"go_tutorial/internal/model"
	"go_tutorial/internal/repository"
	"go_tutorial/pkg/validator"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("invalid email or password")

// UserService defines the business logic methods for user operations.
type UserService struct {
	repo repository.UserRepository
}

// NewUserService constructs a new UserService with its repository dependency injected.
func NewUserService(repo repository.UserRepository) *UserService {
	return &UserService{repo: repo}
}

// Login validates user credentials and returns safe user information.
func (s *UserService) Login(req model.LoginRequest) (*model.LoginResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || strings.TrimSpace(req.Password) == "" {
		return nil, errors.New("both email and password are required")
	}

	// 1. Fetch user by email
	user, err := s.repo.FindByEmail(email)
	if err != nil {
		// Security practice: do not reveal whether the email exists
		return nil, ErrInvalidCredentials
	}

	// 2. Verify hashed password against plain-text password using bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// 3. Return success response with user profile
	return &model.LoginResponse{
		Message: "Login successful",
		User:    user.ToResponse(),
	}, nil
}


// Register validates registration input, hashes the password, and creates the user.
func (s *UserService) Register(req model.RegisterRequest) (*model.UserResponse, error) {
	// 1. Validate fields
	if err := validator.ValidateRegisterInput(req.Name, req.Email, req.Password); err != nil {
		return nil, err
	}

	// 2. Hash password with cryptographic salt
	passwordHash, err := hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// 3. Construct user model
	user := &model.User{
		ID:           fmt.Sprintf("usr_%d", time.Now().UnixNano()),
		Name:         strings.TrimSpace(req.Name),
		Email:        strings.ToLower(strings.TrimSpace(req.Email)),
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
	}

	// 4. Persist to repository
	if err := s.repo.Create(user); err != nil {
		return nil, err
	}

	// 5. Return safe response without password hash
	resp := user.ToResponse()
	return &resp, nil
}

// GetAllUsers retrieves all registered users (safe view).
func (s *UserService) GetAllUsers() ([]model.UserResponse, error) {
	users, err := s.repo.FindAll()
	if err != nil {
		return nil, err
	}

	responses := make([]model.UserResponse, 0, len(users))
	for _, u := range users {
		responses = append(responses, u.ToResponse())
	}
	return responses, nil
}

// hashPassword securely hashes a plain-text password using SHA-256 and a random salt.
// (Note: In production with external modules, golang.org/x/crypto/bcrypt is also widely used).

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes), err
}