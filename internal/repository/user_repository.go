package repository

import (
	"errors"
	"go_tutorial/internal/model"
)

var (
	ErrUserAlreadyExists = errors.New("user with this email already exists")
	ErrUserNotFound      = errors.New("user not found")
)

// UserRepository defines the contract for persisting and retrieving users.
type UserRepository interface {
	Create(user *model.User) error
	FindByEmail(email string) (*model.User, error)
	FindAll() ([]*model.User, error)
}
