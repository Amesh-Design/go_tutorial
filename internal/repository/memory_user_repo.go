package repository

import (
	"go_tutorial/internal/model"
	"strings"
	"sync"
)

// MemoryUserRepository is an in-memory, thread-safe implementation of UserRepository.
type MemoryUserRepository struct {
	mu    sync.RWMutex
	users map[string]*model.User // Keyed by email (lowercased)
}

// NewMemoryUserRepository initializes an in-memory user repository.
func NewMemoryUserRepository() *MemoryUserRepository {
	return &MemoryUserRepository{
		users: make(map[string]*model.User),
	}
}

func (r *MemoryUserRepository) Create(user *model.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	emailKey := strings.ToLower(user.Email)
	if _, exists := r.users[emailKey]; exists {
		return ErrUserAlreadyExists
	}

	r.users[emailKey] = user
	return nil
}

func (r *MemoryUserRepository) FindByEmail(email string) (*model.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	emailKey := strings.ToLower(email)
	user, exists := r.users[emailKey]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (r *MemoryUserRepository) FindAll() ([]*model.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]*model.User, 0, len(r.users))
	for _, u := range r.users {
		list = append(list, u)
	}
	return list, nil
}
