package repository

import (
	"database/sql"
	"errors"
	"go_tutorial/internal/model"
	"strings"
)

// PostgresUserRepository implements the UserRepository interface using PostgreSQL.
type PostgresUserRepository struct {
	db *sql.DB
}

// NewPostgresUserRepository creates a new PostgresUserRepository and ensures the table exists.
func NewPostgresUserRepository(db *sql.DB) (*PostgresUserRepository, error) {
	repo := &PostgresUserRepository{db: db}

	// Auto-create table if it doesn't exist yet in Neon
	if err := repo.createTableIfNotExists(); err != nil {
		return nil, err
	}

	return repo, nil
}

func (r *PostgresUserRepository) createTableIfNotExists() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(64) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);`
	_, err := r.db.Exec(query)
	return err
}

func (r *PostgresUserRepository) Create(user *model.User) error {
	query := `
		INSERT INTO users (id, name, email, password_hash, created_at)
		VALUES ($1, $2, $3, $4, $5);
	`
	_, err := r.db.Exec(query, user.ID, user.Name, strings.ToLower(user.Email), user.PasswordHash, user.CreatedAt)
	if err != nil {
		// Postgres unique_violation error code is 23505
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "23505") {
			return ErrUserAlreadyExists
		}
		return err
	}
	return nil
}

func (r *PostgresUserRepository) FindByEmail(email string) (*model.User, error) {
	query := `
		SELECT id, name, email, password_hash, created_at
		FROM users
		WHERE email = $1;
	`
	var u model.User
	err := r.db.QueryRow(query, strings.ToLower(email)).Scan(
		&u.ID,
		&u.Name,
		&u.Email,
		&u.PasswordHash,
		&u.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (r *PostgresUserRepository) FindAll() ([]*model.User, error) {
	query := `
		SELECT id, name, email, password_hash, created_at
		FROM users
		ORDER BY created_at DESC;
	`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, &u)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}
