package postgres

import (
	"context"
	"errors"
	"fmt"
	"go-finance/internal/core/domain"
	"go-finance/internal/core/port"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// userRepository is the PostgreSQL implementation of port.UserRepository
// This is an ADAPTER in Clean Architecture
type userRepository struct {
	db *pgxpool.Pool
}

// NewUserRepository creates a new instance of UserRepository
// Constructor uses dependency injection for database connection pool
func NewUserRepository(db *pgxpool.Pool) port.UserRepository {
	return &userRepository{
		db: db,
	}
}

// Create inserts a new user into the database
// Uses parameterized queries ($1, $2, etc.) to prevent SQL injection attacks
func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (email, password_hash, full_name)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at
	`

	// Use QueryRow to execute INSERT and retrieve the generated values
	// CRITICAL: Using $1, $2, $3 placeholders prevents SQL injection
	err := r.db.QueryRow(ctx, query,
		user.Email,
		user.PasswordHash,
		user.FullName,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		// Check if error is a PostgreSQL unique violation (duplicate email)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			// PostgreSQL error code 23505 = unique_violation
			if pgErr.Code == "23505" {
				// Return domain error instead of database-specific error
				return domain.ErrDuplicateEmail
			}
		}

		// Wrap error with context for better debugging
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// FindByEmail retrieves a user by their email address
// Uses parameterized query to prevent SQL injection
func (r *userRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, password_hash, full_name, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	var user domain.User

	// Use QueryRow for single-row result
	// CRITICAL: Using $1 placeholder prevents SQL injection
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Return domain error instead of database-specific error
			return nil, domain.ErrUserNotFound
		}

		// Wrap error with context for better debugging
		return nil, fmt.Errorf("failed to find user by email: %w", err)
	}

	return &user, nil
}

// FindByID retrieves a user by their UUID
// Uses parameterized query to prevent SQL injection
func (r *userRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, email, password_hash, full_name, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	var user domain.User

	// Use QueryRow for single-row result
	// CRITICAL: Using $1 placeholder prevents SQL injection
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Return domain error instead of database-specific error
			return nil, domain.ErrUserNotFound
		}

		// Wrap error with context for better debugging
		return nil, fmt.Errorf("failed to find user by ID: %w", err)
	}

	return &user, nil
}
