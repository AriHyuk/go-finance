package port

import (
	"context"
	"go-finance/internal/core/domain"

	"github.com/google/uuid"
)

// ========================================
// REPOSITORY PORT (Interface)
// ========================================

// UserRepository defines the contract for user data persistence
// This is a PORT in Clean Architecture - the implementation is in the adapter layer
type UserRepository interface {
	// Create inserts a new user into the database
	// Returns domain error ErrDuplicateEmail if email already exists
	Create(ctx context.Context, user *domain.User) error

	// FindByEmail retrieves a user by their email address
	// Returns domain error ErrUserNotFound if user doesn't exist
	FindByEmail(ctx context.Context, email string) (*domain.User, error)

	// FindByID retrieves a user by their UUID
	// Returns domain error ErrUserNotFound if user doesn't exist
	FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// ========================================
// SERVICE PORT (Interface)
// ========================================

// AuthService defines the contract for authentication business logic
// This is a PORT in Clean Architecture - the implementation is in the service layer
type AuthService interface {
	// Register creates a new user account with hashed password
	// Returns domain error ErrDuplicateEmail if email exists
	// Returns domain error ErrValidationFailed if input is invalid
	Register(ctx context.Context, req domain.RegisterRequest) (*domain.UserResponse, error)

	// Login authenticates a user and returns a JWT access token
	// Returns domain error ErrInvalidCredentials if credentials are wrong
	// Returns domain error ErrUserNotFound if user doesn't exist
	Login(ctx context.Context, req domain.LoginRequest) (*domain.AuthResponse, error)

	// ValidateToken validates a JWT token and returns the user ID
	// Returns domain error ErrUnauthorized if token is invalid/expired
	ValidateToken(tokenString string) (uuid.UUID, error)
}
