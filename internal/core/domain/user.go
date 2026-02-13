package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ========================================
// DOMAIN ENTITIES
// ========================================

// User represents the core user entity in the domain
type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Email        string    `json:"email" db:"email" validate:"required,email"`
	PasswordHash string    `json:"-" db:"password_hash"` // NEVER expose in JSON
	FullName     string    `json:"full_name" db:"full_name" validate:"required,min=2,max=100"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// ========================================
// DATA TRANSFER OBJECTS (DTOs)
// ========================================

// RegisterRequest represents the payload for user registration
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=72"` // bcrypt max is 72 bytes
	FullName string `json:"full_name" validate:"required,min=2,max=100"`
}

// LoginRequest represents the payload for user login
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// UserResponse represents sanitized user data for API responses (no password)
type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	FullName  string    `json:"full_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuthResponse represents the response after successful authentication
type AuthResponse struct {
	AccessToken string       `json:"access_token"`
	User        UserResponse `json:"user"`
}

// ToUserResponse converts User domain entity to UserResponse DTO
// This ensures password hash is never exposed in API responses
func (u *User) ToUserResponse() UserResponse {
	return UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		FullName:  u.FullName,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

// ========================================
// DOMAIN ERRORS
// ========================================

var (
	// ErrUserNotFound is returned when a user cannot be found by email or ID
	ErrUserNotFound = errors.New("user not found")

	// ErrDuplicateEmail is returned when attempting to register with an existing email
	ErrDuplicateEmail = errors.New("email already registered")

	// ErrInvalidCredentials is returned when login credentials are invalid
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrValidationFailed is returned when input validation fails
	ErrValidationFailed = errors.New("validation failed")

	// ErrUnauthorized is returned when authentication token is invalid or missing
	ErrUnauthorized = errors.New("unauthorized")
)
