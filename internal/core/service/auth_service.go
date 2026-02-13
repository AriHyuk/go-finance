package service

import (
	"context"
	"fmt"
	"go-finance/internal/core/domain"
	"go-finance/internal/core/port"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// authService is the implementation of port.AuthService
// This is the CORE business logic layer in Clean Architecture
type authService struct {
	userRepo  port.UserRepository
	validator *validator.Validate
	jwtSecret string
}

// JWTClaims represents the custom claims for JWT tokens
// Uses standard JWT claims with additional user information
type JWTClaims struct {
	UserID uuid.UUID `json:"sub"` // Subject: User ID
	jwt.RegisteredClaims
}

// NewAuthService creates a new instance of AuthService
// Uses dependency injection for repository and JWT secret
func NewAuthService(userRepo port.UserRepository, jwtSecret string) port.AuthService {
	// Validate that JWT secret is provided (fail-fast principle)
	if jwtSecret == "" {
		panic("JWT_SECRET must not be empty - this is a critical security requirement")
	}

	return &authService{
		userRepo:  userRepo,
		validator: validator.New(),
		jwtSecret: jwtSecret,
	}
}

// Register implements user registration with password hashing and validation
func (s *authService) Register(ctx context.Context, req domain.RegisterRequest) (*domain.UserResponse, error) {
	// 1. Sanitize input
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.FullName = strings.TrimSpace(req.FullName)

	// 2. Validate input using validator tags
	if err := s.validator.Struct(req); err != nil {
		// Wrap validation errors for better error messages
		return nil, fmt.Errorf("%w: %v", domain.ErrValidationFailed, err)
	}

	// 3. Hash password using bcrypt with cost 12 (per backend.md security rule)
	// CRITICAL: Cost 12 is the minimum recommended for production security
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// 4. Create user domain entity
	user := &domain.User{
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		FullName:     req.FullName,
	}

	// 5. Persist user to database
	if err := s.userRepo.Create(ctx, user); err != nil {
		// Repository will return domain.ErrDuplicateEmail if email exists
		return nil, err
	}

	// 6. Return sanitized user response (NEVER return password hash)
	userResponse := user.ToUserResponse()
	return &userResponse, nil
}

// Login implements user authentication with password verification and JWT generation
func (s *authService) Login(ctx context.Context, req domain.LoginRequest) (*domain.AuthResponse, error) {
	// 1. Sanitize input
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// 2. Validate input
	if err := s.validator.Struct(req); err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrValidationFailed, err)
	}

	// 3. Find user by email
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		// Repository returns domain.ErrUserNotFound if user doesn't exist
		// Map it to invalid credentials (don't reveal whether email exists)
		if err == domain.ErrUserNotFound {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	// 4. Verify password using bcrypt
	// CRITICAL: CompareHashAndPassword is constant-time to prevent timing attacks
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		// Return generic invalid credentials error (don't reveal that password was wrong)
		return nil, domain.ErrInvalidCredentials
	}

	// 5. Generate JWT access token
	token, err := s.generateToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// 6. Return auth response with token and user info (NEVER return password hash)
	return &domain.AuthResponse{
		AccessToken: token,
		User:        user.ToUserResponse(),
	}, nil
}

// ValidateToken validates a JWT token and returns the user ID
func (s *authService) ValidateToken(tokenString string) (uuid.UUID, error) {
	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is HMAC (prevent algorithm confusion attacks)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", domain.ErrUnauthorized, err)
	}

	// Extract claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return uuid.Nil, domain.ErrUnauthorized
	}

	return claims.UserID, nil
}

// generateToken creates a JWT access token with 15-minute expiry
func (s *authService) generateToken(userID uuid.UUID) (string, error) {
	// Create claims with 15-minute expiry (per task-auth.md requirement)
	now := time.Now()
	claims := JWTClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(), // sub: user ID
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)), // exp: 15 minutes
			IssuedAt:  jwt.NewNumericDate(now), // iat: issued at timestamp
		},
	}

	// Create token with HMAC-SHA256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret
	signedToken, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}
