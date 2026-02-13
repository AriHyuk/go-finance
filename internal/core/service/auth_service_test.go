package service_test

import (
	"context"
	"errors"
	"go-finance/internal/core/domain"
	"go-finance/internal/core/service"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// ========================================
// MOCK REPOSITORY
// ========================================

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	// Simulate database behavior: set ID and timestamps
	if args.Error(0) == nil {
		user.ID = uuid.New()
		user.CreatedAt = time.Now()
		user.UpdatedAt = time.Now()
	}
	return args.Error(0)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// ========================================
// TEST: Register Function
// ========================================

func TestAuthService_Register(t *testing.T) {
	jwtSecret := "test-jwt-secret-key-for-testing"

	t.Run("should register user successfully", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(user *domain.User) bool {
			return user.Email == "test@example.com" && user.FullName == "Test User"
		})).Return(nil)

		req := domain.RegisterRequest{
			Email:    "test@example.com",
			Password: "SecurePass123",
			FullName: "Test User",
		}

		// Act
		result, err := authService.Register(context.Background(), req)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "test@example.com", result.Email)
		assert.Equal(t, "Test User", result.FullName)
		assert.NotEqual(t, uuid.Nil, result.ID)
		mockRepo.AssertExpectations(t)
	})

	t.Run("should fail with duplicate email", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		mockRepo.On("Create", mock.Anything, mock.Anything).Return(domain.ErrDuplicateEmail)

		req := domain.RegisterRequest{
			Email:    "existing@example.com",
			Password: "SecurePass123",
			FullName: "Test User",
		}

		// Act
		result, err := authService.Register(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, domain.ErrDuplicateEmail)
		mockRepo.AssertExpectations(t)
	})

	t.Run("should fail with invalid email", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		req := domain.RegisterRequest{
			Email:    "invalid-email",
			Password: "SecurePass123",
			FullName: "Test User",
		}

		// Act
		result, err := authService.Register(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, domain.ErrValidationFailed)
	})

	t.Run("should fail with short password", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		req := domain.RegisterRequest{
			Email:    "test@example.com",
			Password: "short",
			FullName: "Test User",
		}

		// Act
		result, err := authService.Register(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, domain.ErrValidationFailed)
	})

	t.Run("should fail with empty full name", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		req := domain.RegisterRequest{
			Email:    "test@example.com",
			Password: "SecurePass123",
			FullName: "",
		}

		// Act
		result, err := authService.Register(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, domain.ErrValidationFailed)
	})
}

// ========================================
// TEST: Login Function
// ========================================

func TestAuthService_Login(t *testing.T) {
	jwtSecret := "test-jwt-secret-key-for-testing"

	t.Run("should login successfully with valid credentials", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		// Create a user with hashed password
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("SecurePass123"), 12)
		existingUser := &domain.User{
			ID:           uuid.New(),
			Email:        "test@example.com",
			PasswordHash: string(hashedPassword),
			FullName:     "Test User",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		mockRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(existingUser, nil)

		req := domain.LoginRequest{
			Email:    "test@example.com",
			Password: "SecurePass123",
		}

		// Act
		result, err := authService.Login(context.Background(), req)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.AccessToken)
		assert.Equal(t, "test@example.com", result.User.Email)
		assert.Equal(t, "Test User", result.User.FullName)
		mockRepo.AssertExpectations(t)
	})

	t.Run("should fail with invalid password", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("CorrectPassword"), 12)
		existingUser := &domain.User{
			ID:           uuid.New(),
			Email:        "test@example.com",
			PasswordHash: string(hashedPassword),
			FullName:     "Test User",
		}

		mockRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(existingUser, nil)

		req := domain.LoginRequest{
			Email:    "test@example.com",
			Password: "WrongPassword",
		}

		// Act
		result, err := authService.Login(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
		mockRepo.AssertExpectations(t)
	})

	t.Run("should fail with non-existent user", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		mockRepo.On("FindByEmail", mock.Anything, "nonexistent@example.com").Return(nil, domain.ErrUserNotFound)

		req := domain.LoginRequest{
			Email:    "nonexistent@example.com",
			Password: "SecurePass123",
		}

		// Act
		result, err := authService.Login(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
		mockRepo.AssertExpectations(t)
	})

	t.Run("should fail with invalid email format", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		req := domain.LoginRequest{
			Email:    "invalid-email",
			Password: "SecurePass123",
		}

		// Act
		result, err := authService.Login(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, domain.ErrValidationFailed)
	})
}

// ========================================
// TEST: ValidateToken Function
// ========================================

func TestAuthService_ValidateToken(t *testing.T) {
	jwtSecret := "test-jwt-secret-key-for-testing"

	t.Run("should validate valid token successfully", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		// First, create a valid token by logging in
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("SecurePass123"), 12)
		existingUser := &domain.User{
			ID:           uuid.New(),
			Email:        "test@example.com",
			PasswordHash: string(hashedPassword),
			FullName:     "Test User",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		mockRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(existingUser, nil)

		loginReq := domain.LoginRequest{
			Email:    "test@example.com",
			Password: "SecurePass123",
		}

		loginResult, _ := authService.Login(context.Background(), loginReq)
		token := loginResult.AccessToken

		// Act
		userID, err := authService.ValidateToken(token)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, existingUser.ID, userID)
	})

	t.Run("should fail with invalid token", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		invalidToken := "invalid.token.here"

		// Act
		userID, err := authService.ValidateToken(invalidToken)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, userID)
		assert.ErrorIs(t, err, domain.ErrUnauthorized)
	})

	t.Run("should fail with empty token", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		// Act
		userID, err := authService.ValidateToken("")

		// Assert
		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, userID)
		assert.ErrorIs(t, err, domain.ErrUnauthorized)
	})

	t.Run("should fail with token signed with different secret", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		
		// Create service with different secret
		differentSecretService := service.NewAuthService(mockRepo, "different-secret")
		
		// Create token with original secret
		originalService := service.NewAuthService(mockRepo, jwtSecret)
		
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("SecurePass123"), 12)
		existingUser := &domain.User{
			ID:           uuid.New(),
			Email:        "test@example.com",
			PasswordHash: string(hashedPassword),
			FullName:     "Test User",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		mockRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(existingUser, nil)

		loginReq := domain.LoginRequest{
			Email:    "test@example.com",
			Password: "SecurePass123",
		}

		loginResult, _ := originalService.Login(context.Background(), loginReq)
		token := loginResult.AccessToken

		// Act - validate with different secret
		userID, err := differentSecretService.ValidateToken(token)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, userID)
		assert.ErrorIs(t, err, domain.ErrUnauthorized)
	})
}

// ========================================
// TEST: Repository Error Handling
// ========================================

func TestAuthService_RepositoryErrors(t *testing.T) {
	jwtSecret := "test-jwt-secret-key-for-testing"

	t.Run("should handle repository error during registration", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		mockRepo.On("Create", mock.Anything, mock.Anything).Return(errors.New("database connection error"))

		req := domain.RegisterRequest{
			Email:    "test@example.com",
			Password: "SecurePass123",
			FullName: "Test User",
		}

		// Act
		result, err := authService.Register(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		mockRepo.AssertExpectations(t)
	})

	t.Run("should handle repository error during login", func(t *testing.T) {
		// Arrange
		mockRepo := new(MockUserRepository)
		authService := service.NewAuthService(mockRepo, jwtSecret)

		mockRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(nil, errors.New("database connection error"))

		req := domain.LoginRequest{
			Email:    "test@example.com",
			Password: "SecurePass123",
		}

		// Act
		result, err := authService.Login(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		mockRepo.AssertExpectations(t)
	})
}
