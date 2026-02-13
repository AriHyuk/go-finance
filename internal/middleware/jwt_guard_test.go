package middleware_test

import (
	"context"
	"go-finance/internal/core/domain"
	"go-finance/internal/core/port"
	"go-finance/internal/middleware"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// ========================================
// MOCK AUTH SERVICE
// ========================================

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, req domain.RegisterRequest) (*domain.UserResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.UserResponse), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, req domain.LoginRequest) (*domain.AuthResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuthResponse), args.Error(1)
}

func (m *MockAuthService) ValidateToken(tokenString string) (uuid.UUID, error) {
	args := m.Called(tokenString)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

// ========================================
// TEST SETUP
// ========================================

func setupTestRouter(authService port.AuthService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	
	// Protected route with JWT middleware
	protectedGroup := r.Group("/api")
	protectedGroup.Use(middleware.JWTGuard(authService))
	{
		protectedGroup.GET("/protected", func(c *gin.Context) {
			userID, exists := middleware.GetUserIDFromContext(c)
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id_not_found"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"user_id": userID.String()})
		})
	}
	
	return r
}

// ========================================
// TEST: JWT Guard Middleware
// ========================================

func TestJWTGuard_ValidToken(t *testing.T) {
	t.Run("should allow access with valid token", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		router := setupTestRouter(mockService)

		userID := uuid.New()
		validToken := "valid.jwt.token"

		mockService.On("ValidateToken", validToken).Return(userID, nil)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("should inject user ID into context", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		router := setupTestRouter(mockService)

		userID := uuid.New()
		validToken := "valid.jwt.token"

		mockService.On("ValidateToken", validToken).Return(userID, nil)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), userID.String())
		mockService.AssertExpectations(t)
	})
}

func TestJWTGuard_InvalidToken(t *testing.T) {
	t.Run("should reject invalid token - 401 Unauthorized", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		router := setupTestRouter(mockService)

		invalidToken := "invalid.token"

		mockService.On("ValidateToken", invalidToken).Return(uuid.Nil, domain.ErrUnauthorized)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+invalidToken)
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "unauthorized")
		mockService.AssertExpectations(t)
	})

	t.Run("should reject expired token - 401 Unauthorized", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		router := setupTestRouter(mockService)

		expiredToken := "expired.jwt.token"

		mockService.On("ValidateToken", expiredToken).Return(uuid.Nil, domain.ErrUnauthorized)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestJWTGuard_MissingToken(t *testing.T) {
	t.Run("should reject request without Authorization header - 401", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		router := setupTestRouter(mockService)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/protected", nil)
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "missing_token")
	})

	t.Run("should reject request with empty Authorization header - 401", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		router := setupTestRouter(mockService)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/protected", nil)
		req.Header.Set("Authorization", "")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("should reject request without Bearer prefix - 401", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		router := setupTestRouter(mockService)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/protected", nil)
		req.Header.Set("Authorization", "InvalidFormat token")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_token_format")
	})

	t.Run("should reject request with only 'Bearer' without token - 401", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		router := setupTestRouter(mockService)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer ")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ========================================
// TEST: GetUserIDFromContext Helper
// ========================================

func TestGetUserIDFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("should retrieve user ID from context", func(t *testing.T) {
		// Arrange
		expectedUserID := uuid.New()
		
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("userID", expectedUserID)

		// Act
		userID, exists := middleware.GetUserIDFromContext(c)

		// Assert
		assert.True(t, exists)
		assert.Equal(t, expectedUserID, userID)
	})

	t.Run("should return false when user ID not in context", func(t *testing.T) {
		// Arrange
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// Act
		userID, exists := middleware.GetUserIDFromContext(c)

		// Assert
		assert.False(t, exists)
		assert.Equal(t, uuid.Nil, userID)
	})

	t.Run("should return false when context has wrong type", func(t *testing.T) {
		// Arrange
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("userID", "not-a-uuid")

		// Act
		userID, exists := middleware.GetUserIDFromContext(c)

		// Assert
		assert.False(t, exists)
		assert.Equal(t, uuid.Nil, userID)
	})
}
