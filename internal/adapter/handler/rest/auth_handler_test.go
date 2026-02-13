package rest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"go-finance/internal/adapter/handler/rest"
	"go-finance/internal/core/domain"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func setupTestRouter(handler *rest.AuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	
	authGroup := r.Group("/api/auth")
	{
		authGroup.POST("/register", handler.Register)
		authGroup.POST("/login", handler.Login)
	}
	
	return r
}

// ========================================
// TEST: Register Handler
// ========================================

func TestAuthHandler_Register(t *testing.T) {
	t.Run("should register user successfully - 201 Created", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		userResponse := &domain.UserResponse{
			ID:        uuid.New(),
			Email:     "test@example.com",
			FullName:  "Test User",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		mockService.On("Register", mock.Anything, mock.MatchedBy(func(req domain.RegisterRequest) bool {
			return req.Email == "test@example.com"
		})).Return(userResponse, nil)

		reqBody := domain.RegisterRequest{
			Email:    "test@example.com",
			Password: "SecurePass123",
			FullName: "Test User",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var response domain.UserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "test@example.com", response.Email)
		assert.Equal(t, "Test User", response.FullName)
		
		mockService.AssertExpectations(t)
	})

	t.Run("should fail with duplicate email - 409 Conflict", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		mockService.On("Register", mock.Anything, mock.Anything).Return(nil, domain.ErrDuplicateEmail)

		reqBody := domain.RegisterRequest{
			Email:    "existing@example.com",
			Password: "SecurePass123",
			FullName: "Test User",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusConflict, w.Code)
		
		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "duplicate_email", response["error"])
		
		mockService.AssertExpectations(t)
	})

	t.Run("should fail with validation error - 400 Bad Request", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		mockService.On("Register", mock.Anything, mock.Anything).Return(nil, domain.ErrValidationFailed)

		reqBody := domain.RegisterRequest{
			Email:    "invalid-email",
			Password: "short",
			FullName: "",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
		
		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "validation_failed", response["error"])
		
		mockService.AssertExpectations(t)
	})

	t.Run("should fail with invalid JSON - 400 Bad Request", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		invalidJSON := []byte(`{"email": "test@example.com", "password": }`)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(invalidJSON))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ========================================
// TEST: Login Handler
// ========================================

func TestAuthHandler_Login(t *testing.T) {
	t.Run("should login successfully - 200 OK", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		authResponse := &domain.AuthResponse{
			AccessToken: "valid.jwt.token",
			User: domain.UserResponse{
				ID:        uuid.New(),
				Email:     "test@example.com",
				FullName:  "Test User",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}

		mockService.On("Login", mock.Anything, mock.MatchedBy(func(req domain.LoginRequest) bool {
			return req.Email == "test@example.com" && req.Password == "SecurePass123"
		})).Return(authResponse, nil)

		reqBody := domain.LoginRequest{
			Email:    "test@example.com",
			Password: "SecurePass123",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response domain.AuthResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.Equal(t, "test@example.com", response.User.Email)
		
		mockService.AssertExpectations(t)
	})

	t.Run("should fail with invalid credentials - 401 Unauthorized", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		mockService.On("Login", mock.Anything, mock.Anything).Return(nil, domain.ErrInvalidCredentials)

		reqBody := domain.LoginRequest{
			Email:    "test@example.com",
			Password: "WrongPassword",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "invalid_credentials", response["error"])
		
		mockService.AssertExpectations(t)
	})

	t.Run("should fail with user not found - 401 Unauthorized", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		mockService.On("Login", mock.Anything, mock.Anything).Return(nil, domain.ErrUserNotFound)

		reqBody := domain.LoginRequest{
			Email:    "nonexistent@example.com",
			Password: "SecurePass123",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		mockService.AssertExpectations(t)
	})

	t.Run("should fail with validation error - 400 Bad Request", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		mockService.On("Login", mock.Anything, mock.Anything).Return(nil, domain.ErrValidationFailed)

		reqBody := domain.LoginRequest{
			Email:    "invalid-email",
			Password: "SecurePass123",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
		
		mockService.AssertExpectations(t)
	})

	t.Run("should fail with invalid JSON - 400 Bad Request", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		invalidJSON := []byte(`{"email": }`)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(invalidJSON))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should fail with empty request body - 400 Bad Request", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		handler := rest.NewAuthHandler(mockService)
		router := setupTestRouter(handler)

		// Act
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer([]byte{}))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
