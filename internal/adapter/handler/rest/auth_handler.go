package rest

import (
	"errors"
	"go-finance/internal/core/domain"
	"go-finance/internal/core/port"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles HTTP requests for authentication endpoints
// This is an ADAPTER in Clean Architecture (HTTP -> Domain)
type AuthHandler struct {
	authService port.AuthService
}

// ErrorResponse represents standardized error response format
// Follows the pattern: { "error": "error_code", "message": "human-readable message" }
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// NewAuthHandler creates a new instance of AuthHandler
// Uses dependency injection for auth service
func NewAuthHandler(authService port.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Register handles POST /auth/register
// @Summary Register a new user
// @Accept json
// @Produce json
// @Param request body domain.RegisterRequest true "Registration details"
// @Success 201 {object} domain.UserResponse
// @Failure 400 {object} ErrorResponse "Validation error"
// @Failure 409 {object} ErrorResponse "Email already exists"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req domain.RegisterRequest

	// Bind and validate JSON request body
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body: " + err.Error(),
		})
		return
	}

	// Call service layer to register user
	user, err := h.authService.Register(c.Request.Context(), req)
	if err != nil {
		// Map domain errors to HTTP status codes
		switch {
		case errors.Is(err, domain.ErrDuplicateEmail):
			c.JSON(http.StatusConflict, ErrorResponse{
				Error:   "duplicate_email",
				Message: "This email address is already registered",
			})
		case errors.Is(err, domain.ErrValidationFailed):
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:   "validation_failed",
				Message: err.Error(),
			})
		default:
			// CRITICAL: Don't expose internal errors to clients
			// Log the actual error internally but return generic message
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "internal_error",
				Message: "Failed to register user",
			})
		}
		return
	}

	// Return 201 Created with user data (password hash is never included)
	c.JSON(http.StatusCreated, user)
}

// Login handles POST /auth/login
// @Summary Authenticate user and return JWT token
// @Accept json
// @Produce json
// @Param request body domain.LoginRequest true "Login credentials"
// @Success 200 {object} domain.AuthResponse
// @Failure 400 {object} ErrorResponse "Validation error"
// @Failure 401 {object} ErrorResponse "Invalid credentials"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req domain.LoginRequest

	// Bind and validate JSON request body
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body: " + err.Error(),
		})
		return
	}

	// Call service layer to authenticate user
	authResponse, err := h.authService.Login(c.Request.Context(), req)
	if err != nil {
		// Map domain errors to HTTP status codes
		switch {
		case errors.Is(err, domain.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "invalid_credentials",
				Message: "Invalid email or password",
			})
		case errors.Is(err, domain.ErrValidationFailed):
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:   "validation_failed",
				Message: err.Error(),
			})
		default:
			// CRITICAL: Don't expose internal errors to clients
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "internal_error",
				Message: "Failed to authenticate user",
			})
		}
		return
	}

	// Return 200 OK with access token and user info
	c.JSON(http.StatusOK, authResponse)
}
