package middleware

import (
	"go-finance/internal/core/port"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ErrorResponse represents standardized error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// JWTGuard is a middleware that validates JWT tokens and injects user info into context
// Protects routes from unauthorized access
func JWTGuard(authService port.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Extract Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Missing Authorization header",
			})
			c.Abort() // Stop request processing
			return
		}

		// 2. Validate Bearer token format
		// Expected format: "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Invalid Authorization header format. Expected: Bearer <token>",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// CRITICAL SECURITY: NEVER log the token value
		// Logging tokens can expose them in logs and compromise security

		// 3. Validate token and extract user ID
		userID, err := authService.ValidateToken(tokenString)
		if err != nil {
			// Don't expose detailed token validation errors to clients
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// 4. Inject user ID into Gin context for downstream handlers
		// This allows handlers to access the authenticated user ID
		c.Set("user_id", userID)

		// 5. Continue to next handler
		c.Next()
	}
}

// GetUserIDFromContext retrieves the authenticated user ID from Gin context
// This is a helper function for handlers that need the user ID
func GetUserIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, false
	}

	id, ok := userID.(uuid.UUID)
	return id, ok
}
