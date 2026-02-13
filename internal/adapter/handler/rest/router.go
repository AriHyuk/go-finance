package rest

import (
	"go-finance/internal/core/port"
	"go-finance/internal/middleware"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewRouter creates and configures the Gin router with all routes and middleware
// This function encapsulates all route registration logic, keeping main.go clean
func NewRouter(authHandler *AuthHandler, authService port.AuthService, dbPool *pgxpool.Pool) *gin.Engine {
	r := gin.Default()

	// ========================================
	// API GROUP - All routes under /api
	// ========================================
	apiGroup := r.Group("/api")
	{
		// Health check endpoint
		apiGroup.GET("/health", func(c *gin.Context) {
			// Check database status
			err := dbPool.Ping(c.Request.Context())
			status := "ok"
			dbStatus := "connected"
			httpCode := http.StatusOK

			if err != nil {
				status = "degraded"
				dbStatus = "disconnected: " + err.Error()
				httpCode = http.StatusServiceUnavailable
			}

			c.JSON(httpCode, gin.H{
				"status":   status,
				"database": dbStatus,
				"service":  "go-finance",
			})
		})

		// ========================================
		// PUBLIC ROUTES (No Authentication)
		// ========================================

		// Authentication routes - /api/auth/*
		authGroup := apiGroup.Group("/auth")
		{
			authGroup.POST("/register", authHandler.Register)
			authGroup.POST("/login", authHandler.Login)
		}

		// ========================================
		// PROTECTED ROUTES (Require JWT)
		// ========================================

		// Apply JWT middleware to protected routes
		apiGroup.Use(middleware.JWTGuard(authService))

		// Demo protected endpoint to show JWT middleware in action
		apiGroup.GET("/protected", func(c *gin.Context) {
			// Get user ID injected by JWT middleware
			userID, exists := middleware.GetUserIDFromContext(c)
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "User ID not found in context",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "This is a protected endpoint",
				"user_id": userID.String(),
			})
		})
	}

	return r
}
