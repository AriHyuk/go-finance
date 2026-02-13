# Go Testing Guide for go-finance

## 📚 Overview

This project uses **proper Go testing** with the standard `*_test.go` naming convention, following best practices for unit tests, integration tests, and mocking.

## 🏗️ Test Structure

```
go-finance/
├── internal/
│   ├── core/
│   │   └── service/
│   │       ├── auth_service.go
│   │       └── auth_service_test.go        # ✅ Unit tests (15+ test cases)
│   ├── adapter/
│   │   ├── handler/rest/
│   │   │   ├── auth_handler.go
│   │   │   └── auth_handler_test.go        # ✅ HTTP handler tests (11 test cases)
│   │   └── repository/postgres/
│   │       ├── user_repo.go
│   │       └── user_repo_test.go           # (To be implemented)
│   └── middleware/
│       ├── jwt_guard.go
│       └── jwt_guard_test.go               # ✅ Middleware tests (10 test cases)
```

## 🧪 Test Coverage

### 1. Service Layer Tests (`auth_service_test.go`)
**15+ test cases** covering:
- ✅ Register: success, duplicate email, validation errors (invalid email, short password, empty name)
- ✅ Login: success, invalid password, non-existent user, validation errors
- ✅ ValidateToken: valid token, invalid token, empty token, wrong secret
- ✅ Repository error handling

### 2. Handler Layer Tests (`auth_handler_test.go`)
**11 test cases** covering:
- ✅ Register endpoint: 201 Created, 409 Conflict (duplicate), 400 Bad Request (validation, invalid JSON)
- ✅ Login endpoint: 200 OK, 401 Unauthorized (invalid credentials, user not found), 400 Bad Request (validation, invalid JSON, empty body)

### 3. Middleware Tests (`jwt_guard_test.go`)
**10 test cases** covering:
- ✅ Valid token access and user ID injection
- ✅ Invalid/expired token rejection (401)
- ✅ Missing Authorization header (401)
- ✅ Malformed Bearer format (401)
- ✅ GetUserIDFromContext helper function

## 🚀 Running Tests

### Run All Tests
```bash
go test ./...
```

### Run Tests with Verbose Output
```bash
go test ./... -v
```

### Run Tests with Coverage
```bash
go test ./... -cover
```

### Run Tests in Specific Package
```bash
# Service tests only
go test ./internal/core/service -v

# Handler tests only
go test ./internal/adapter/handler/rest -v

# Middleware tests only
go test ./internal/middleware -v
```

### Run Specific Test
```bash
go test -run TestAuthService_Register ./internal/core/service
```

### Run Tests with Coverage Report
```bash
# Generate coverage profile
go test ./... -coverprofile=coverage.out

# View coverage in browser
go tool cover -html=coverage.out
```

## 📊 Test Results

All tests use:
- **testify/assert** for assertions
- **testify/mock** for mocking dependencies
- **httptest** for HTTP testing
- **gin.TestMode** for Gin router testing

## 🎯 Best Practices Applied

### 1. **Arrange-Act-Assert Pattern**
```go
func TestExample(t *testing.T) {
    // Arrange - setup test data and mocks
    mockRepo := new(MockUserRepository)
    service := NewAuthService(mockRepo, "secret")
    
    // Act - execute the function under test
    result, err := service.Register(ctx, req)
    
    // Assert - verify the results
    assert.NoError(t, err)
    assert.NotNil(t, result)
}
```

### 2. **Table-Driven Tests** (where applicable)
```go
func TestMultipleScenarios(t *testing.T) {
    t.Run("scenario 1", func(t *testing.T) { /* test */ })
    t.Run("scenario 2", func(t *testing.T) { /* test */ })
}
```

### 3. **Mocking with Interfaces**
```go
type MockUserRepository struct {
    mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
    args := m.Called(ctx, user)
    return args.Error(0)
}
```

### 4. **HTTP Testing with httptest**
```go
w := httptest.NewRecorder()
req := httptest.NewRequest("POST", "/api/auth/register", body)
router.ServeHTTP(w, req)

assert.Equal(t, http.StatusCreated, w.Code)
```

## 🔄 Comparison: PowerShell Script vs Go Tests

| Aspect | PowerShell Script | Go Tests |
|--------|-------------------|----------|
| **Type** | E2E/Integration | Unit + Integration |
| **Scope** | Full HTTP endpoints | Per-function/per-layer |
| **Speed** | Slow (needs server) | Fast (isolated) |
| **Mocking** | None | Full mocking support |
| **CI/CD** | Limited | Native support |
| **Coverage** | Not measurable | Measurable (`-cover`) |
| **Isolation** | Requires DB | Can run without DB |

## 📝 Adding New Tests

### For a New Service Function:
1. Create test in `*_service_test.go`
2. Mock dependencies using `testify/mock`
3. Test success case + error cases
4. Verify mock expectations

### For a New HTTP Handler:
1. Create test in `*_handler_test.go`
2. Mock the service layer
3. Use `httptest` to create requests
4. Assert HTTP status codes and response bodies

### For New Middleware:
1. Create test in `*_middleware_test.go`
2. Setup test router with middleware
3. Test with valid/invalid inputs
4. Verify middleware behavior

## ✅ Next Steps

- [ ] Add repository tests with test database (testcontainers)
- [ ] Add integration tests for full auth flow
- [ ] Setup CI/CD pipeline to run tests automatically
- [ ] Add benchmark tests for performance-critical functions

## 🎓 Learning Resources

- [Go Testing Package](https://pkg.go.dev/testing)
- [Testify Documentation](https://github.com/stretchr/testify)
- [Table Driven Tests](https://go.dev/wiki/TableDrivenTests)
- [Effective Go - Testing](https://go.dev/doc/effective_go#testing)
