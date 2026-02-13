# Test script for authentication API endpoints
# This script tests the complete authentication flow

Write-Host "🧪 Testing Go-Finance Authentication API" -ForegroundColor Cyan
Write-Host "==========================================`n" -ForegroundColor Cyan

$baseUrl = "http://localhost:8081"
$testEmail = "test@example.com"
$testPassword = "SecurePass123!"
$testName = "Test User"

# Test 1: Health Check
Write-Host "✅ Test 1: Health Check" -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$baseUrl/api/health" -Method GET
    Write-Host "Response:" -ForegroundColor Green
    $health | ConvertTo-Json
} catch {
    Write-Host "❌ Failed: $_" -ForegroundColor Red
}

Write-Host "`n---`n"

# Test 2: User Registration
Write-Host "✅ Test 2: User Registration" -ForegroundColor Yellow
$registerBody = @{
    email = $testEmail
    password = $testPassword
    full_name = $testName
} | ConvertTo-Json

try {
    $registerResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/register" -Method POST -Body $registerBody -ContentType "application/json"
    Write-Host "✓ Registration successful!" -ForegroundColor Green
    Write-Host "Response:" -ForegroundColor Green
    $registerResponse | ConvertTo-Json
} catch {
    if ($_.Exception.Response.StatusCode -eq 409) {
        Write-Host "⚠️  User already exists (expected if running test multiple times)" -ForegroundColor Yellow
    } else {
        Write-Host "❌ Failed: $_" -ForegroundColor Red
        Write-Host $_.Exception.Response.StatusCode -ForegroundColor Red
    }
}

Write-Host "`n---`n"

# Test 3: User Login
Write-Host "✅ Test 3: User Login" -ForegroundColor Yellow
$loginBody = @{
    email = $testEmail
    password = $testPassword
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
    Write-Host "✓ Login successful!" -ForegroundColor Green
    Write-Host "Response:" -ForegroundColor Green
    $loginResponse | ConvertTo-Json
    
    $token = $loginResponse.access_token
    Write-Host "`n🔑 JWT Token obtained: $($token.Substring(0,50))..." -ForegroundColor Cyan
} catch {
    Write-Host "❌ Failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "`n---`n"

# Test 4: Access Protected Route with Token
Write-Host "✅ Test 4: Access Protected Endpoint (with valid token)" -ForegroundColor Yellow
try {
    $headers = @{
        "Authorization" = "Bearer $token"
    }
    $protectedResponse = Invoke-RestMethod -Uri "$baseUrl/api/protected" -Method GET -Headers $headers
    Write-Host "✓ Protected endpoint accessed successfully!" -ForegroundColor Green
    Write-Host "Response:" -ForegroundColor Green
    $protectedResponse | ConvertTo-Json
} catch {
    Write-Host "❌ Failed: $_" -ForegroundColor Red
}

Write-Host "`n---`n"

# Test 5: Access Protected Route without Token
Write-Host "✅ Test 5: Access Protected Endpoint (without token - should fail)" -ForegroundColor Yellow
try {
    $protectedResponse = Invoke-RestMethod -Uri "$baseUrl/api/protected" -Method GET
    Write-Host "❌ SECURITY ISSUE: Protected endpoint accessible without token!" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "✓ Correctly rejected (401 Unauthorized)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Unexpected status code: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    }
}

Write-Host "`n---`n"

# Test 6: Invalid Credentials
Write-Host "✅ Test 6: Login with Invalid Credentials (should fail)" -ForegroundColor Yellow
$invalidLoginBody = @{
    email = $testEmail
    password = "WrongPassword123!"
} | ConvertTo-Json

try {
    $invalidLogin = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method POST -Body $invalidLoginBody -ContentType "application/json"
    Write-Host "❌ SECURITY ISSUE: Login succeeded with wrong password!" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "✓ Correctly rejected (401 Unauthorized)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Unexpected status code: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    }
}

Write-Host "`n==========================================`n" -ForegroundColor Cyan
Write-Host "✅ All authentication tests completed!" -ForegroundColor Green
