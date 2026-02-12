FROM golang:alpine AS builder

WORKDIR /app

# Download dependencies dulu (di-cache biar build selanjutnya cepet)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary aplikasi
# -o main: nama output binary
# ./cmd/api: lokasi main.go kamu
RUN go build -o main ./cmd/api

# --- Stage 2: Run ---
FROM alpine:latest

WORKDIR /app

# Install sertifikat SSL (penting kalo app kamu request ke https luar)
RUN apk --no-cache add ca-certificates

# Copy binary dari Stage 1
COPY --from=builder /app/main .
# COPY --from=builder /app/.env . 
# Note: Di production asli, .env jangan di-copy, tapi inject dari secret manager. 
# Untuk belajar/dev, copy .env gapapa.

# Expose port (sesuai app kamu)
EXPOSE 8080

# Jalankan
CMD ["./main"]