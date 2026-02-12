run:
	go run cmd/api/main.go

build:
	go build -o bin/go-finance cmd/api/main.go

# Docker commands
docker-up:
	docker-compose up --build

docker-down:
	docker-compose down

# Database migration (nanti kita bahas tools migrate)
migrate-up:
	migrate -path migrations -database "postgresql://postgres:rahasia@localhost:5432/belajar_go?sslmode=disable" -verbose up

.PHONY: run build docker-up docker-down