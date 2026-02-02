FROM golang:alpine

WORKDIR /app

COPY go.mod ./
# COPY go.sum ./
# RUN go mod download

COPY . .

# 5. Build aplikasi jadi binary namanya "finance-app"
RUN go build -o go-finance .

CMD ["./go-finance"]

