FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -trimpath \
    -o rootseal ./cmd/rootseal

FROM alpine:3.23
RUN apk --no-cache add ca-certificates cryptsetup
WORKDIR /root/

COPY --from=builder /app/rootseal /usr/local/bin/rootseal
RUN chmod +x /usr/local/bin/rootseal

CMD ["rootseal"]
