FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o rootseal-ctl ./cmd/ctl

FROM alpine:3.23
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/rootseal-ctl /usr/local/bin/rootseal-ctl
RUN chmod +x /usr/local/bin/rootseal-ctl

ENTRYPOINT ["rootseal-ctl"]
