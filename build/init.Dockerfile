FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o rootseal-init ./cmd/init

FROM alpine:3.23
RUN apk --no-cache add ca-certificates cryptsetup
WORKDIR /root/

COPY --from=builder /app/rootseal-init /usr/local/bin/rootseal-init
RUN chmod +x /usr/local/bin/rootseal-init

ENTRYPOINT ["rootseal-init"]
