# Docker Compose Development Environment

Quick local development setup with Postgres, Vault, and the rootseal server.

## Usage

```bash
# Generate certificates first
cd ../..
./scripts/mkcerts.sh

# Start the stack
cd deploy/compose
docker-compose up -d

# Check logs
docker-compose logs -f rootseal-server

# Stop the stack
docker-compose down
```

## Services

- **postgres**: Database on port 5432
- **vault**: Dev mode on port 8200 (token: `dev-root-token`)
- **rootseal-server**: gRPC server on port 50051

## Testing

```bash
# Test with agent
rootseal-agent postimaging --device=/dev/sdb1 --server=localhost:50051
```
