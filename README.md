# NaabuM8 - Network Asset Audit & Brute-force Utility Mate

<div align="center">

**Production-grade Go microservice for distributed network port scanning and service enumeration.**

[![Go Version](https://img.shields.io/badge/Go-1.21.5+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker)](dockerfile)
[![Status](https://img.shields.io/badge/status-pre--production-orange)](https://github.com/yourusername/naabum8)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

[Features](#key-features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Architecture](#architecture) • [API](#api-reference)

</div>

---

## Overview

NaabuM8 (Network Asset Audit & Brute-force Utility Mate) is an enterprise-grade port scanning orchestration service that integrates multiple security tools into a unified API-driven platform. It combines the power of Naabu (fast port scanner), Nmap (service detection), and HTTPx (HTTP enumeration) with PostgreSQL persistence and RabbitMQ-based message queuing for scalable, distributed scanning operations.

**Built for:**
- Security operations teams managing network inventories
- Penetration testers conducting infrastructure assessments
- Red teams performing reconnaissance operations
- DevSecOps engineers automating security validation

### Key Features

- **Multi-Tool Integration**: Combines Naabu v2.3.1, Nmap, and HTTPx v1.6.7 for comprehensive scanning
- **Distributed Architecture**: RabbitMQ-based message queuing with advanced connection pooling
- **Reliable Message Processing**: Manual acknowledgment mode prevents data loss during service crashes
- **RESTful API**: Gin-based HTTP API with health check endpoints
- **Data Persistence**: PostgreSQL database with structured schema for domains, hostnames, services, and endpoints
- **Graceful Shutdown**: Signal handling (SIGINT/SIGTERM) with proper resource cleanup
- **Docker Support**: Multi-stage builds with Alpine Linux for production deployment
- **Kubernetes Ready**: Health and readiness probes for container orchestration

---

## Quick Start

### Prerequisites

- **Go** 1.21.5 or higher
- **PostgreSQL** 12+ (for data persistence)
- **RabbitMQ** 3.8+ (for message queuing)
- **Nmap** system binary (for service detection)
- **libpcap** for packet capture (Naabu dependency)
- **Docker** (optional, for containerized deployment)

### Installation

#### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/naabum8.git
cd naabum8

# Install dependencies
go mod download

# Build the binary
go build -o naabum8 .

# Verify installation
./naabum8 version
```

#### Option 2: Docker

```bash
# Build the Docker image
docker build -t naabum8:latest .

# Run the container
docker run -d \
  -p 8001:8001 \
  -e POSTGRESQL_HOSTNAME=your-db-host \
  -e RABBITMQ_HOSTNAME=your-rabbitmq-host \
  --name naabum8 \
  naabum8:latest
```

### Configuration

1. Copy the example configuration:
```bash
cp configs/configuration_template.yaml configs/configuration.yaml
```

2. Edit `configs/configuration.yaml` with your settings (see below)

3. Set environment variables for sensitive data:

**IMPORTANT**: For security, use environment variables for sensitive data:

```bash
export POSTGRESQL_HOSTNAME="localhost"
export POSTGRESQL_DB="naabum8_db"
export POSTGRESQL_USERNAME="naabum8_user"
export POSTGRESQL_PASSWORD="your_secure_password"

export RABBITMQ_HOSTNAME="localhost"
export RABBITMQ_USERNAME="naabum8_user"
export RABBITMQ_PASSWORD="your_secure_password"

export NAABUM8_URL="http://localhost:8001"
export KATANAM8_URL="http://katanam8:8002"
```

### Configuration Example

The configuration file supports environment variable substitution using `${VARIABLE_NAME}` syntax:

```yaml
APP_ENV: "DEV"  # DEV, TEST, or PROD
LOG_LEVEL: 0    # 0=Debug, 1=Info, 2=Warn, 3=Error, 4=Fatal, 5=Panic

Database:
  location: "${POSTGRESQL_HOSTNAME}"
  database: "${POSTGRESQL_DB}"
  username: "${POSTGRESQL_USERNAME}"
  password: "${POSTGRESQL_PASSWORD}"
  port: 5432
  schema: "public"

RabbitMQ:
  location: "${RABBITMQ_HOSTNAME}"
  username: "${RABBITMQ_USERNAME}"
  password: "${RABBITMQ_PASSWORD}"
  port: 5672
  # Connection pool settings
  max_connections: 10
  min_connections: 2
  max_idle_time: "1h"
  max_lifetime: "2h"

NAABUM8:
  ports: "1-65535"
  threads: 50
  timeout: 10000
  retries: 3
  rate: 1000
  scan_type: "s"  # s=SYN, c=Connect, u=UDP
  enable_nmap: true
  nmap_command: "nmap -sV -p {ports} {ip}"
```

See [configs/configuration_template.yaml](configs/configuration_template.yaml) for complete configuration options.

### Database Setup

```sql
-- Create database
CREATE DATABASE naabum8_db;

-- Connect to the database
\c naabum8_db

-- Create necessary tables (refer to database migration files or documentation)
-- Example domain table:
CREATE TABLE domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Example hostname table:
CREATE TABLE hostnames (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id UUID REFERENCES domains(id),
    hostname VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Additional tables: services, endpoints, hostnameinfo
-- (See docs/ARCHITECTURE.md for complete schema)
```

---

## Usage

### Basic Workflow

```bash
# 1. Start the service
./naabum8 launch --ip 0.0.0.0 --port 8001

# 2. Run a full scan of all enabled hostnames
curl -X GET http://localhost:8001/scan

# 3. Scan specific hostnames
curl -X POST http://localhost:8001/scan \
  -H "Content-Type: application/json" \
  -d '{"hostnames": ["example.com", "test.example.com"]}'

# 4. Scan hostnames under a specific domain
curl -X GET http://localhost:8001/scan/domain/{domain-uuid}

# 5. Check service health
curl http://localhost:8001/health
```

### Command-Line Options

```bash
# Display help
./naabum8 --help
./naabum8 launch --help

# Show version information
./naabum8 version

# Launch on specific IP and port
./naabum8 launch --ip 127.0.0.1 --port 8001
```

---

## API Reference

### Scanning Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/scan` | Launch full scan across all enabled hosts |
| `POST` | `/scan` | Scan specific hostnames from request body |
| `GET` | `/scan/domain/:id` | Scan hostnames under specific domain |

### Health Check Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness probe (always 200 OK) |
| `GET` | `/ready` | Readiness probe (checks DB + RabbitMQ) |

**Example Response:**
```json
{
  "status": "success",
  "message": "Scan completed",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "hostnames_scanned": 15,
  "ports_discovered": 127,
  "endpoints_found": 23
}
```

---

## Architecture

### High-Level Overview

```
┌─────────────┐
│   Client    │───┐
│   (HTTP)    │   │
└─────────────┘   │
                  │    ┌─────────────┐    ┌─────────────┐
┌─────────────┐   ├───▶│  NaabuM8    │───▶│  Database   │
│  RabbitMQ   │   │    │  API (Gin)  │    │ (PostgreSQL)│
│  (Message   │───┘    └─────────────┘    └─────────────┘
│   Queue)    │                 │
└─────────────┘                 │
                 ┌──────────────┼──────────────┐
                 ▼              ▼              ▼
         ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
         │   Naabu     │ │    Nmap     │ │    HTTPx    │
         │Port Scanner │ │   Service   │ │  Endpoint   │
         │(ProjectDisc)│ │  Detection  │ │   Probing   │
         └─────────────┘ └─────────────┘ └─────────────┘
```

### Scanning Workflow

**Complete Scan Pipeline:**

```
1. TRIGGER
   └─→ HTTP API request OR RabbitMQ message (with delivery tag)

2. DATABASE QUERY
   └─→ Fetch enabled hostnames from PostgreSQL

3. PORT DISCOVERY
   ├─→ Naabu concurrent port scanning
   └─→ Results aggregation → Database storage

4. SERVICE DETECTION (Optional)
   ├─→ Nmap service enumeration
   └─→ Version detection → Database storage

5. HTTP ENUMERATION
   ├─→ HTTPx endpoint discovery
   └─→ HTTP/HTTPS probing → Database storage

6. ORCHESTRATION
   └─→ Publish completion message to RabbitMQ
       └─→ Trigger downstream services (e.g., Katanam8)

7. ACKNOWLEDGMENT
   └─→ ACK (success) or NACK (failure) to RabbitMQ
       └─→ Failed scans requeued for retry
```

### Package Structure

```
naabum8/
├── cmd/                    # CLI commands (Cobra)
│   ├── root.go            # Base command setup
│   ├── launch.go          # API service launcher
│   └── version.go         # Version information
├── pkg/                    # 13 packages, 42 Go files
│   ├── amqpM8/            # RabbitMQ connection pooling (5 files)
│   ├── api8/              # HTTP API routes and initialization
│   ├── cleanup8/          # Temporary file cleanup utilities
│   ├── configparser/      # Configuration management (Viper)
│   ├── controller8/       # Business logic controllers
│   ├── db8/               # Database access layer (6 modules)
│   ├── log8/              # Structured logging (zerolog)
│   ├── model8/            # Data models and domain entities (13 files)
│   ├── notification8/     # Notification system (multi-channel)
│   ├── orchestrator8/     # Service orchestration
│   └── utils/             # Utility functions
├── configs/               # Configuration files
├── docs/                  # Comprehensive documentation
└── main.go                # Application entry point
```

### Key Components

- **[API Layer](pkg/api8/)** - Gin-based REST API
- **[Controllers](pkg/controller8/)** - Business logic and scan orchestration
- **[Database Layer](pkg/db8/)** - PostgreSQL repository pattern (6 modules)
- **[Message Queue](pkg/amqpM8/)** - RabbitMQ with connection pooling (5 files)
- **[Orchestrator](pkg/orchestrator8/)** - Service coordination and message routing

For detailed architecture documentation, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Advanced Features

### RabbitMQ Manual Acknowledgment

NaabuM8 implements reliable message processing with manual acknowledgment mode:

- **Delivery Tag Tracking**: Messages tracked via HTTP headers (`X-RabbitMQ-Delivery-Tag`)
- **At-Least-Once Delivery**: Guarantees messages processed at least once
- **Automatic Retry**: Failed scans automatically requeued via NACK
- **Panic Recovery**: Defer functions ensure proper cleanup on crashes
- **Observability**: Delivery tags logged for message lifecycle tracking

```go
// Defer function ensures ACK/NACK even on panic
defer func() {
    if r := recover(); r != nil {
        log8.BaseLogger.Error().Msgf("PANIC recovered: %v", r)
        scanCompleted = false
    }
    if deliveryTag > 0 {
        orch.AckScanCompletion(deliveryTag, scanCompleted)
    }
}()
```

### Connection Pooling

Advanced connection pooling for RabbitMQ:

- Configurable pool size (max/min connections)
- Automatic connection lifecycle management
- Idle timeout and maximum lifetime settings
- Shared state for consistency across goroutines

### Graceful Shutdown

Signal handling for clean service termination:

```go
// Handles SIGINT and SIGTERM
quit := make(chan os.Signal, 1)
signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
<-quit

// Cleanup RabbitMQ connection pool
amqpM8.ClosePooledConnection()
```

---

## External Tools

NaabuM8 integrates with industry-standard security tools:

| Tool | Version | Purpose | Repository |
|------|---------|---------|------------|
| [Naabu](https://github.com/projectdiscovery/naabu) | v2.3.1 | Fast port scanning | ProjectDiscovery |
| [Nmap](https://nmap.org/) | Latest | Service detection and version enumeration | Nmap Project |
| [HTTPx](https://github.com/projectdiscovery/httpx) | v1.6.7 | HTTP endpoint enumeration | ProjectDiscovery |

All external tools are included in the Docker image.

---

## Performance

**Typical Performance Metrics:**

- **Port Scanning**: 1-10 minutes for 65,535 ports (depends on network and rate limits)
- **Service Detection**: 2-5 minutes additional (if Nmap enabled)
- **HTTP Enumeration**: 1-3 minutes for discovered services
- **Database Operations**: Batch insertions for optimal performance
- **Concurrent Processing**: Configurable threads (default: 50)

**Resource Requirements:**

- **CPU**: 2+ cores recommended
- **Memory**: 2 GB minimum, 4 GB recommended
- **Storage**: 10 GB for application + logs + temporary files
- **Network**: Low-latency connection to target infrastructure

For optimization tips, see [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

---

## Development

### Development Commands

```bash
# Format code
go fmt ./...

# Run static analysis
go vet ./...

# Run linter (if golangci-lint is installed)
golangci-lint run

# Clean dependencies
go mod tidy
```

### Testing

**Note**: No unit tests currently exist in the codebase. Target: 80%+ coverage for new code.

```bash
# Run tests (when implemented)
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./...
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed testing guidelines.

---

## Deployment

### Docker Deployment

The project includes a multi-stage Dockerfile optimized for production with Alpine Linux (3.20), Nmap, libpcap, and tini for proper signal handling.

### Docker Compose

Example `docker-compose.yml`:

```yaml
version: '3.8'
services:
  naabum8:
    image: naabum8:latest
    ports:
      - "8001:8001"
    environment:
      - POSTGRESQL_HOSTNAME=postgres
      - RABBITMQ_HOSTNAME=rabbitmq
      - APP_ENV=PROD
    depends_on:
      - postgres
      - rabbitmq
    volumes:
      - ./configs:/app/configs
      - ./log:/app/log

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=naabum8_db
      - POSTGRES_USER=naabum8_user
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  rabbitmq:
    image: rabbitmq:3.12-management-alpine
    environment:
      - RABBITMQ_DEFAULT_USER=naabum8_user
      - RABBITMQ_DEFAULT_PASS=secure_password
    ports:
      - "15672:15672"  # Management UI
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq

volumes:
  postgres_data:
  rabbitmq_data:
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: naabum8
spec:
  replicas: 2
  selector:
    matchLabels:
      app: naabum8
  template:
    metadata:
      labels:
        app: naabum8
    spec:
      containers:
      - name: naabum8
        image: naabum8:latest
        ports:
        - containerPort: 8001
        env:
        - name: APP_ENV
          value: "PROD"
        - name: POSTGRESQL_HOSTNAME
          valueFrom:
            secretKeyRef:
              name: naabum8-secrets
              key: db-host
        livenessProbe:
          httpGet:
            path: /health
            port: 8001
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8001
          initialDelaySeconds: 10
          periodSeconds: 5
```

### Production Checklist

- [ ] Rotate all credentials before deployment
- [ ] Use environment variables for all secrets
- [ ] Enable SSL/TLS for database connections (`sslmode=require`)
- [ ] Configure connection pooling (database and RabbitMQ)
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Configure log aggregation (ELK/Loki)
- [ ] Implement rate limiting on API endpoints
- [ ] Add authentication/authorization
- [ ] Set up backup strategy for PostgreSQL
- [ ] Configure resource limits (CPU/memory)

---

## Documentation

Comprehensive documentation is available in the [docs/](docs/) directory:

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Detailed system architecture and design patterns |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Development setup and guidelines |
| [SECURITY.md](docs/SECURITY.md) | Security best practices and audit findings |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | Performance optimization and analysis |
| [TODO.md](docs/TODO.md) | Known issues, roadmap, and improvement backlog |
| [CODE_REVIEW.md](docs/CODE_REVIEW.md) | Code review checklist and assessment |

---

## Security Considerations

### Current Limitations

- No authentication on API endpoints (planned for v2.0)
- Database credentials in configuration file (use environment variables)
- Limited input validation (basic Gin binding only)

### Recommendations

1. **Use environment variables** for all secrets
2. **Deploy behind API gateway** with authentication
3. **Enable TLS/SSL** for production deployments
4. **Implement rate limiting** to prevent abuse
5. **Run as non-root user** in containers (already configured)

See [docs/SECURITY.md](docs/SECURITY.md) for comprehensive security guidelines.

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow Go best practices and existing code style
4. Add tests for new functionality (target: 80%+ coverage)
5. Update documentation as needed
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed development guidelines.

---

## Roadmap

### Version 1.x (Current)
- [x] Core port scanning functionality
- [x] Nmap service detection integration
- [x] HTTPx endpoint enumeration
- [x] PostgreSQL persistence
- [x] RabbitMQ message queuing with manual ACK
- [x] Docker containerization
- [x] Health check endpoints

### Version 2.0 (Planned)
- [ ] JWT-based authentication
- [ ] Rate limiting and request throttling
- [ ] Unit and integration tests (target: 80% coverage)
- [ ] Kubernetes deployment manifests
- [ ] Prometheus metrics integration
- [ ] GraphQL API option
- [ ] Web dashboard for visualization

See [docs/TODO.md](docs/TODO.md) for the complete roadmap and known issues.

---

## Troubleshooting

### Common Issues

**1. Database connection failures**
```bash
# Check PostgreSQL is running
systemctl status postgresql

# Verify connection settings in configs/configuration.yaml
# Ensure database and tables are created
```

**2. RabbitMQ connection errors**
```bash
# Check RabbitMQ status
systemctl status rabbitmq-server

# Verify credentials and port in configuration
# Check exchange and queue creation
```

**3. Nmap not found**
```bash
# Ensure Nmap is installed
which nmap

# Install if needed (Debian/Ubuntu)
sudo apt-get install nmap

# Install if needed (Alpine)
apk add nmap
```

**4. Permission errors**
```bash
# Ensure log directory is writable
chmod 755 log/ app/log/

# Check file permissions for config files
chmod 640 configs/configuration.yaml
```

---

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for Naabu and HTTPx
- [Nmap Project](https://nmap.org/) for network scanning capabilities
- [Gin Web Framework](https://github.com/gin-gonic/gin) for the HTTP router
- [RabbitMQ](https://www.rabbitmq.com/) for reliable message queuing
- [PostgreSQL](https://www.postgresql.org/) for robust data persistence

---

## Contact

For questions, issues, or feature requests, please open an issue on GitHub.

**Project Link:** [https://github.com/yourusername/naabum8](https://github.com/yourusername/naabum8)

---

<div align="center">

**Built for the security community**

**Note**: This software is intended for authorized security testing and network reconnaissance. Users are responsible for compliance with applicable laws and regulations.

[⬆ Back to Top](#naabum8---network-asset-audit--brute-force-utility-mate)

</div>
