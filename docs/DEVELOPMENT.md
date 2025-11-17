# Development Guidelines: NaabuM8

**Last Updated:** 2025-01-18
**Status:** Active Development Guidelines

## 🚀 Getting Started

### Prerequisites
- **Go 1.23** or higher (currently using Go 1.23)
- **PostgreSQL 12+** (tested with PostgreSQL 12+)
- **RabbitMQ 3.8+** (tested with RabbitMQ 3.8+)
- **Nmap** (external binary required for service detection)
- **Docker** (optional, for containerized deployment)
- **Redis** (optional, for future caching implementation)

### Local Development Setup

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd NaabuM8
   go mod download
   ```

2. **Configuration Setup**
   ```bash
   # Copy template configuration
   cp configs/configuration_template.yaml configs/configuration.yaml

   # Set environment variables (recommended for security)
   export POSTGRESQL_HOSTNAME="localhost"
   export POSTGRESQL_DB="cptm8"
   export POSTGRESQL_USERNAME="cpt_dbuser"
   export POSTGRESQL_PASSWORD="your-secure-db-password"
   export RABBITMQ_HOSTNAME="localhost"
   export RABBITMQ_USERNAME="guest"
   export RABBITMQ_PASSWORD="your-secure-rabbitmq-password"
   export DISCORD_BOT_TOKEN="your-discord-bot-token"
   export DISCORD_WEBHOOK_TOKEN="your-discord-webhook-token"
   export NAABUM8_URL="http://localhost:8001"
   export KATANAM8_URL="http://localhost:8002"

   # Edit configuration file and use environment variable references
   # Example: password: "${POSTGRESQL_PASSWORD}"
   ```

3. **Database Setup**
   ```bash
   # Create database and run migrations
   createdb cptm8
   # Run your database migrations here
   ```

4. **Run Services**
   ```bash
   # Start RabbitMQ
   docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management
   
   # Start application
   go run main.go launch --ip 127.0.0.1 --port 8001
   ```

## 📋 Development Standards

### Code Style
- **Follow Go conventions**: Use `gofmt`, `go vet`, and `golint`
- **Package naming**: Use clear, descriptive names (avoid abbreviations like `db8`, `log8`)
- **Interface naming**: End interfaces with `Interface` or use descriptive names
- **Error handling**: Always handle errors explicitly, avoid `panic()` and `log.Fatal()`

### Good Examples
```go
// ✅ Good: Clear naming and error handling
type HostnameRepository interface {
    GetEnabledHostnames(ctx context.Context) ([]domain.Hostname, error)
}

func (r *PostgresHostnameRepository) GetEnabledHostnames(ctx context.Context) ([]domain.Hostname, error) {
    rows, err := r.db.QueryContext(ctx, "SELECT id, name FROM hostnames WHERE enabled = true")
    if err != nil {
        return nil, fmt.Errorf("failed to query hostnames: %w", err)
    }
    defer rows.Close()
    
    // ... implementation
    return hostnames, nil
}
```

### Bad Examples
```go
// ❌ Bad: Unclear naming and poor error handling
type Db8Hostname8Interface interface {
    GetAllEnabled() ([]model8.Hostname8, error)
}

func (db *Db8Hostname8) GetAllEnabled() ([]model8.Hostname8, error) {
    rows, err := db.db.Query("SELECT id, name FROM hostnames WHERE enabled = true")
    if err != nil {
        log8.BaseLogger.Fatal().Msg("Database query failed")  // ❌ Kills entire process
    }
    // ... implementation
}
```

## 🧪 Testing Guidelines

### Unit Testing
- **Test file naming**: `*_test.go`
- **Test function naming**: `TestFunctionName_Scenario_ExpectedResult`
- **Coverage target**: Minimum 80% for new code

```go
// Example test structure
func TestHostnameRepository_GetEnabledHostnames_Success(t *testing.T) {
    // Arrange
    db, mock, err := sqlmock.New()
    require.NoError(t, err)
    defer db.Close()
    
    repo := NewPostgresHostnameRepository(db)
    
    mock.ExpectQuery("SELECT id, name FROM hostnames WHERE enabled = true").
        WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
            AddRow("1", "example.com"))
    
    // Act
    hostnames, err := repo.GetEnabledHostnames(context.Background())
    
    // Assert
    require.NoError(t, err)
    assert.Len(t, hostnames, 1)
    assert.Equal(t, "example.com", hostnames[0].Name)
}
```

### Integration Testing
- Use Docker containers for database testing
- Test complete workflows end-to-end
- Use testcontainers for consistent test environments

### Testing RabbitMQ Manual Acknowledgment

**Test Scenarios for Manual ACK Mode:**

1. **Normal Scan Completion** (Should ACK):
   ```bash
   # Trigger a scan via RabbitMQ message
   # Expected: Message acknowledged after successful scan
   # Verify: Message removed from queue
   # Log verification: "Scan completed successfully (deliveryTag: X) - sending ACK"
   ```

2. **Scan Failure** (Should NACK with requeue):
   ```bash
   # Trigger a scan that will fail (e.g., invalid hostname)
   # Expected: Message NACKed and requeued
   # Verify: Message returns to queue
   # Log verification: "Scan incomplete (deliveryTag: X) - sending NACK with requeue"
   ```

3. **Service Crash/Panic** (Should NACK with requeue):
   ```bash
   # Trigger a scan and kill service during execution
   # Expected: Message remains in queue (not acknowledged)
   # Verify: Message redelivered on service restart
   # Log verification: "PANIC recovered in NaabuM8 scans"
   ```

4. **Early Exit Errors** (Should ACK or NACK):
   ```bash
   # Test various early exit paths:
   # - Init runner options failure
   # - Failed to fetch hostnames
   # - No targets in scope
   # - RabbitMQ queue setup failure
   # Expected: Appropriate ACK/NACK based on error type
   ```

**Test Configuration:**
```yaml
ORCHESTRATORM8:
  naabum8:
    Consumer:
      - "cptm8_naabum8_queue"
      - "cptm8_naabum8_consumer"
      - "false"  # auto_ack MUST be false for manual ACK mode
```

**Manual Testing with RabbitMQ Management UI:**
```bash
# 1. Access RabbitMQ Management UI
open http://localhost:15672

# 2. Navigate to queue: cptm8_naabum8_queue

# 3. Publish test message:
{
  "routing_key": "cptm8.naabum8.get.scan",
  "payload": ""
}

# 4. Monitor:
# - Message count (should decrease on ACK)
# - Unacked count (should increase during processing)
# - Redelivered count (should increase on NACK with requeue)

# 5. Check logs for delivery tag tracking:
tail -f log/naabum8.log | grep -E "deliveryTag|ACK|NACK"
```

**Unit Test Example:**
```go
func TestAckScanCompletion_Success(t *testing.T) {
    // Arrange
    mockConn := &MockPooledAmqpInterface{}
    mockChannel := &MockChannel{}
    mockConn.On("GetChannel").Return(mockChannel)

    orchestrator := &Orchestrator8{}

    // Act
    err := orchestrator.AckScanCompletion(123, true)

    // Assert
    require.NoError(t, err)
    mockChannel.AssertCalled(t, "Ack", uint64(123), false)
}

func TestAckScanCompletion_Failure(t *testing.T) {
    // Arrange
    mockConn := &MockPooledAmqpInterface{}
    mockChannel := &MockChannel{}
    mockConn.On("GetChannel").Return(mockChannel)

    orchestrator := &Orchestrator8{}

    // Act
    err := orchestrator.AckScanCompletion(123, false)

    // Assert
    require.NoError(t, err)
    mockChannel.AssertCalled(t, "Nack", uint64(123), false, true) // requeue=true
}
```

### Performance Testing
- Benchmark critical paths
- Use `go test -bench=.` for benchmarks
- Monitor memory allocations with `go test -benchmem`

## 🔧 Build and Deployment

### Build Commands
```bash
# Development build
go build -o naabum8 .

# Production build with optimizations
go build -ldflags="-s -w" -o naabum8 .

# Cross-compilation
GOOS=linux GOARCH=amd64 go build -o naabum8-linux-amd64 .
```

### Docker
```bash
# Build Docker image
docker build -t naabum8:latest .

# Run with Docker Compose
docker-compose up -d
```

### Linting and Formatting
```bash
# Format code
go fmt ./...

# Run linter
golangci-lint run

# Vet code
go vet ./...

# Run all checks
make lint  # if Makefile exists
```

## 📊 Monitoring and Debugging

### Logging Standards
- **Use structured logging**: Always use the zerolog logger
- **Log levels**: Use appropriate levels (Debug, Info, Warn, Error)
- **Context**: Include relevant context in log messages

```go
// ✅ Good logging
logger.Info().
    Str("hostname", hostname).
    Int("port_count", len(ports)).
    Msg("scan completed successfully")

// ❌ Bad logging
log.Printf("Scan completed for %s with %d ports", hostname, len(ports))
```

**RabbitMQ-Specific Logging:**
```go
// Delivery tag tracking
log8.BaseLogger.Debug().Msgf("Scan triggered via RabbitMQ (deliveryTag: %d)", deliveryTag)

// ACK logging
log8.BaseLogger.Info().Msgf("Scan completed successfully (deliveryTag: %d) - sending ACK", deliveryTag)

// NACK logging
log8.BaseLogger.Warn().Msgf("Scan incomplete (deliveryTag: %d) - sending NACK with requeue", deliveryTag)

// Handler error logging
log8.BaseLogger.Warn().Msgf("Handler failed, NACKing message (deliveryTag: %d, requeue: true)", msg.DeliveryTag)
```

### Debugging
- Use `delve` debugger for debugging: `dlv debug`
- Enable debug logging: Set `LOG_LEVEL=0` in configuration
- Use pprof for profiling: `go tool pprof`

### Performance Monitoring
- Monitor key metrics: response times, memory usage, goroutine count
- Use Prometheus metrics in production
- Set up alerts for critical thresholds

## 🔐 Security Best Practices

### Environment Variables
```bash
# Required environment variables
export DB_PASSWORD="secure-password"
export DISCORD_BOT_TOKEN="your-bot-token"
export RABBITMQ_PASSWORD="secure-password"
export ENCRYPTION_KEY="32-byte-key"
```

### Input Validation
- Always validate and sanitize input
- Use UUID validation for ID parameters
- Implement rate limiting for APIs

### Database Security
- Use prepared statements
- Enable SSL for database connections
- Implement connection timeouts

## 📝 Documentation Standards

### Code Documentation
- Use GoDoc format for public functions
- Include examples in documentation
- Document complex algorithms and business logic

```go
// GetEnabledHostnames retrieves all hostnames marked as enabled for scanning.
// It returns a slice of Hostname objects and an error if the operation fails.
//
// Example:
//   hostnames, err := repo.GetEnabledHostnames(ctx)
//   if err != nil {
//       return fmt.Errorf("failed to get hostnames: %w", err)
//   }
func (r *PostgresHostnameRepository) GetEnabledHostnames(ctx context.Context) ([]domain.Hostname, error) {
    // Implementation
}
```

### API Documentation
- Document all API endpoints
- Include request/response examples
- **TODO**: Create OpenAPI/Swagger specification (currently missing)

### Current API Endpoints
```
GET  /scan                 - Full scan across all enabled hostnames
POST /scan                 - Scan specific hostnames from request body
GET  /scan/domain/:id      - Scan hostnames under specific domain
GET  /health               - Kubernetes liveness probe
GET  /ready                - Kubernetes readiness probe
```

## 🔄 Git Workflow

### Branch Naming
- **Feature branches**: `feature/description`
- **Bug fixes**: `bugfix/description`
- **Security fixes**: `security/description`

### Commit Messages
```
type(scope): description

Examples:
feat(scan): add batch hostname scanning
fix(db): resolve connection pool exhaustion
security(auth): implement API key validation
```

### Pull Request Process
1. Create feature branch from `develop`
2. Implement changes with tests
3. Update documentation
4. Create pull request with description
5. Code review and approval
6. Merge to `develop`

## 🚦 CI/CD Pipeline

### Required Checks
- [ ] Code formatting (`go fmt`)
- [ ] Linting (`golangci-lint`)
- [ ] Unit tests (`go test`)
- [ ] Integration tests
- [ ] Security scanning
- [ ] Dependency vulnerability check

### Deployment Process
1. **Development**: Auto-deploy on merge to `develop`
2. **Staging**: Manual deployment for testing
3. **Production**: Tagged releases only

## 📚 Learning Resources

### Go Resources
- [Effective Go](https://golang.org/doc/effective_go.html)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Go Best Practices](https://peter.bourgon.org/go-best-practices-2016/)

### Architecture Resources
- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Hexagonal Architecture](https://netflixtechblog.com/ready-for-changes-with-hexagonal-architecture-b315ec967749)
- [Domain-Driven Design](https://martinfowler.com/bliki/DomainDrivenDesign.html)

## 🆘 Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Check database connectivity
psql -h localhost -U cpt_dbuser -d cptm8 -c "SELECT 1"

# Check connection pool
# Look for connection exhaustion errors in logs
```

#### RabbitMQ Issues
```bash
# Check RabbitMQ status
rabbitmqctl status

# Check queue depths
rabbitmqctl list_queues
```

#### Memory Issues
```bash
# Check for memory leaks
go tool pprof http://localhost:8001/debug/pprof/heap

# Check goroutine leaks
go tool pprof http://localhost:8001/debug/pprof/goroutine
```

### Getting Help
- Check existing issues in the repository
- Review logs with appropriate log level
- Use debugger for complex issues
- Ask for code review for architectural questions

## 🔄 Current Development Status

### Implemented Features
✅ Port scanning with Naabu v2.3.1
✅ HTTP endpoint enumeration with HTTPx v1.6.7
✅ Nmap service detection integration
✅ RabbitMQ connection pooling
✅ PostgreSQL database integration
✅ Discord notifications
✅ Graceful shutdown handling
✅ Health and readiness probes
✅ Temporary file cleanup
✅ Panic recovery in scan operations
✅ Configuration hot-reload

### Known Limitations
⚠️ No unit or integration tests
⚠️ Blocking channel issue in RabbitMQ consumer (line 289)
⚠️ N+1 query problem in hostname lookups
⚠️ Unbounded memory growth in Results8 map
⚠️ Multiple Fatal() calls instead of error returns
⚠️ No OpenAPI/Swagger documentation
⚠️ Hardcoded credentials in default configuration

### Planned Features (See [TODO.md](TODO.md))
- [ ] Comprehensive test suite (80%+ coverage)
- [ ] Batch database operations
- [ ] Memory bounds checking
- [ ] Circuit breaker pattern
- [ ] Caching layer with Redis
- [ ] Metrics and monitoring (Prometheus/Grafana)
- [ ] Rate limiting
- [ ] API authentication and authorization

## 📞 Contributing

### Code Review Process
- All changes require peer review
- Security-related changes require thorough security review
- Performance-critical changes require performance testing
- Follow guidelines in this document and [CLAUDE.md](../CLAUDE.md)

### Reporting Issues
- Check existing issues in repository
- Include reproduction steps
- Provide relevant logs and configuration
- Tag appropriately (bug, enhancement, security, etc.)