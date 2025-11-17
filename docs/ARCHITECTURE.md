# Architecture Review: NaabuM8

**Date:** 2025-01-18
**Last Updated:** 2025-01-18
**Status:** Architectural Improvements Recommended

## 🏗️ Current Architecture

### Service Layer Structure
```
pkg/                      # 13 packages, 42 Go files
├── amqpM8/              # RabbitMQ messaging with connection pooling (5 files)
├── api8/                # HTTP API routes and initialization
├── cleanup8/            # Temporary file cleanup utilities (2 files)
├── configparser/        # Configuration management with Viper
├── controller8/         # Business logic controllers (2 controllers + interfaces)
├── db8/                 # Database access layer (6 modules + interfaces)
├── log8/                # Logging utilities with zerolog
├── model8/              # Data models and domain entities (13 files)
├── notification8/       # Discord notifications
├── orchestrator8/       # Service orchestration (2 files)
└── utils/               # Utility functions (IP validation, etc.)

cmd/                     # Command-line interface
├── root.go              # Base CLI setup with Cobra
├── launch.go            # API service launcher (main command)
└── version.go           # Version information
```

### Current Data Flow
```
HTTP Request → Controller → Database → RabbitMQ → External Services
```

## 🔧 Architectural Issues

### 1. Tight Coupling
**Problem**: Controllers directly instantiate dependencies
```go
// PROBLEMATIC: Direct dependency creation
func (m *Controller8Naabum8) Naabum8Scan(c *gin.Context) {
    orchestrator8, err := orchestrator8.NewOrchestrator8()  // ❌ Tight coupling
    hostname8 := db8.NewDb8Hostname8(DB)                    // ❌ Direct instantiation
}
```

### 2. Error Handling Inconsistency
**Problem**: Mix of fatal exits and error returns
```go
// INCONSISTENT: Some functions use Fatal, others return errors
log8.BaseLogger.Fatal().Msg("Error connecting to RabbitMQ")  // ❌ Kills process
return fmt.Errorf("failed to connect: %w", err)             // ✅ Proper error handling
```

### 3. Missing Abstraction Layers
**Problem**: No clear separation between business logic and infrastructure

## 🎯 Recommended Architecture

### 1. Hexagonal Architecture (Ports and Adapters)

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Core                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────  │
│  │   Domain        │  │   Use Cases     │  │   Interfaces │
│  │   Models        │  │   (Business     │  │   (Ports)    │
│  │                 │  │    Logic)       │  │              │
│  └─────────────────┘  └─────────────────┘  └─────────────  │
└─────────────────────────────────────────────────────────────┘
            │                    │                    │
            ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   HTTP API      │  │   Database      │  │   RabbitMQ      │
│   (Adapter)     │  │   (Adapter)     │  │   (Adapter)     │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### 2. Improved Package Structure

```
internal/
├── domain/
│   ├── models/         # Domain entities
│   ├── repositories/   # Repository interfaces
│   └── services/       # Business logic interfaces
├── usecases/
│   ├── scanning/       # Scanning use cases
│   ├── reporting/      # Reporting use cases
│   └── notification/   # Notification use cases
├── adapters/
│   ├── http/           # HTTP handlers
│   ├── database/       # Database implementations
│   ├── messaging/      # RabbitMQ implementations
│   └── external/       # External service clients
└── infrastructure/
    ├── config/         # Configuration
    ├── logging/        # Logging setup
    └── monitoring/     # Metrics and health checks
```

## 🔄 Dependency Injection Pattern

### 1. Service Container
```go
// Container holds all dependencies
type Container struct {
    Config       config.Provider
    Logger       logging.Logger
    DB           database.Connection
    MessageQueue messaging.Queue
    
    // Repositories
    HostnameRepo   repositories.HostnameRepository
    ScanRepo       repositories.ScanRepository
    
    // Services
    ScanService    services.ScanService
    NotifyService  services.NotificationService
    
    // Use Cases
    ScanUseCase    usecases.ScanUseCase
}

func NewContainer() (*Container, error) {
    container := &Container{}
    
    // Initialize dependencies in order
    if err := container.initConfig(); err != nil {
        return nil, err
    }
    if err := container.initLogger(); err != nil {
        return nil, err
    }
    if err := container.initDatabase(); err != nil {
        return nil, err
    }
    // ... continue initialization
    
    return container, nil
}
```

### 2. Interface-Based Design
```go
// Domain interfaces (ports)
type ScanService interface {
    StartScan(ctx context.Context, targets []string) (*ScanResult, error)
    GetScanStatus(ctx context.Context, scanID string) (*ScanStatus, error)
}

type HostnameRepository interface {
    GetEnabledHostnames(ctx context.Context) ([]domain.Hostname, error)
    GetHostnamesByDomain(ctx context.Context, domainID string) ([]domain.Hostname, error)
}

type MessageQueue interface {
    Publish(ctx context.Context, exchange, routingKey string, message interface{}) error
    Subscribe(ctx context.Context, queue string, handler MessageHandler) error
}
```

### 3. Clean Controllers
```go
// Controller with injected dependencies
type ScanController struct {
    scanUseCase usecases.ScanUseCase
    logger      logging.Logger
}

func NewScanController(scanUseCase usecases.ScanUseCase, logger logging.Logger) *ScanController {
    return &ScanController{
        scanUseCase: scanUseCase,
        logger:      logger,
    }
}

func (sc *ScanController) StartScan(c *gin.Context) {
    var req StartScanRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        sc.logger.Error("invalid request", "error", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    result, err := sc.scanUseCase.StartScan(c.Request.Context(), req.Targets)
    if err != nil {
        sc.logger.Error("scan failed", "error", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
        return
    }

    c.JSON(http.StatusOK, result)
}
```

## 📊 Event-Driven Architecture

### 1. Event System
```go
// Domain events
type Event interface {
    Type() string
    Timestamp() time.Time
    AggregateID() string
}

type ScanStartedEvent struct {
    ScanID    string
    Targets   []string
    StartTime time.Time
}

type ScanCompletedEvent struct {
    ScanID      string
    Results     []ScanResult
    CompletedAt time.Time
}

// Event dispatcher
type EventDispatcher interface {
    Dispatch(ctx context.Context, event Event) error
    Subscribe(eventType string, handler EventHandler) error
}
```

### 2. Message Flow
```
HTTP Request → Use Case → Domain Service → Event → Message Queue → External Service
```

### 3. RabbitMQ Manual Acknowledgment Pattern (Current Implementation)

**Message Lifecycle Flow:**
```
RabbitMQ Queue → Consumer (auto_ack=false) → HTTP Handler → Scan Execution
                                                                    ↓
                                                          Defer Function
                                                                    ↓
                                                    ┌───────────────┴───────────────┐
                                                    ↓                               ↓
                                            Scan Completed?                   Panic/Crash?
                                                    ↓                               ↓
                                    YES: ACK (remove from queue)      NACK with requeue
                                    NO:  NACK with requeue
```

**Implementation Pattern:**
```go
// In orchestrator8/orchestrator8.go
func (o *Orchestrator8) AckScanCompletion(deliveryTag uint64, scanCompleted bool) error {
    return amqpM8.WithPooledConnection(func(conn amqpM8.PooledAmqpInterface) error {
        ch := conn.GetChannel()
        if ch == nil {
            return fmt.Errorf("channel is nil, cannot acknowledge message")
        }

        if !scanCompleted {
            // Scan didn't complete - NACK and requeue for retry
            log8.BaseLogger.Warn().Msgf("Scan incomplete (deliveryTag: %d) - sending NACK with requeue", deliveryTag)
            return ch.Nack(deliveryTag, false, true) // requeue=true
        }

        // Scan completed successfully - ACK
        log8.BaseLogger.Info().Msgf("Scan completed successfully (deliveryTag: %d) - sending ACK", deliveryTag)
        return ch.Ack(deliveryTag, false)
    })
}

// In controller8/controller8_naabum8.go
func (m *Controller8Naabum8) runNaabu8(fullscan bool, firstrun bool, deliveryTag uint64) {
    var scanCompleted bool = false
    var scanFailed bool = false

    if fullscan {
        defer func() {
            // Recover from panic if any
            if r := recover(); r != nil {
                log8.BaseLogger.Error().Msgf("PANIC recovered in NaabuM8 scans: %v", r)
                scanCompleted = false
                scanFailed = true
            }

            // Always ACK or NACK the message
            if deliveryTag > 0 {
                ackErr := m.Orch.AckScanCompletion(deliveryTag, scanCompleted)
                if ackErr != nil {
                    log8.BaseLogger.Error().Msgf("Failed to ACK/NACK message (deliveryTag: %d): %v", deliveryTag, ackErr)
                }
            }
        }()
    }

    // ... scan execution logic ...
    scanCompleted = true // Set to true when scan completes successfully
}
```

**Key Benefits:**
- **Reliability**: Messages are not lost if the service crashes during processing
- **Automatic Retry**: Failed scans are automatically requeued and retried
- **Observability**: Delivery tags logged for tracking message lifecycle
- **At-Least-Once Delivery**: Guarantees messages are processed at least once
- **Panic Safety**: Defer function ensures proper cleanup even on panic

**Configuration:**
```yaml
ORCHESTRATORM8:
  naabum8:
    Consumer:
      - "cptm8_naabum8_queue"
      - "cptm8_naabum8_consumer"
      - "false"  # auto_ack (default: false for manual ACK mode)
```

## 🔒 Error Handling Strategy

### 1. Structured Error Types
```go
// Domain errors
type DomainError struct {
    Code    string
    Message string
    Cause   error
}

func (e DomainError) Error() string {
    return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Error types
var (
    ErrHostnameNotFound = DomainError{Code: "HOSTNAME_NOT_FOUND", Message: "hostname not found"}
    ErrScanInProgress   = DomainError{Code: "SCAN_IN_PROGRESS", Message: "scan already in progress"}
)
```

### 2. Error Handling Middleware
```go
func ErrorHandlingMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()
        
        if len(c.Errors) > 0 {
            err := c.Errors[0]
            
            switch e := err.Err.(type) {
            case DomainError:
                c.JSON(http.StatusBadRequest, gin.H{
                    "error": e.Code,
                    "message": e.Message,
                })
            default:
                c.JSON(http.StatusInternalServerError, gin.H{
                    "error": "INTERNAL_ERROR",
                    "message": "internal server error",
                })
            }
        }
    }
}
```

## 🔄 Context Management

### 1. Context Propagation
```go
// Pass context through all layers
func (uc *ScanUseCase) StartScan(ctx context.Context, targets []string) (*ScanResult, error) {
    // Validate input
    if len(targets) == 0 {
        return nil, ErrNoTargets
    }
    
    // Create scan with context
    scan := domain.NewScan(targets)
    
    // Save to repository with context
    if err := uc.scanRepo.Save(ctx, scan); err != nil {
        return nil, fmt.Errorf("failed to save scan: %w", err)
    }
    
    // Start background scanning with context
    go uc.executeScan(ctx, scan)
    
    return &ScanResult{ID: scan.ID, Status: "started"}, nil
}
```

### 2. Graceful Shutdown
```go
func (app *Application) Run(ctx context.Context) error {
    // Create cancellable context
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()
    
    // Start services
    g, ctx := errgroup.WithContext(ctx)
    
    g.Go(func() error {
        return app.httpServer.ListenAndServe()
    })
    
    g.Go(func() error {
        return app.messageConsumer.Start(ctx)
    })
    
    // Wait for shutdown signal
    g.Go(func() error {
        <-ctx.Done()
        return app.shutdown()
    })
    
    return g.Wait()
}
```

## 📈 Monitoring and Observability

### 1. Metrics Collection
```go
// Metrics interface
type Metrics interface {
    IncrementCounter(name string, labels map[string]string)
    RecordDuration(name string, duration time.Duration, labels map[string]string)
    SetGauge(name string, value float64, labels map[string]string)
}

// Middleware for metrics
func MetricsMiddleware(metrics Metrics) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        
        c.Next()
        
        duration := time.Since(start)
        status := c.Writer.Status()
        
        metrics.RecordDuration("http_request_duration", duration, map[string]string{
            "method": c.Request.Method,
            "path":   c.FullPath(),
            "status": strconv.Itoa(status),
        })
    }
}
```

### 2. Distributed Tracing
```go
// Add tracing to use cases
func (uc *ScanUseCase) StartScan(ctx context.Context, targets []string) (*ScanResult, error) {
    span, ctx := opentracing.StartSpanFromContext(ctx, "scan_usecase.start_scan")
    defer span.Finish()
    
    span.SetTag("targets_count", len(targets))
    
    // ... business logic
    
    return result, nil
}
```

## 🎯 Migration Strategy

### Phase 1: Dependency Injection
1. Create service container
2. Refactor controllers to use injection
3. Add proper error handling

### Phase 2: Separation of Concerns
1. Extract business logic to use cases
2. Create domain models
3. Implement repository pattern

### Phase 3: Event-Driven Architecture
1. Add event system
2. Implement async processing
3. Add proper monitoring

### Phase 4: Production Readiness
1. Add comprehensive testing
2. Implement circuit breakers
3. Add performance monitoring

## ✅ Recent Improvements

### Completed Enhancements (2025-11)
1. **RabbitMQ Manual Acknowledgment Mode** (2025-11-12, commit bff6291)
   - **Reliable Message Processing**: Messages only acknowledged after scan completion
   - **Automatic Retry on Failure**: Failed scans trigger NACK with requeue
   - **Panic Protection**: Defer function ensures NACK even on panic/crash
   - **Delivery Tag Tracking**: Tags propagated via HTTP headers (`X-RabbitMQ-Delivery-Tag`)
   - **Implementation Details**:
     - `pkg/orchestrator8/orchestrator8.go`: New methods `AckScanCompletion()` and `NackScanMessage()`
     - `pkg/controller8/controller8_naabum8.go`: Delivery tag extraction and lifecycle management
     - `pkg/amqpM8/pooled_amqp.go`: Handler-level conditional ACK/NACK
     - Default `auto_ack` changed from `true` to `false`
   - **Benefits**:
     - No message loss during service crashes or panics
     - Automatic retry of failed scans
     - Better observability via delivery tag logging
     - Supports at-least-once delivery semantics

### Completed Enhancements (2025-01)
1. **Panic Recovery**: Added defer function to handle panics during scan operations
   - Location: Scan controllers
   - Prevents entire service crashes from individual scan failures

2. **Error Handling Improvements**: Fixed full scan flow to handle errors gracefully
   - Multiple commits addressing error propagation
   - Better error context for debugging

3. **Graceful Shutdown**: Implemented signal handling for clean service termination
   - Location: [cmd/launch.go:51-58](../cmd/launch.go#L51-L58)
   - Handles SIGINT and SIGTERM signals
   - Cleanup of RabbitMQ connection pool on shutdown

4. **Connection Pool Management**: Advanced RabbitMQ connection pooling implemented
   - Location: `pkg/amqpM8/` (5 files)
   - Configurable pool parameters (max_connections, min_connections, idle times)
   - Shared state management for consistency
   - ⚠️ Still has blocking channel issue at line 289

5. **Temporary File Cleanup**: Automated cleanup of scan artifacts
   - Location: `pkg/cleanup8/`
   - Removes files older than specified duration (default: 24 hours)
   - Runs on service startup

6. **Health Probes**: Kubernetes-ready health and readiness endpoints
   - `/health` - Liveness probe
   - `/ready` - Readiness probe
   - Location: [pkg/api8/api8.go:101-102](../pkg/api8/api8.go#L101-L102)

## 📊 Current Architecture Metrics

### Code Organization
- **Total Packages**: 13 in `pkg/`, 1 in `cmd/`
- **Total Go Files**: 42 in `pkg/`, 3 in `cmd/`
- **Interface Coverage**: High (all data access layers use interfaces)
- **Test Coverage**: 0% (no tests exist yet)

### External Dependencies
- **Core Dependencies**: 6 (Gin, Cobra, Viper, Naabu, HTTPx, RabbitMQ client)
- **Utility Dependencies**: 5 (zerolog, lumberjack, discordgo, uuid, pq)
- **Total Direct Dependencies**: 11 major libraries

### Configuration Complexity
- **Config Sections**: 6 (APP_ENV, LOG_LEVEL, NAABUM8, ORCHESTRATORM8, Database, RabbitMQ, Discord)
- **Environment Variables**: 8+ supported
- **Hot-Reload**: Yes (Viper watch enabled)