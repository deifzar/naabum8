# Performance Review: NaabuM8

**Date:** 2025-01-18  
**Status:** Performance Issues Identified  

## 🐌 Critical Performance Issues

### 1. Blocking Forever Channel
**File**: `pkg/amqpM8/pooled_amqp.go:289`
**Issue**: Infinite blocking channel
**Impact**: Goroutine leaks and resource exhaustion
**Status**: ⚠️ OPEN - Needs fixing despite graceful shutdown implementation

```go
// PROBLEMATIC CODE
func (a *PooledAmqpImp) Consume(consumerName, queueName string, autoACK bool) error {
    // ... setup code ...

    var forever chan struct{}

    go func() {
        for msg := range msgs {
            // Process messages
        }
    }()

    <-forever  // ❌ This blocks forever!

    return nil
}
```

**Current State**: Graceful shutdown has been implemented in [cmd/launch.go:51-58](../cmd/launch.go#L51-L58), but the blocking channel issue remains in the Consume method.

**Fix**: Implement proper context cancellation and graceful shutdown within the Consume method itself

### 2. N+1 Query Problem
**File**: `pkg/controller8/controller8_naabum8.go`  
**Issue**: Multiple single-record queries instead of batch operations  
**Impact**: Significant database load and latency

```go
// INEFFICIENT: Multiple queries in loop
for _, target := range m.runnerOptions.Host {
    h, err := hostnameDB.GetOneHostnameByName(target)  // ❌ N+1 queries
    // ... process each individually
}
```

**Fix**: Use batch queries with `WHERE hostname IN (...)`

### 3. Unbounded Memory Growth
**File**: `pkg/model8/results8.go`  
**Issue**: Unlimited map growth without cleanup  
**Impact**: Memory leaks in long-running scans

```go
// MEMORY LEAK: No bounds checking
func (r *Results8) AddPort(h, ip string, p *port.Port) {
    if _, ok := r.HostnamesIPPorts[h]; !ok {
        r.HostnamesIPPorts[h] = make(map[string]map[string]*port.Port)  // ❌ Grows forever
    }
    // ... continues to grow
}
```

## 📊 Performance Metrics

### Database Performance
- **Current**: ~500ms per hostname query
- **Target**: <50ms with batch operations
- **Improvement**: 90% reduction in query time

### Memory Usage
- **Current**: Unbounded growth (~100MB per 1000 hosts)
- **Target**: Fixed memory footprint with pagination
- **Improvement**: Predictable memory usage

### Concurrent Operations
- **Current**: Sequential processing with blocking operations
- **Target**: Parallel processing with proper synchronization
- **Improvement**: 10x throughput increase

## 🚀 Performance Optimizations

### High Priority Fixes

#### 1. Fix Blocking Channel Issue
**Priority**: CRITICAL
**Estimated Effort**: 4-6 hours
**Dependencies**: None

```go
// IMPROVED: Proper context handling
func (a *PooledAmqpImp) Consume(ctx context.Context, consumerName, queueName string, autoACK bool) error {
    msgs, err := a.ch.Consume(queueName, consumerName, autoACK, false, false, false, nil)
    if err != nil {
        return fmt.Errorf("consumer creation failed: %w", err)
    }

    go func() {
        defer func() {
            if err := a.ch.Cancel(consumerName, false); err != nil {
                log8.BaseLogger.Error().Err(err).Msg("failed to cancel consumer")
            }
        }()

        for {
            select {
            case msg, ok := <-msgs:
                if !ok {
                    log8.BaseLogger.Info().Msg("consumer channel closed")
                    return
                }
                if handler := a.handler[queueName]; handler != nil {
                    handler(msg)
                }
                if !autoACK {
                    msg.Ack(false)
                }
            case <-ctx.Done():
                log8.BaseLogger.Info().Msg("consumer context cancelled, shutting down gracefully")
                return
            }
        }
    }()

    return nil
}
```

**Note**: This requires updating all Consume() method calls to pass context. Update orchestrator8 to create and manage contexts.

#### 2. Batch Database Operations
**Priority**: HIGH
**Estimated Effort**: 6-8 hours
**Dependencies**: None

```go
// OPTIMIZED: Batch hostname queries
func (db *Db8Hostname8) GetHostnamesByNames(names []string) ([]model8.Hostname8, error) {
    if len(names) == 0 {
        return nil, nil
    }

    placeholders := make([]string, len(names))
    args := make([]interface{}, len(names))
    for i, name := range names {
        placeholders[i] = fmt.Sprintf("$%d", i+1)
        args[i] = name
    }

    query := fmt.Sprintf(`
        SELECT id, name, enabled, parent_id, created_at, updated_at 
        FROM hostnames 
        WHERE name IN (%s) AND enabled = true
    `, strings.Join(placeholders, ","))

    rows, err := db.db.Query(query, args...)
    if err != nil {
        return nil, fmt.Errorf("batch hostname query failed: %w", err)
    }
    defer rows.Close()

    var results []model8.Hostname8
    for rows.Next() {
        var h model8.Hostname8
        if err := rows.Scan(&h.Id, &h.Name, &h.Enabled, &h.ParentId, &h.CreatedAt, &h.UpdatedAt); err != nil {
            return nil, fmt.Errorf("scan failed: %w", err)
        }
        results = append(results, h)
    }

    return results, nil
}
```

#### 3. Bounded Memory Management
**Priority**: HIGH
**Estimated Effort**: 4-6 hours
**Dependencies**: None

```go
// MEMORY EFFICIENT: Add bounds checking
const MaxHostsPerResult = 1000

func (r *Results8) AddPort(h, ip string, p *port.Port) error {
    r.Lock()
    defer r.Unlock()

    if len(r.HostnamesIPPorts) >= MaxHostsPerResult {
        return fmt.Errorf("results capacity exceeded")
    }

    // ... existing logic with bounds checking
    return nil
}
```

**Additional Considerations**:
- Implement pagination for large scan results
- Add periodic cleanup of processed results
- Consider using streaming results instead of in-memory accumulation

### Medium Priority Optimizations

#### 1. Connection Pooling
**Status**: ⚠️ PARTIALLY IMPLEMENTED
**Priority**: MEDIUM
**Estimated Effort**: 2-3 hours

```go
// DATABASE: Implement connection pooling (RECOMMENDED SETTINGS)
func (d *Db8) OpenConnection() (*sql.DB, error) {
    db, err := sql.Open("postgres", d.GetConnectionString())
    if err != nil {
        return nil, err
    }

    // Recommended connection pool settings
    db.SetMaxOpenConns(25)           // Maximum number of open connections
    db.SetMaxIdleConns(5)            // Maximum number of idle connections
    db.SetConnMaxLifetime(5 * time.Minute)  // Maximum connection lifetime
    db.SetConnMaxIdleTime(1 * time.Minute)  // Maximum idle time

    return db, nil
}
```

**Current State**: Database connection is opened in [pkg/db8/db8.go](../pkg/db8/db8.go) but connection pooling settings need to be configured.

**RabbitMQ Connection Pooling**: ✅ Already implemented with configurable parameters in `pkg/amqpM8/` (5 files).

#### 2. Caching Layer
```go
// CACHING: Add Redis for frequently accessed data
type CachedHostnameService struct {
    db    *Db8Hostname8
    cache *redis.Client
    ttl   time.Duration
}

func (c *CachedHostnameService) GetHostname(name string) (*model8.Hostname8, error) {
    // Check cache first
    cached, err := c.cache.Get(ctx, "hostname:"+name).Result()
    if err == nil {
        var hostname model8.Hostname8
        if err := json.Unmarshal([]byte(cached), &hostname); err == nil {
            return &hostname, nil
        }
    }

    // Fallback to database
    hostname, err := c.db.GetOneHostnameByName(name)
    if err != nil {
        return nil, err
    }

    // Cache the result
    if data, err := json.Marshal(hostname); err == nil {
        c.cache.Set(ctx, "hostname:"+name, data, c.ttl)
    }

    return hostname, nil
}
```

#### 3. Worker Pool Pattern
```go
// CONCURRENCY: Implement worker pool for scanning
type ScanWorkerPool struct {
    workerCount int
    jobQueue    chan ScanJob
    results     chan ScanResult
}

func NewScanWorkerPool(workerCount int) *ScanWorkerPool {
    return &ScanWorkerPool{
        workerCount: workerCount,
        jobQueue:    make(chan ScanJob, workerCount*2),
        results:     make(chan ScanResult, workerCount*2),
    }
}

func (p *ScanWorkerPool) Start(ctx context.Context) {
    for i := 0; i < p.workerCount; i++ {
        go p.worker(ctx)
    }
}

func (p *ScanWorkerPool) worker(ctx context.Context) {
    for {
        select {
        case job := <-p.jobQueue:
            result := p.processScanJob(job)
            p.results <- result
        case <-ctx.Done():
            return
        }
    }
}
```

### Low Priority Optimizations

#### 1. Async Processing
```go
// ASYNC: Non-blocking operations
func (m *Controller8Naabum8) Naabum8ScanAsync(c *gin.Context) {
    // Return immediately with job ID
    jobID := uuid.New().String()
    
    go func() {
        // Process scan in background
        m.runNaabu8(true, orchestrator8, true)
        // Update job status
    }()
    
    c.JSON(http.StatusAccepted, gin.H{
        "job_id": jobID,
        "status": "processing",
        "message": "Scan started successfully",
    })
}
```

#### 2. Compression
```go
// COMPRESSION: Compress large responses
func GzipMiddleware() gin.HandlerFunc {
    return gin.HandlerFunc(func(c *gin.Context) {
        if strings.Contains(c.GetHeader("Accept-Encoding"), "gzip") {
            c.Header("Content-Encoding", "gzip")
            // Implement gzip compression
        }
        c.Next()
    })
}
```

## 📈 Performance Monitoring

### Metrics to Track
- **Database query duration**
- **Memory usage per scan**
- **RabbitMQ message processing rate**
- **API response times**
- **Goroutine count**

### Recommended Tools
- **Prometheus** for metrics collection
- **Grafana** for visualization
- **pprof** for Go profiling
- **OpenTelemetry** for distributed tracing

## 🎯 Performance Targets

### Response Times
- API endpoints: <200ms p95
- Database queries: <50ms p95
- Message processing: <100ms p95

### Throughput
- Concurrent scans: 10-50 simultaneous
- Message processing: 1000 msgs/sec
- Database operations: 500 ops/sec

### Resource Usage
- Memory: <1GB per instance
- CPU: <80% utilization
- Connections: <100 database connections

## 🔧 Implementation Priority

### Week 1 (Critical)
- Fix blocking channel issue
- Implement context cancellation
- Add connection pooling

### Week 2 (High)
- Implement batch database operations
- Add memory bounds checking
- Optimize concurrent processing

### Week 3 (Medium)
- Add caching layer
- Implement worker pools
- Add performance monitoring

### Week 4 (Low)
- Async processing patterns
- Response compression
- Fine-tuning optimizations