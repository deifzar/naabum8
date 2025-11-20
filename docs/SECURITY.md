# Security Audit & Best Practices

**Document Version:** 2.0
**Last Updated:** 2025-11-17
**Severity Levels:** 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ℹ️ Info

---

## Executive Summary

This document provides a comprehensive security audit of the NaabuM8 port scanning service. NaabuM8 is a distributed network reconnaissance tool that integrates with PostgreSQL, RabbitMQ, and external scanning tools (Naabu, Nmap, HTTPx). As a security-critical service with network scanning capabilities, proper security controls are essential.

### Overall Security Status

- **Current Status:** ⚠️ Pre-Production (Security hardening required)
- **Risk Level:** 🟠 High (Multiple security issues identified)
- **Production Ready:** ❌ No (Critical issues must be addressed)

### Key Findings Summary

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Authentication & Authorization | 2 | 1 | 0 | 0 |
| Configuration & Secrets | 1 | 2 | 1 | 0 |
| Network Security | 0 | 2 | 1 | 0 |
| Input Validation | 0 | 1 | 2 | 1 |
| Logging & Monitoring | 0 | 0 | 1 | 2 |
| **Total** | **3** | **6** | **5** | **3** |

---

## Table of Contents

1. [Critical Vulnerabilities](#critical-vulnerabilities)
2. [High Severity Issues](#high-severity-issues)
3. [Medium Severity Issues](#medium-severity-issues)
4. [Low Severity Issues](#low-severity-issues)
5. [Configuration Security](#configuration-security)
6. [Network Security](#network-security)
7. [Database Security](#database-security)
8. [API Security](#api-security)
9. [Secrets Management](#secrets-management)
10. [Remediation Roadmap](#remediation-roadmap)
11. [Security Checklist](#security-checklist)
12. [Responsible Disclosure](#responsible-disclosure)

---

## Critical Vulnerabilities

### 🔴 CRIT-01: No API Authentication

**Location:** `pkg/api8/api8.go:135-148`

**Description:**
All API endpoints are completely unauthenticated and publicly accessible. Anyone with network access can:
- Trigger port scans against any configured target
- Retrieve scan results
- Potentially abuse the service for malicious scanning

**Affected Endpoints:**
```go
r.GET("/scan", contrNaabum8.Naabum8Scan)           // ❌ No auth
r.POST("/scan", contrNaabum8.Naabum8Hostnames)     // ❌ No auth
r.GET("/scan/domain/:id", contrNaabum8.Naabum8Domain) // ❌ No auth
r.GET("/health", contrNaabum8.HealthCheck)         // ✅ OK (public)
r.GET("/ready", contrNaabum8.ReadinessCheck)       // ✅ OK (public)
```

**Impact:**
- Unauthorized users can trigger resource-intensive port scans
- Service can be abused for malicious network reconnaissance
- Potential for DoS attacks through scan flooding
- Legal liability for unauthorized network scanning

**CVSS Score:** 9.1 (Critical)
**CVE:** N/A (Not publicly disclosed)

**Remediation:**

**Option 1: API Key Authentication**
```go
// middleware/auth.go
func APIKeyAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        apiKey := c.GetHeader("X-API-Key")
        if apiKey == "" {
            c.JSON(401, gin.H{"error": "Missing API key"})
            c.Abort()
            return
        }

        validKeys := os.Getenv("API_KEYS") // Comma-separated list
        if !strings.Contains(validKeys, apiKey) {
            c.JSON(403, gin.H{"error": "Invalid API key"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// Apply to routes
protected := r.Group("/")
protected.Use(APIKeyAuth())
{
    protected.GET("/scan", contrNaabum8.Naabum8Scan)
    protected.POST("/scan", contrNaabum8.Naabum8Hostnames)
    protected.GET("/scan/domain/:id", contrNaabum8.Naabum8Domain)
}
```

**Option 2: JWT Authentication (Recommended for Production)**
```go
import "github.com/golang-jwt/jwt/v5"

func JWTAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        if tokenString == "" {
            c.JSON(401, gin.H{"error": "Missing token"})
            c.Abort()
            return
        }

        // Remove "Bearer " prefix
        tokenString = strings.TrimPrefix(tokenString, "Bearer ")

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("JWT_SECRET")), nil
        })

        if err != nil || !token.Valid {
            c.JSON(403, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Next()
    }
}
```

**Timeline:** Must be implemented before production deployment

---

### 🔴 CRIT-02: No Rate Limiting

**Location:** `pkg/api8/api8.go:135-148`

**Description:**
No rate limiting is implemented on any endpoint, allowing unlimited requests from a single source.

**Impact:**
- Service can be overwhelmed by request flooding
- Resource exhaustion (CPU, memory, database connections)
- RabbitMQ queue flooding
- Database connection pool exhaustion

**Attack Scenario:**
```bash
# Attacker can flood the service
while true; do
    curl -X POST http://target:8001/scan \
         -H "Content-Type: application/json" \
         -d '{"hostnames":["target1.com","target2.com"]}'
done
```

**Remediation:**

**Install rate limiting middleware:**
```bash
go get github.com/ulule/limiter/v3
go get github.com/ulule/limiter/v3/drivers/middleware/gin
```

**Implement rate limiting:**
```go
import (
    "github.com/ulule/limiter/v3"
    mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
    "github.com/ulule/limiter/v3/drivers/store/memory"
)

func setupRateLimiting(r *gin.Engine) {
    // Create rate limiter: 10 requests per minute per IP
    rate := limiter.Rate{
        Period: 1 * time.Minute,
        Limit:  10,
    }

    store := memory.NewStore()
    instance := limiter.New(store, rate)
    middleware := mgin.NewMiddleware(instance)

    // Apply to scan endpoints
    r.Use(middleware)
}
```

**Configuration:**
```yaml
API:
  rate_limit:
    enabled: true
    requests_per_minute: 10
    burst: 20
```

**Timeline:** Must be implemented before production deployment

---

### 🔴 CRIT-03: Database Credentials in Plain Connection String

**Location:** `pkg/db8/db8.go:53-56`

**Description:**
Database password is passed in plain text through connection string with `sslmode=disable`.

**Code:**
```go
func (d *Db8) GetConnectionString() string {
    return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable search_path=%s",
        d.location, d.port, d.username, d.password, d.database, d.schema)
}
```

**Issues:**
1. `sslmode=disable` - No encryption in transit
2. Password exposed in memory/logs if connection string is logged
3. No certificate validation

**Impact:**
- Credentials can be intercepted via network sniffing
- Man-in-the-middle attacks possible
- Password exposure in stack traces/error logs

**Remediation:**

**1. Enable SSL/TLS:**
```go
func (d *Db8) GetConnectionString() string {
    sslMode := os.Getenv("DB_SSL_MODE")
    if sslMode == "" {
        sslMode = "require" // Default to secure
    }

    connStr := fmt.Sprintf(
        "host=%s port=%d user=%s password=%s dbname=%s sslmode=%s search_path=%s",
        d.location, d.port, d.username, d.password, d.database, sslMode, d.schema,
    )

    // Add SSL certificate validation for production
    if sslMode == "verify-full" {
        certPath := os.Getenv("DB_SSL_CERT")
        if certPath != "" {
            connStr += fmt.Sprintf(" sslrootcert=%s", certPath)
        }
    }

    return connStr
}
```

**2. Environment variables:**
```bash
export DB_SSL_MODE="verify-full"  # Or "require" minimum
export DB_SSL_CERT="/path/to/ca-certificate.crt"
```

**3. Configuration:**
```yaml
Database:
  location: "${POSTGRESQL_HOSTNAME}"
  port: 5432
  ssl_mode: "verify-full"  # require, verify-ca, verify-full
  ssl_cert: "${DB_SSL_CERT_PATH}"
  database: "${POSTGRESQL_DB}"
  username: "${POSTGRESQL_USERNAME}"
  password: "${POSTGRESQL_PASSWORD}"
```

**Timeline:** Critical - Must be fixed before production

---

## High Severity Issues

### 🟠 HIGH-01: No Input Validation on Domain/Hostname Parameters

**Location:** `pkg/controller8/controller8_naabum8.go`

**Description:**
User-supplied domain IDs and hostnames are not validated before use in database queries or scan operations.

**Vulnerable Code:**
```go
// GET /scan/domain/:id
func (m *Controller8Naabum8) Naabum8Domain(c *gin.Context) {
    id := c.Param("id")  // ❌ No validation
    domainUUID, err := uuid.FromString(id)  // Basic parsing only
    // ...
}
```

**Attack Vectors:**
1. **SQL Injection:** If UUID parsing fails and raw string is used
2. **Path Traversal:** Malformed UUIDs could cause unexpected behavior
3. **DoS:** Invalid input causing repeated parsing errors

**Impact:**
- Potential for SQL injection (low probability but possible)
- Service disruption through malformed requests
- Error log flooding

**Remediation:**

**Add comprehensive input validation:**
```go
func validateUUID(uuidStr string) (uuid.UUID, error) {
    // Validate format first
    if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(uuidStr) {
        return uuid.Nil, errors.New("invalid UUID format")
    }

    return uuid.FromString(uuidStr)
}

func validateHostname(hostname string) error {
    // Validate hostname format (RFC 1123)
    if len(hostname) > 253 {
        return errors.New("hostname too long")
    }

    validHostname := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
    if !validHostname.MatchString(hostname) {
        return errors.New("invalid hostname format")
    }

    return nil
}

// Usage in controller
func (m *Controller8Naabum8) Naabum8Domain(c *gin.Context) {
    id := c.Param("id")

    domainUUID, err := validateUUID(id)
    if err != nil {
        log8.BaseLogger.Warn().Str("invalid_uuid", id).Msg("Invalid UUID provided")
        c.JSON(http.StatusBadRequest, gin.H{
            "status": "error",
            "msg": "Invalid domain ID format",
        })
        return
    }
    // ... continue with validated UUID
}
```

**Timeline:** High priority - Implement within 2 weeks

---

### 🟠 HIGH-02: RabbitMQ Connection String Contains Plain Text Password

**Location:** `pkg/amqpM8/initialization.go` (inferred from configuration usage)

**Description:**
Similar to the database issue, RabbitMQ credentials are handled without encryption.

**Current Configuration:**
```yaml
RabbitMQ:
  location: "${RABBITMQ_HOSTNAME}"
  port: 5672
  username: "${RABBITMQ_USERNAME}"
  password: "${RABBITMQ_PASSWORD}"  # Plain text in memory
```

**Impact:**
- Credentials exposed in memory dumps
- Network traffic can be intercepted (AMQP is plain text by default)
- Man-in-the-middle attacks

**Remediation:**

**1. Enable TLS for RabbitMQ:**
```go
import "crypto/tls"

func connectWithTLS(host, user, pass string) (*amqp.Connection, error) {
    tlsConfig := &tls.Config{
        InsecureSkipVerify: false,
        ServerName:         host,
    }

    connStr := fmt.Sprintf("amqps://%s:%s@%s:5671/", user, pass, host)
    return amqp.DialTLS(connStr, tlsConfig)
}
```

**2. Update configuration:**
```yaml
RabbitMQ:
  location: "${RABBITMQ_HOSTNAME}"
  port: 5671  # TLS port
  use_tls: true
  tls_verify: true
  ca_cert: "${RABBITMQ_CA_CERT}"
  username: "${RABBITMQ_USERNAME}"
  password: "${RABBITMQ_PASSWORD}"
```

**Timeline:** High priority - Implement before production

---

### 🟠 HIGH-03: Nmap Command Injection Vulnerability

**Location:** `configs/configuration_template.yaml:73`

**Description:**
Nmap CLI command is configured via YAML and executed via shell, potentially allowing command injection if user input reaches this configuration.

**Current Configuration:**
```yaml
NmapCLI: 'nmap -sV -oX ./tmp/nmap-output.xml'
```

**Risk:**
If an attacker can influence the NmapCLI configuration or any parameters passed to it, they could inject additional shell commands.

**Attack Scenario:**
```yaml
# Malicious configuration
NmapCLI: 'nmap -sV -oX ./tmp/nmap-output.xml; rm -rf /'
```

**Remediation:**

**1. Use parameterized execution (not shell):**
```go
import "os/exec"

func runNmap(host string, ports []int) error {
    // Build arguments safely
    args := []string{
        "-sV",
        "-p", formatPorts(ports),
        "-oX", "/tmp/nmap-output.xml",
        host,
    }

    // Execute without shell
    cmd := exec.Command("nmap", args...)

    // Sanitize hostname
    if !isValidHostname(host) {
        return errors.New("invalid hostname")
    }

    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("nmap failed: %w", err)
    }

    return nil
}

func isValidHostname(host string) bool {
    // Only allow alphanumeric, dots, hyphens
    validPattern := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
    return validPattern.MatchString(host)
}
```

**2. Restrict Nmap options:**
```go
// Allowed Nmap flags (whitelist)
var allowedNmapFlags = map[string]bool{
    "-sV": true,  // Version detection
    "-sS": true,  // SYN scan
    "-sT": true,  // TCP connect scan
    "-p":  true,  // Port specification
    "-oX": true,  // XML output
}
```

**Timeline:** High priority - Implement within 1 week

---

### 🟠 HIGH-04: Excessive Logging May Expose Sensitive Data

**Location:** Throughout codebase, especially `pkg/log8/log8.go`

**Description:**
Debug logging may inadvertently log sensitive information like connection strings, API responses, or internal system details.

**Example Issues:**
```go
log8.BaseLogger.Debug().Msgf("Database connection: %s", connectionString)  // ❌ May contain password
log8.BaseLogger.Debug().Msgf("Config: %+v", config)  // ❌ May contain secrets
```

**Impact:**
- Credentials exposed in log files
- Internal architecture details leaked
- Compliance violations (GDPR, PCI-DSS)

**Remediation:**

**1. Implement log sanitization:**
```go
func sanitizeLogData(data string) string {
    // Remove passwords from connection strings
    data = regexp.MustCompile(`password=[^ ]+`).ReplaceAllString(data, "password=***")

    // Remove API keys
    data = regexp.MustCompile(`(api[_-]?key|token|secret)=([^ ]+)`).ReplaceAllString(data, "$1=***")

    return data
}

// Usage
log8.BaseLogger.Debug().Msg(sanitizeLogData(fmt.Sprintf("Connection: %s", connStr)))
```

**2. Structured logging with field filtering:**
```go
type SafeLogger struct {
    *zerolog.Logger
}

func (sl *SafeLogger) SafeFields(fields map[string]interface{}) *zerolog.Event {
    sensitiveKeys := []string{"password", "token", "secret", "api_key"}

    safeFields := make(map[string]interface{})
    for k, v := range fields {
        if contains(sensitiveKeys, strings.ToLower(k)) {
            safeFields[k] = "***"
        } else {
            safeFields[k] = v
        }
    }

    event := sl.Logger.Log()
    for k, v := range safeFields {
        event = event.Interface(k, v)
    }

    return event
}
```

**3. Disable debug logging in production:**
```yaml
APP_ENV: PROD
LOG_LEVEL: "1"  # Info level (not Debug)
```

**Timeline:** Medium priority - Implement within 3 weeks

---

### 🟠 HIGH-05: Fatal Errors Crash Entire Service

**Location:** Multiple locations, e.g., `pkg/controller8/controller8_naabum8.go:40`

**Description:**
Use of `log8.BaseLogger.Fatal()` causes the entire service to terminate on errors that could be handled gracefully.

**Problematic Code:**
```go
if err != nil {
    log8.BaseLogger.Fatal().Msg("Error initializing orchestrator8")  // ❌ Terminates process
}
```

**Impact:**
- Single error brings down entire service
- Affects all active scans and connections
- Poor availability and resilience

**Remediation:**

**Replace Fatal() with proper error handling:**
```go
func NewController8Naabum8(db *sql.DB, cnfg *viper.Viper) (Controller8Naabum8Interface, error) {
    orch, err := orchestrator8.NewOrchestrator8()
    if err != nil {
        log8.BaseLogger.Error().Err(err).Msg("Failed to initialize orchestrator8")
        return nil, fmt.Errorf("orchestrator initialization failed: %w", err)
    }
    return &Controller8Naabum8{Db: db, Config: cnfg, Orch: orch}, nil
}

// Caller handles the error
controller, err := NewController8Naabum8(db, config)
if err != nil {
    log8.BaseLogger.Error().Err(err).Msg("Controller initialization failed")
    // Implement retry logic or graceful degradation
    return err
}
```

**Timeline:** Medium priority - Refactor within 3-4 weeks

---

### 🟠 HIGH-06: No Request Timeout Configuration

**Location:** `pkg/api8/api8.go:79-104`

**Description:**
HTTP client used to poll `/health` endpoint has no timeout, potentially causing goroutine leaks.

**Vulnerable Code:**
```go
resp, err := http.Get(requestURL)  // ❌ No timeout
```

**Impact:**
- Goroutines may hang indefinitely
- Resource exhaustion over time
- Service degradation

**Remediation:**

**Add HTTP client timeouts:**
```go
func (a *Api8) InitializeConsumerAfterReady() {
    go func() {
        client := &http.Client{
            Timeout: 5 * time.Second,
        }

        requestURL := "http://localhost:8001/health"
        maxRetries := 60
        retryCount := 0

        for retryCount < maxRetries {
            req, err := http.NewRequest("GET", requestURL, nil)
            if err != nil {
                log8.BaseLogger.Error().Err(err).Msg("Failed to create health check request")
                return
            }

            // Set request timeout context
            ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
            req = req.WithContext(ctx)

            resp, err := client.Do(req)
            cancel() // Always cancel context

            if err == nil && resp.StatusCode == http.StatusOK {
                resp.Body.Close()
                log8.BaseLogger.Info().Msg("API service is ready")
                break
            }

            if resp != nil {
                resp.Body.Close()
            }

            retryCount++
            time.Sleep(5 * time.Second)
        }

        // ... continue with initialization
    }()
}
```

**Timeline:** Medium priority - Implement within 2 weeks

---

## Medium Severity Issues

### 🟡 MED-01: Directory Creation with Permissive Permissions

**Location:** `pkg/api8/api8.go:29-40`

**Description:**
Directories are created with `0750` permissions, which is acceptable, but should be explicitly documented and potentially restricted further.

**Current Code:**
```go
if err := os.MkdirAll("configs", 0750); err != nil {  // rwxr-x---
    return err
}
```

**Recommendation:**
- `configs/`: 0750 is appropriate (owner read/write/execute, group read/execute)
- `log/`: Consider 0700 (owner only) for sensitive logs
- `tmp/`: 0750 is acceptable

**Remediation:**
```go
// Define directory permissions as constants
const (
    ConfigDirPerms = 0750  // rwxr-x---
    LogDirPerms    = 0700  // rwx------
    TmpDirPerms    = 0750  // rwxr-x---
)

if err := os.MkdirAll("configs", ConfigDirPerms); err != nil {
    return err
}
if err := os.MkdirAll("log", LogDirPerms); err != nil {
    return err
}
if err := os.MkdirAll("tmp", TmpDirPerms); err != nil {
    return err
}
```

**Timeline:** Low priority - Document and review

---

### 🟡 MED-02: No CORS Configuration

**Location:** `pkg/api8/api8.go:135-148`

**Description:**
No CORS (Cross-Origin Resource Sharing) headers are configured, potentially allowing unauthorized cross-origin requests.

**Impact:**
- Web-based attacks from malicious websites
- Potential for CSRF (Cross-Site Request Forgery)

**Remediation:**

**Add CORS middleware:**
```go
import "github.com/gin-contrib/cors"

func (a *Api8) Routes() {
    r := gin.Default()

    // Configure CORS
    config := cors.Config{
        AllowOrigins:     []string{os.Getenv("ALLOWED_ORIGINS")},  // Specify allowed domains
        AllowMethods:     []string{"GET", "POST"},
        AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-API-Key"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
        MaxAge:           12 * time.Hour,
    }

    r.Use(cors.New(config))

    // ... routes
}
```

**Configuration:**
```bash
export ALLOWED_ORIGINS="https://your-frontend.com,https://your-admin.com"
```

**Timeline:** Medium priority - Implement within 3 weeks

---

### 🟡 MED-03: Temporary File Cleanup Failures Not Tracked

**Location:** `pkg/cleanup8/cleanup8.go`, `pkg/api8/api8.go:43-46`

**Description:**
Cleanup failures are logged but not tracked, potentially leading to disk space exhaustion over time.

**Current Handling:**
```go
if err := cleanup.CleanupDirectory("tmp", 24*time.Hour); err != nil {
    log8.BaseLogger.Error().Err(err).Msg("Failed to cleanup tmp directory")
    // Don't return error here as cleanup failure shouldn't prevent startup
}
```

**Recommendation:**
- Implement monitoring for cleanup failures
- Alert when tmp directory exceeds threshold
- Automatic retry mechanism

**Remediation:**
```go
type CleanupMonitor struct {
    failureCount    int
    lastFailureTime time.Time
    mu              sync.Mutex
}

func (cm *CleanupMonitor) RecordFailure() {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    cm.failureCount++
    cm.lastFailureTime = time.Now()

    if cm.failureCount > 10 {
        log8.BaseLogger.Warn().
            Int("failure_count", cm.failureCount).
            Msg("Excessive cleanup failures - manual intervention may be required")
        // Send alert to monitoring system
    }
}

func (cm *CleanupMonitor) CheckDiskSpace(path string, thresholdMB int64) error {
    var stat syscall.Statfs_t
    syscall.Statfs(path, &stat)

    availableMB := stat.Bavail * uint64(stat.Bsize) / 1024 / 1024

    if availableMB < uint64(thresholdMB) {
        return fmt.Errorf("low disk space: %d MB available", availableMB)
    }

    return nil
}
```

**Timeline:** Low priority - Implement within 4 weeks

---

### 🟡 MED-04: No Health Check for RabbitMQ Connection

**Location:** `pkg/api8/api8.go:144-145`

**Description:**
The `/ready` endpoint exists but doesn't verify RabbitMQ connectivity, only API availability.

**Current Implementation:**
```go
r.GET("/ready", contrNaabum8.ReadinessCheck)  // Doesn't check RabbitMQ
```

**Impact:**
- Kubernetes may route traffic to unhealthy pods
- Service appears "ready" but cannot process messages

**Remediation:**

**Implement comprehensive readiness check:**
```go
func (m *Controller8Naabum8) ReadinessCheck(c *gin.Context) {
    checks := make(map[string]string)
    allHealthy := true

    // Check database
    if err := m.Db.Ping(); err != nil {
        checks["database"] = "unhealthy"
        allHealthy = false
    } else {
        checks["database"] = "healthy"
    }

    // Check RabbitMQ
    if err := m.Orch.HealthCheck(); err != nil {
        checks["rabbitmq"] = "unhealthy"
        allHealthy = false
    } else {
        checks["rabbitmq"] = "healthy"
    }

    status := "ready"
    statusCode := http.StatusOK
    if !allHealthy {
        status = "not ready"
        statusCode = http.StatusServiceUnavailable
    }

    c.JSON(statusCode, gin.H{
        "status": status,
        "checks": checks,
        "timestamp": time.Now().UTC(),
    })
}
```

**Timeline:** Medium priority - Implement within 2 weeks

---

### 🟡 MED-05: Error Messages Expose Internal Details

**Location:** Throughout codebase, especially controllers

**Description:**
Detailed error messages are returned to clients, exposing internal implementation details.

**Example:**
```go
c.JSON(http.StatusInternalServerError, gin.H{
    "status": "error",
    "msg": "Naabum8 scan failed - Something wrong fetching the hostnames in scope.",
    "error": err.Error(),  // ❌ Internal error details
})
```

**Impact:**
- Information disclosure
- Assists attackers in reconnaissance
- May expose database schema, file paths, etc.

**Remediation:**

**Implement generic error responses:**
```go
type ErrorResponse struct {
    Status    string `json:"status"`
    Message   string `json:"message"`
    ErrorCode string `json:"error_code"`
    RequestID string `json:"request_id"`
}

func newErrorResponse(c *gin.Context, code string, userMsg string, internalErr error) ErrorResponse {
    requestID := c.GetHeader("X-Request-ID")
    if requestID == "" {
        requestID = uuid.Must(uuid.NewV4()).String()
    }

    // Log detailed error internally
    log8.BaseLogger.Error().
        Err(internalErr).
        Str("request_id", requestID).
        Str("error_code", code).
        Msg("Request failed")

    // Return generic message to client
    return ErrorResponse{
        Status:    "error",
        Message:   userMsg,
        ErrorCode: code,
        RequestID: requestID,
    }
}

// Usage
if err != nil {
    response := newErrorResponse(c, "DB_QUERY_FAILED",
        "Unable to retrieve scan targets", err)
    c.JSON(http.StatusInternalServerError, response)
    return
}
```

**Timeline:** Medium priority - Implement within 3 weeks

---

## Low Severity Issues

### 🔵 LOW-01: No Security Headers in HTTP Responses

**Location:** `pkg/api8/api8.go`

**Description:**
Missing security headers make the API more vulnerable to certain web-based attacks.

**Remediation:**

**Add security headers middleware:**
```go
func SecurityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Header("Content-Security-Policy", "default-src 'self'")
        c.Header("Referrer-Policy", "no-referrer")
        c.Next()
    }
}

// Apply globally
r.Use(SecurityHeaders())
```

**Timeline:** Low priority - Implement within 4 weeks

---

### 🔵 LOW-02: No Request ID Tracking

**Location:** All API endpoints

**Description:**
Requests lack unique identifiers, making troubleshooting and audit logging difficult.

**Remediation:**

**Add request ID middleware:**
```go
func RequestID() gin.HandlerFunc {
    return func(c *gin.Context) {
        requestID := c.GetHeader("X-Request-ID")
        if requestID == "" {
            requestID = uuid.Must(uuid.NewV4()).String()
        }

        c.Set("request_id", requestID)
        c.Header("X-Request-ID", requestID)

        log8.BaseLogger.UpdateContext(func(ctx zerolog.Context) zerolog.Context {
            return ctx.Str("request_id", requestID)
        })

        c.Next()
    }
}

r.Use(RequestID())
```

**Timeline:** Low priority - Implement within 4 weeks

---

### 🔵 LOW-03: Gin Debug Mode in Production

**Location:** `pkg/api8/api8.go:136`

**Description:**
Gin runs in debug mode by default, which is verbose and exposes internal details.

**Current:**
```go
r := gin.Default()  // Runs in debug mode unless GIN_MODE=release
```

**Remediation:**

**Set production mode:**
```go
func (a *Api8) Routes() {
    // Set Gin mode based on environment
    if a.Cnfg.GetString("APP_ENV") == "PROD" {
        gin.SetMode(gin.ReleaseMode)
    }

    r := gin.Default()
    // ... routes
}
```

**Or via environment variable:**
```bash
export GIN_MODE=release
```

**Timeline:** Low priority - Quick fix (1 day)

---

## Configuration Security

### Best Practices for Configuration Management

#### 1. Environment Variable Usage

**✅ Good (Current Implementation):**
```yaml
Database:
  username: "${POSTGRESQL_USERNAME}"
  password: "${POSTGRESQL_PASSWORD}"
```

**❌ Bad (Never Do This):**
```yaml
Database:
  username: "postgres"
  password: "mysecretpassword123"
```

#### 2. Configuration File Permissions

**Secure file permissions:**
```bash
# Configuration files
chmod 640 configs/configuration.yaml
chown naabum8:naabum8 configs/configuration.yaml

# Ensure root owns directory
chown root:root configs/
chmod 755 configs/
```

#### 3. Configuration Validation

**Implement configuration validation on startup:**
```go
func validateConfig(v *viper.Viper) error {
    // Check required environment variables
    required := []string{
        "Database.location",
        "Database.database",
        "Database.username",
        "Database.password",
        "RabbitMQ.location",
        "RabbitMQ.username",
        "RabbitMQ.password",
    }

    for _, key := range required {
        if v.GetString(key) == "" {
            return fmt.Errorf("required configuration missing: %s", key)
        }
    }

    // Validate that placeholders were replaced
    if strings.Contains(v.GetString("Database.password"), "${") {
        return errors.New("environment variables not properly substituted")
    }

    return nil
}
```

---

## Network Security

### External Scanning Tool Security

**Naabu Security Considerations:**

1. **Restrict Scan Types:**
```yaml
NAABUM8:
  ScanType: s  # Only SYN scans (requires root/CAP_NET_RAW)
  # Avoid: "u" (UDP) - slower, noisier
```

2. **Rate Limiting:**
```yaml
NAABUM8:
  Rate: 1000  # Packets per second - adjust based on network capacity
  Threads: 25  # Concurrent scanning threads
```

3. **Timeout Configuration:**
```yaml
NAABUM8:
  Timeout: 1000      # Connection timeout (ms)
  Retries: 1         # Retry count
  WarmUpTime: 2      # Initial warm-up time (seconds)
```

### Network Segmentation Recommendations

**Production Deployment:**

```
┌─────────────────────────────────────────┐
│         External Network (Internet)      │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│     DMZ / API Gateway (with WAF)         │
│   - TLS Termination                      │
│   - Rate Limiting                        │
│   - Authentication                       │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│      Application Network (Private)       │
│   - NaabuM8 Service                      │
│   - No direct internet access            │
└────┬─────────────────────────┬──────────┘
     │                          │
┌────▼────────┐        ┌───────▼──────────┐
│  PostgreSQL │        │     RabbitMQ     │
│  (Private)  │        │    (Private)     │
└─────────────┘        └──────────────────┘
```

**Firewall Rules:**

```bash
# Allow only necessary connections
# NaabuM8 → PostgreSQL
iptables -A OUTPUT -p tcp -d <db_host> --dport 5432 -m state --state NEW,ESTABLISHED -j ACCEPT

# NaabuM8 → RabbitMQ
iptables -A OUTPUT -p tcp -d <rabbitmq_host> --dport 5671 -m state --state NEW,ESTABLISHED -j ACCEPT

# Block all other outbound connections
iptables -P OUTPUT DROP
```

---

## Database Security

### PostgreSQL Hardening Checklist

#### 1. Connection Security

**postgresql.conf:**
```conf
# Require SSL/TLS
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'
ssl_ca_file = '/path/to/root.crt'

# Require encrypted connections
ssl_min_protocol_version = 'TLSv1.2'
```

**pg_hba.conf:**
```conf
# Require SSL for naabum8 user
hostssl  naabum8_db  naabum8_user  10.0.0.0/8  md5
# Reject non-SSL connections
hostnossl  all  all  0.0.0.0/0  reject
```

#### 2. User Permissions

**Create dedicated database user:**
```sql
-- Create user with limited privileges
CREATE USER naabum8_user WITH PASSWORD 'strong_random_password';

-- Grant only necessary permissions
GRANT CONNECT ON DATABASE naabum8_db TO naabum8_user;
GRANT USAGE ON SCHEMA public TO naabum8_user;

-- Grant table-specific permissions
GRANT SELECT, INSERT, UPDATE ON TABLE domains TO naabum8_user;
GRANT SELECT, INSERT, UPDATE ON TABLE hostnames TO naabum8_user;
GRANT SELECT, INSERT, UPDATE ON TABLE services TO naabum8_user;
GRANT SELECT, INSERT, UPDATE ON TABLE endpoints TO naabum8_user;
GRANT SELECT, INSERT, UPDATE ON TABLE hostnameinfo TO naabum8_user;

-- DO NOT grant DELETE or TRUNCATE unless specifically needed
-- DO NOT grant CREATE or DROP
```

#### 3. Query Security

**Current Status:** ✅ Good - Application uses parameterized queries

**Example from codebase:**
```go
// ✅ Good - parameterized query
stmt, err := db.Prepare("SELECT * FROM hostnames WHERE domain_id = $1 AND enabled = $2")
if err != nil {
    return nil, err
}
defer stmt.Close()

rows, err := stmt.Query(domainID, true)
```

**❌ Never do this:**
```go
// SQL Injection vulnerable
query := fmt.Sprintf("SELECT * FROM hostnames WHERE domain_id = '%s'", userInput)
rows, err := db.Query(query)
```

#### 4. Audit Logging

**Enable PostgreSQL audit logging:**
```sql
-- Install pgaudit extension
CREATE EXTENSION pgaudit;

-- Configure audit logging
ALTER SYSTEM SET pgaudit.log = 'write, ddl';
ALTER SYSTEM SET pgaudit.log_catalog = off;
ALTER SYSTEM SET pgaudit.log_parameter = on;

-- Reload configuration
SELECT pg_reload_conf();
```

---

## API Security

### Endpoint Security Matrix

| Endpoint | Auth Required | Rate Limit | Input Validation | Output Sanitization |
|----------|---------------|------------|------------------|---------------------|
| `GET /scan` | ❌ Missing | ❌ Missing | N/A | ⚠️ Partial |
| `POST /scan` | ❌ Missing | ❌ Missing | ⚠️ Partial | ⚠️ Partial |
| `GET /scan/domain/:id` | ❌ Missing | ❌ Missing | ⚠️ Basic | ⚠️ Partial |
| `GET /health` | ✅ Public | ✅ Not needed | N/A | ✅ Safe |
| `GET /ready` | ✅ Public | ✅ Not needed | N/A | ✅ Safe |

### API Security Roadmap

**Phase 1 (Before Production):**
1. ✅ Implement API key or JWT authentication
2. ✅ Add rate limiting (10 req/min per IP)
3. ✅ Input validation for all parameters
4. ✅ Enable HTTPS/TLS
5. ✅ Add security headers

**Phase 2 (Production Hardening):**
1. Implement role-based access control (RBAC)
2. Add API request signing
3. Implement webhook authentication
4. Add IP whitelisting option
5. Implement audit logging

**Phase 3 (Advanced Security):**
1. Mutual TLS (mTLS) authentication
2. API versioning with deprecation notices
3. GraphQL alternative with query complexity limits
4. OAuth2/OpenID Connect integration

---

## Secrets Management

### Current State Analysis

**✅ Strengths:**
- Configuration uses environment variable substitution
- Template files don't contain actual secrets
- `.gitignore` includes configuration files

**❌ Weaknesses:**
- No secrets rotation mechanism
- No centralized secrets management
- Secrets stored as plain environment variables
- No secrets encryption at rest

### Recommended Solutions

#### Option 1: HashiCorp Vault (Enterprise-Grade)

**1. Install Vault:**
```bash
# Install Vault
wget https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip
unzip vault_1.15.0_linux_amd64.zip
sudo mv vault /usr/local/bin/
```

**2. Configure Vault:**
```hcl
# vault-config.hcl
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 0
  tls_cert_file = "/path/to/cert.pem"
  tls_key_file = "/path/to/key.pem"
}

api_addr = "https://vault.example.com:8200"
```

**3. Store secrets in Vault:**
```bash
# Initialize Vault
vault operator init

# Enable KV secrets engine
vault secrets enable -path=naabum8 kv-v2

# Store database credentials
vault kv put naabum8/database \
  username=naabum8_user \
  password=strong_random_password_123

# Store RabbitMQ credentials
vault kv put naabum8/rabbitmq \
  username=naabum8_mq_user \
  password=another_strong_password_456
```

**4. Modify application to fetch secrets:**
```go
import (
    "github.com/hashicorp/vault/api"
)

func getSecretFromVault(path string) (map[string]interface{}, error) {
    config := api.DefaultConfig()
    config.Address = os.Getenv("VAULT_ADDR")

    client, err := api.NewClient(config)
    if err != nil {
        return nil, err
    }

    // Authenticate using AppRole
    client.SetToken(os.Getenv("VAULT_TOKEN"))

    secret, err := client.Logical().Read(path)
    if err != nil {
        return nil, err
    }

    return secret.Data, nil
}

// Usage
func (d *Db8) InitDatabase8FromVault() error {
    secrets, err := getSecretFromVault("naabum8/database")
    if err != nil {
        return err
    }

    d.username = secrets["username"].(string)
    d.password = secrets["password"].(string)

    return nil
}
```

#### Option 2: Kubernetes Secrets (Kubernetes Deployments)

**1. Create Kubernetes secrets:**
```bash
# Create secret from literals
kubectl create secret generic naabum8-db-credentials \
  --from-literal=username=naabum8_user \
  --from-literal=password=strong_password_123

kubectl create secret generic naabum8-rabbitmq-credentials \
  --from-literal=username=naabum8_mq_user \
  --from-literal=password=mq_password_456
```

**2. Mount secrets in deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: naabum8
spec:
  template:
    spec:
      containers:
      - name: naabum8
        image: naabum8:latest
        env:
        - name: POSTGRESQL_USERNAME
          valueFrom:
            secretKeyRef:
              name: naabum8-db-credentials
              key: username
        - name: POSTGRESQL_PASSWORD
          valueFrom:
            secretKeyRef:
              name: naabum8-db-credentials
              key: password
        - name: RABBITMQ_USERNAME
          valueFrom:
            secretKeyRef:
              name: naabum8-rabbitmq-credentials
              key: username
        - name: RABBITMQ_PASSWORD
          valueFrom:
            secretKeyRef:
              name: naabum8-rabbitmq-credentials
              key: password
```

#### Option 3: AWS Secrets Manager (Cloud Deployments)

**1. Store secrets:**
```bash
aws secretsmanager create-secret \
  --name naabum8/database \
  --secret-string '{"username":"naabum8_user","password":"strong_password_123"}'

aws secretsmanager create-secret \
  --name naabum8/rabbitmq \
  --secret-string '{"username":"naabum8_mq_user","password":"mq_password_456"}'
```

**2. Fetch secrets in application:**
```go
import (
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/secretsmanager"
)

func getAWSSecret(secretName string) (map[string]interface{}, error) {
    sess := session.Must(session.NewSession())
    svc := secretsmanager.New(sess)

    input := &secretsmanager.GetSecretValueInput{
        SecretId: aws.String(secretName),
    }

    result, err := svc.GetSecretValue(input)
    if err != nil {
        return nil, err
    }

    var secretData map[string]interface{}
    json.Unmarshal([]byte(*result.SecretString), &secretData)

    return secretData, nil
}
```

### Secrets Rotation Strategy

**Automated rotation schedule:**

1. **Database passwords:** Rotate every 90 days
2. **RabbitMQ credentials:** Rotate every 90 days
3. **API keys:** Rotate every 180 days
4. **TLS certificates:** Rotate every 365 days (or before expiry)

**Rotation procedure:**
```bash
#!/bin/bash
# rotate-db-password.sh

# Generate new password
NEW_PASSWORD=$(openssl rand -base64 32)

# Update in PostgreSQL
psql -U postgres -c "ALTER USER naabum8_user WITH PASSWORD '$NEW_PASSWORD';"

# Update in secrets manager (choose one)
# Option 1: Vault
vault kv put naabum8/database username=naabum8_user password=$NEW_PASSWORD

# Option 2: Kubernetes
kubectl create secret generic naabum8-db-credentials \
  --from-literal=username=naabum8_user \
  --from-literal=password=$NEW_PASSWORD \
  --dry-run=client -o yaml | kubectl apply -f -

# Option 3: AWS Secrets Manager
aws secretsmanager update-secret \
  --secret-id naabum8/database \
  --secret-string "{\"username\":\"naabum8_user\",\"password\":\"$NEW_PASSWORD\"}"

# Restart application to pick up new password
kubectl rollout restart deployment/naabum8
```

---

## Remediation Roadmap

### Phase 1: Critical Security (Week 1-2) 🔴

**Must be completed before production deployment**

| Issue | Priority | Effort | Owner | Status |
|-------|----------|--------|-------|--------|
| CRIT-01: API Authentication | P0 | 3 days | Backend Team | ⏳ Pending |
| CRIT-02: Rate Limiting | P0 | 2 days | Backend Team | ⏳ Pending |
| CRIT-03: Database SSL/TLS | P0 | 2 days | DevOps Team | ⏳ Pending |

**Deliverables:**
- [ ] API key or JWT authentication implemented
- [ ] Rate limiting middleware active (10 req/min)
- [ ] PostgreSQL SSL enabled with certificate verification
- [ ] RabbitMQ TLS enabled
- [ ] Documentation updated with new authentication requirements

### Phase 2: High Security (Week 3-4) 🟠

**Should be completed before production deployment**

| Issue | Priority | Effort | Owner | Status |
|-------|----------|--------|-------|--------|
| HIGH-01: Input Validation | P1 | 3 days | Backend Team | ⏳ Pending |
| HIGH-02: RabbitMQ TLS | P1 | 2 days | DevOps Team | ⏳ Pending |
| HIGH-03: Nmap Injection | P1 | 3 days | Backend Team | ⏳ Pending |
| HIGH-04: Log Sanitization | P1 | 2 days | Backend Team | ⏳ Pending |
| HIGH-05: Fatal() Refactor | P1 | 5 days | Backend Team | ⏳ Pending |
| HIGH-06: HTTP Timeouts | P1 | 1 day | Backend Team | ⏳ Pending |

**Deliverables:**
- [ ] All user inputs validated with whitelist approach
- [ ] RabbitMQ connections use TLS
- [ ] Nmap execution uses parameterized commands
- [ ] Sensitive data removed from logs
- [ ] Fatal() replaced with error returns
- [ ] All HTTP clients have timeouts

### Phase 3: Medium Security (Week 5-6) 🟡

**Nice to have before production, required for long-term stability**

| Issue | Priority | Effort | Owner | Status |
|-------|----------|--------|-------|--------|
| MED-01: Directory Permissions | P2 | 1 day | DevOps Team | ⏳ Pending |
| MED-02: CORS Configuration | P2 | 1 day | Backend Team | ⏳ Pending |
| MED-03: Cleanup Monitoring | P2 | 2 days | Backend Team | ⏳ Pending |
| MED-04: Health Checks | P2 | 2 days | Backend Team | ⏳ Pending |
| MED-05: Error Sanitization | P2 | 3 days | Backend Team | ⏳ Pending |

**Deliverables:**
- [ ] Log directory restricted to owner-only (0700)
- [ ] CORS headers configured
- [ ] Cleanup monitoring and alerting active
- [ ] RabbitMQ health checks in /ready endpoint
- [ ] Generic error messages for all endpoints

### Phase 4: Low Security & Hardening (Week 7-8) 🔵

**Production optimization and security polish**

| Issue | Priority | Effort | Owner | Status |
|-------|----------|--------|-------|--------|
| LOW-01: Security Headers | P3 | 1 day | Backend Team | ⏳ Pending |
| LOW-02: Request ID | P3 | 1 day | Backend Team | ⏳ Pending |
| LOW-03: Gin Release Mode | P3 | 1 hour | Backend Team | ⏳ Pending |

**Deliverables:**
- [ ] Security headers middleware active
- [ ] Request ID tracking implemented
- [ ] Gin running in release mode for production
- [ ] Final security audit report

### Phase 5: Ongoing Security 🔄

**Continuous security practices**

- [ ] Monthly dependency updates
- [ ] Quarterly penetration testing
- [ ] Annual security audit
- [ ] Secrets rotation (every 90 days)
- [ ] Security training for development team
- [ ] Incident response plan maintained

---

## Security Checklist

### Pre-Production Deployment

**Authentication & Authorization:**
- [ ] API authentication implemented (JWT/API Key)
- [ ] Rate limiting active on all scan endpoints
- [ ] CORS configured with specific origins
- [ ] Security headers present in all responses

**Network Security:**
- [ ] PostgreSQL SSL/TLS enabled and enforced
- [ ] RabbitMQ TLS enabled and enforced
- [ ] Certificate validation configured
- [ ] Firewall rules restrict outbound connections

**Input Validation:**
- [ ] UUID validation on all ID parameters
- [ ] Hostname validation with RFC 1123 compliance
- [ ] Nmap command parameters sanitized
- [ ] SQL injection prevention verified (parameterized queries)

**Secrets Management:**
- [ ] No hardcoded credentials in code or config
- [ ] Environment variables used for all secrets
- [ ] Configuration files in .gitignore
- [ ] Secrets stored in vault/secrets manager
- [ ] Initial passwords rotated from defaults

**Logging & Monitoring:**
- [ ] Sensitive data excluded from logs
- [ ] Debug logging disabled in production
- [ ] Request IDs tracked for all requests
- [ ] Audit logging enabled for security events
- [ ] Log aggregation configured (ELK/Loki)

**Error Handling:**
- [ ] Generic error messages returned to clients
- [ ] Fatal() replaced with error returns
- [ ] Panic recovery implemented
- [ ] HTTP timeouts configured

**Infrastructure:**
- [ ] Service runs as non-root user
- [ ] File permissions restricted (configs: 0640, logs: 0700)
- [ ] Temporary files cleaned up regularly
- [ ] Disk space monitoring active
- [ ] Health checks functional (/health, /ready)

**Database:**
- [ ] Dedicated database user with minimal privileges
- [ ] No DELETE/DROP permissions granted
- [ ] Connection pooling configured
- [ ] Query timeouts set
- [ ] Audit logging enabled

**Documentation:**
- [ ] Security policies documented
- [ ] Incident response plan created
- [ ] Runbook for security incidents
- [ ] API documentation includes auth requirements
- [ ] Secrets rotation procedures documented

### Post-Deployment Verification

**Within 24 hours:**
- [ ] Verify authentication is enforced
- [ ] Test rate limiting behavior
- [ ] Confirm TLS connections to DB and RabbitMQ
- [ ] Check logs for any credential leakage
- [ ] Verify health check endpoints

**Within 1 week:**
- [ ] Perform basic penetration testing
- [ ] Review access logs for anomalies
- [ ] Verify backup procedures
- [ ] Test incident response plan
- [ ] Review monitoring dashboards

**Within 1 month:**
- [ ] Full security audit by external party
- [ ] Load testing with security focus
- [ ] Review and update threat model
- [ ] Conduct security training for team
- [ ] Update security documentation

---

## Responsible Disclosure

### Reporting Security Vulnerabilities

If you discover a security vulnerability in NaabuM8, please report it responsibly:

**Email:** i@deifzar.me
**PGP Key:** [Link to PGP public key if available]
**Response Time:** We aim to respond within 48 hours

**Please Include:**
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested remediation (if available)
5. Your contact information

**What to Expect:**
1. **Acknowledgment:** Within 48 hours
2. **Assessment:** Within 7 days
3. **Fix Timeline:** Critical: 7 days, High: 14 days, Medium: 30 days
4. **Credit:** We will credit security researchers (unless anonymity is requested)

**Out of Scope:**
- DoS attacks against public instances
- Social engineering of project maintainers
- Physical attacks
- Issues requiring unusual user interaction

**Bug Bounty:**
Currently, we do not offer a bug bounty program. However, we greatly appreciate responsible disclosure and will publicly credit researchers.

---

## Security References

### Standards & Compliance

- **OWASP Top 10 2021:** https://owasp.org/www-project-top-ten/
- **OWASP API Security Top 10:** https://owasp.org/www-project-api-security/
- **CWE/SANS Top 25:** https://cwe.mitre.org/top25/
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework

### Tools & Resources

- **Go Security Checker:** `gosec` - https://github.com/securego/gosec
- **Dependency Scanner:** `snyk` - https://snyk.io/
- **SAST Tool:** `SonarQube` - https://www.sonarqube.org/
- **Secrets Scanner:** `trufflehog` - https://github.com/trufflesecurity/trufflehog

### Related Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and design
- [PERFORMANCE.md](PERFORMANCE.md) - Performance optimization
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development guidelines
- [TODO.md](TODO.md) - Security improvements roadmap

---

**Document Control:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 2.0 | 2025-11-17 | Security Audit Team | Complete security review after history cleanup |
| 1.0 | 2025-11-12 | Initial | First security assessment |

---

**Classification:** Internal Use - Security Sensitive
**Review Cycle:** Quarterly
**Next Review:** 2025-02-17
