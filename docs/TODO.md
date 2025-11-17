# TODO: NaabuM8 Improvements

**Last Updated:** 2025-01-18
**Status:** Active Development

## 🚨 Critical Priority (Fix Immediately)

### Security Issues - URGENT

- [ ] **🔴 ROTATE ALL EXPOSED CREDENTIALS**
  - Rotate Discord bot token (currently exposed in configuration.yaml)
  - Rotate Discord webhook token (currently exposed in configuration.yaml)
  - Rotate database password (currently exposed in configuration.yaml)
  - Rotate RabbitMQ password (currently exposed in configuration.yaml)
  - **Assignee:** Security Team
  - **Deadline:** IMMEDIATELY (within 24 hours)
  - **Priority:** P0 - CRITICAL

- [ ] **Remove hardcoded secrets from configs/configuration.yaml**
  - Move Discord tokens to environment variables
  - Move database passwords to environment variables
  - Move RabbitMQ credentials to environment variables
  - Update `configs/configuration.yaml` to use `${VARIABLE_NAME}` syntax
  - **Assignee:** Security Team
  - **Deadline:** End of Week 1
  - **Priority:** P0 - CRITICAL

- [ ] **Update .gitignore to prevent future credential leaks**
  - Add `configs/configuration.yaml` to `.gitignore`
  - Consider adding `configs/*.yaml` except `configuration_template.yaml`
  - Run git history scan for other exposed secrets
  - **Assignee:** DevOps Team
  - **Deadline:** End of Week 1
  - **Priority:** P0 - CRITICAL

- [ ] **Replace Fatal() calls with proper error handling**
  - Files: `pkg/controller8/controller8_naabum8.go:45,87`
  - Files: `cmd/root.go:45,46`
  - Files: `cmd/launch.go:32,36,40,48`
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 1

- [ ] **Implement proper context management**
  - Replace `context.TODO()` with proper context propagation
  - Add context cancellation for long-running operations
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 1

### Authentication & Authorization
- [ ] **Implement API authentication**
  - Add API key validation middleware
  - Or implement JWT token authentication
  - **Assignee:** Security Team
  - **Deadline:** End of Week 2
  - **Priority:** P0 - CRITICAL (for production)

- [ ] **Add input validation to all endpoints**
  - Validate UUID format in `/scan/domain/:id`
  - Validate hostname list in `POST /scan`
  - Add validation middleware for all inputs
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 2
  - **Priority:** P1 - HIGH

### Performance Issues
- [ ] **Fix blocking channel issue in pkg/amqpM8/pooled_amqp.go:289**
  - Implement proper context cancellation in Consume() method
  - Update orchestrator8 to pass context to consumers
  - Add graceful shutdown mechanism within Consume()
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 1
  - **Priority:** P1 - HIGH
  - **Note:** Graceful shutdown implemented in cmd/launch.go, but consumer still blocks

## 🔥 High Priority (Next Sprint)

### Security Hardening
- [ ] **Enable SSL/TLS for database connections**
  - Update connection string to use `sslmode=require`
  - Configure SSL certificates for PostgreSQL
  - Test connection with SSL enabled
  - **Assignee:** DevOps Team
  - **Deadline:** End of Week 2
  - **Priority:** P1 - HIGH

- [ ] **Implement rate limiting**
  - Add rate limiting middleware to Gin router
  - Configure per-endpoint rate limits
  - Implement IP-based request throttling
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 3
  - **Priority:** P1 - HIGH

- [ ] **Add security headers middleware**
  - Implement `X-Content-Type-Options: nosniff`
  - Implement `X-Frame-Options: DENY`
  - Implement `X-XSS-Protection: 1; mode=block`
  - Add HSTS header for HTTPS
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 3
  - **Priority:** P2 - MEDIUM

### Database Optimization
- [ ] **Implement database connection pooling**
  - Add connection pool configuration to db8.OpenConnection()
  - Set `SetMaxOpenConns(25)`
  - Set `SetMaxIdleConns(5)`
  - Set `SetConnMaxLifetime(5 * time.Minute)`
  - Set `SetConnMaxIdleTime(1 * time.Minute)`
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 2
  - **Priority:** P2 - MEDIUM

- [ ] **Fix N+1 query problem**
  - Batch hostname queries in `controller8_naabum8.go`
  - Implement `GetHostnamesByNames()` method in db8_hostname8.go
  - Use `WHERE hostname IN (...)` for batch queries
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 2
  - **Priority:** P1 - HIGH

- [ ] **Add memory bounds checking**
  - Limit `Results8` map growth in pkg/model8/results8.go
  - Implement pagination for large result sets
  - Add periodic cleanup of processed results
  - Consider streaming results instead of in-memory accumulation
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 2
  - **Priority:** P1 - HIGH

### Input Validation
- [ ] **Add UUID validation to API endpoints**
  - Validate UUID format in `Naabum8Domain()` method
  - Add input sanitization middleware
  - **Assignee:** Backend Team
  - **Deadline:** End of Week 2

### Resource Management
- [x] **Implement proper RabbitMQ connection management** (✅ COMPLETED 2025-11-12)
  - ✅ Add connection pooling (completed in pkg/amqpM8/)
  - ✅ Manual acknowledgment mode for reliable message processing
  - ✅ Delivery tag tracking via HTTP headers
  - ✅ Automatic retry on failure (NACK with requeue)
  - ✅ Panic protection with defer function
  - ⚠️ Still need to fix connection leaks in concurrent scenarios (blocking channel at line 289)
  - **Completed By:** Backend Team
  - **Completed Date:** 2025-11-12 (commit bff6291)

## 📊 Medium Priority (Month 2)

### Architecture Improvements
- [ ] **Implement dependency injection**
  - Create service container
  - Refactor controllers to use dependency injection
  - **Assignee:** Architecture Team
  - **Deadline:** End of Month 1

- [ ] **Add structured error types**
  - Create domain-specific error types
  - Implement error handling middleware
  - **Assignee:** Backend Team
  - **Deadline:** End of Month 1

- [ ] **Implement circuit breaker pattern**
  - Add circuit breakers for external services
  - Implement fallback mechanisms
  - **Assignee:** Backend Team
  - **Deadline:** End of Month 1

### Code Quality
- [ ] **Refactor package naming convention**
  - Rename `pkg/amqpM8/` to `pkg/messaging/`
  - Rename `pkg/db8/` to `pkg/database/`
  - Rename `pkg/log8/` to `pkg/logging/`
  - **Assignee:** Backend Team
  - **Deadline:** End of Month 1

- [ ] **Add comprehensive unit tests**
  - Test coverage for all business logic
  - Integration tests for database operations
  - **Assignee:** QA Team
  - **Deadline:** End of Month 1

### Monitoring
- [ ] **Add Prometheus metrics**
  - Track scan performance metrics
  - Monitor RabbitMQ queue depths
  - Monitor database connection usage
  - **Assignee:** DevOps Team
  - **Deadline:** End of Month 1

## 🔧 Low Priority (Month 3+)

### Performance Optimizations
- [ ] **Implement caching layer**
  - Add Redis for frequently accessed data
  - Cache hostname lookups
  - **Assignee:** Backend Team
  - **Deadline:** End of Month 2

- [ ] **Add async processing**
  - Implement job queues for long-running tasks
  - Add worker pool patterns
  - **Assignee:** Backend Team
  - **Deadline:** End of Month 2

### Documentation
- [ ] **Add comprehensive API documentation**
  - OpenAPI/Swagger specification
  - API usage examples
  - **Assignee:** Documentation Team
  - **Deadline:** End of Month 2

- [ ] **Add GoDoc comments**
  - Document all public interfaces
  - Add code examples
  - **Assignee:** Backend Team
  - **Deadline:** End of Month 2

### Additional Features
- [ ] **Implement health check endpoints**
  - Database health checks
  - RabbitMQ health checks
  - External service health checks
  - **Assignee:** Backend Team
  - **Deadline:** End of Month 2

- [ ] **Add rate limiting**
  - Implement API rate limiting
  - Add request throttling
  - **Assignee:** Backend Team
  - **Deadline:** End of Month 2

## 📅 Sprint Planning

### Sprint 1 (Week 1-2) - SECURITY CRITICAL
**Focus:** Critical security fixes and credential rotation
- 🔴 **P0**: Rotate all exposed credentials (IMMEDIATE)
- 🔴 **P0**: Remove hardcoded secrets from configuration
- 🔴 **P0**: Update .gitignore to prevent future leaks
- **P1**: Fix blocking channel issue in RabbitMQ consumer
- **P1**: Replace Fatal() calls with proper error handling
- **P1**: Implement proper context management

**Success Criteria:**
- [ ] All credentials rotated and old credentials revoked
- [ ] No hardcoded secrets in codebase
- [ ] Configuration uses environment variables
- [ ] Blocking channel issue resolved
- [ ] No Fatal() calls in production code paths

### Sprint 2 (Week 3-4) - SECURITY & PERFORMANCE
**Focus:** Authentication, database optimization, and input validation
- 🔴 **P0**: Implement API authentication (API keys or JWT)
- **P1**: Fix N+1 query problem with batch operations
- **P1**: Add memory bounds checking to Results8
- **P1**: Enable SSL/TLS for database connections
- **P1**: Add input validation to all endpoints
- **P1**: Implement rate limiting
- **P2**: Add database connection pooling configuration

**Success Criteria:**
- [ ] Authentication required for all API endpoints
- [ ] Database queries use batch operations
- [ ] Memory usage bounded and predictable
- [ ] All database connections use SSL/TLS
- [ ] All inputs validated before processing

### Sprint 3 (Week 5-8) - ARCHITECTURE & TESTING
**Focus:** Architecture improvements and testing
- **P2**: Implement dependency injection
- **P2**: Add structured error types
- **P2**: Add comprehensive unit tests (target: 80% coverage)
- **P2**: Implement circuit breaker pattern
- **P2**: Add security headers middleware
- **P3**: Add Prometheus metrics
- **P3**: Implement caching layer with Redis

**Success Criteria:**
- [ ] Dependency injection container implemented
- [ ] Unit test coverage >80%
- [ ] Circuit breakers protect external services
- [ ] Security headers on all responses
- [ ] Monitoring and metrics in place

## 🎯 Success Metrics

### Performance Targets
- [ ] API response time: <200ms p95
- [ ] Database query time: <50ms p95
- [ ] Memory usage: <1GB per instance
- [ ] Zero fatal crashes

### Security Targets
- [ ] No hardcoded secrets in codebase
- [ ] All API inputs validated
- [ ] No SQL injection vulnerabilities
- [ ] SSL/TLS enabled for all connections

### Quality Targets
- [ ] Test coverage: >80%
- [ ] Code review coverage: 100%
- [ ] Documentation coverage: >90%
- [ ] Zero critical security issues

## 👥 Team Assignments

### Backend Team
- Security fixes
- Performance optimizations
- Code quality improvements
- Testing implementation

### DevOps Team
- Monitoring setup
- CI/CD improvements
- Infrastructure optimization
- Security scanning

### QA Team
- Test case development
- Performance testing
- Security testing
- Documentation review

## 📋 Completed Items

### ✅ 2025-01 Completed
- [x] Initial code review completed
- [x] Security vulnerabilities identified
- [x] Performance issues documented
- [x] Architecture improvements planned
- [x] Panic recovery added to scan operations
- [x] Error handling improvements in full scan flow
- [x] Graceful shutdown handling implemented (SIGINT/SIGTERM)
- [x] RabbitMQ connection pooling implemented
- [x] RabbitMQ manual acknowledgment mode implemented (2025-11-12, commit bff6291)
- [x] Temporary file cleanup utilities added
- [x] Health and readiness probe endpoints added
- [x] CLAUDE.md updated with comprehensive codebase information
- [x] Documentation updated in docs/ folder (ARCHITECTURE, DEVELOPMENT, PERFORMANCE, SECURITY, TODO, CODE_REVIEW)

## 🔄 Review Process

### Weekly Reviews
- Review progress on critical items
- Update priorities based on findings
- Assign new tasks as needed
- Update success metrics

### Monthly Reviews
- Assess overall progress
- Refine long-term goals
- Update team assignments
- Review and update documentation

---

**Note:** This TODO list should be updated regularly as work progresses. Items should be moved to completed section when finished, and new items should be added as they are identified.