package amqpM8

import (
	"context"
	"deifzar/naabum8/pkg/log8"
	"fmt"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// PooledConnection represents a connection in the pool with metadata
type PooledConnection struct {
	conn       *amqp.Connection
	channel    *amqp.Channel
	inUse      bool
	createdAt  time.Time
	lastUsed   time.Time
	usageCount uint64
	isHealthy  bool
	mu         sync.RWMutex
}

// ConnectionPoolConfig holds configuration for the connection pool
type ConnectionPoolConfig struct {
	MaxConnections    int           // Maximum number of connections in pool
	MinConnections    int           // Minimum number of connections to maintain
	MaxIdleTime       time.Duration // Maximum time a connection can be idle
	MaxLifetime       time.Duration // Maximum lifetime of a connection
	HealthCheckPeriod time.Duration // How often to perform health checks
	ConnectionTimeout time.Duration // Timeout for creating new connections
	RetryAttempts     int           // Number of retry attempts for failed operations
	RetryDelay        time.Duration // Delay between retry attempts
}

// ConnectionPool manages a pool of RabbitMQ connections
type ConnectionPool struct {
	config       ConnectionPoolConfig
	connString   string
	pool         []*PooledConnection
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	healthTicker *time.Ticker

	// Metrics
	totalCreated   uint64
	totalDestroyed uint64
	totalBorrowed  uint64
	totalReturned  uint64
}

// ConnectionPoolStats provides statistics about the connection pool
type ConnectionPoolStats struct {
	ActiveConnections  int
	IdleConnections    int
	TotalCreated       uint64
	TotalDestroyed     uint64
	TotalBorrowed      uint64
	TotalReturned      uint64
	HealthyConnections int
}

// ConnectionPoolInterface defines the interface for connection pool operations
type ConnectionPoolInterface interface {
	Get() (PooledAmqpInterface, error)
	Return(conn PooledAmqpInterface)
	Close()
	Stats() ConnectionPoolStats
	HealthCheck()
}

// DefaultConnectionPoolConfig returns a default configuration for the connection pool
func DefaultConnectionPoolConfig() ConnectionPoolConfig {
	return ConnectionPoolConfig{
		MaxConnections:    10,
		MinConnections:    2,
		MaxIdleTime:       15 * time.Minute,
		MaxLifetime:       1 * time.Hour,
		HealthCheckPeriod: 5 * time.Minute,
		ConnectionTimeout: 30 * time.Second,
		RetryAttempts:     3,
		RetryDelay:        2 * time.Second,
	}
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(location string, port int, username, password string, config ConnectionPoolConfig) (ConnectionPoolInterface, error) {
	connString := fmt.Sprintf("amqp://%s:%s@%s:%d/", username, password, location, port)

	ctx, cancel := context.WithCancel(context.Background())

	pool := &ConnectionPool{
		config:     config,
		connString: connString,
		pool:       make([]*PooledConnection, 0, config.MaxConnections),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Initialize minimum connections
	if err := pool.initializeMinConnections(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize connection pool: %w", err)
	}

	// Start health check routine
	pool.startHealthCheck()

	log8.BaseLogger.Info().Msgf("Connection pool initialized with %d/%d connections",
		len(pool.pool), config.MaxConnections)

	return pool, nil
}

// initializeMinConnections creates the minimum required connections
func (p *ConnectionPool) initializeMinConnections() error {
	for i := 0; i < p.config.MinConnections; i++ {
		conn, err := p.createConnection()
		if err != nil {
			return fmt.Errorf("failed to create initial connection %d: %w", i, err)
		}
		p.pool = append(p.pool, conn)
		p.totalCreated++
	}
	return nil
}

// createConnection creates a new pooled connection with retry logic
func (p *ConnectionPool) createConnection() (*PooledConnection, error) {
	var conn *amqp.Connection
	var err error

	for attempt := 0; attempt < p.config.RetryAttempts; attempt++ {
		_, cancel := context.WithTimeout(p.ctx, p.config.ConnectionTimeout)

		conn, err = amqp.DialConfig(p.connString, amqp.Config{
			Heartbeat: 10 * time.Second,
			Locale:    "en_US",
		})
		cancel()

		if err == nil {
			break
		}

		if attempt < p.config.RetryAttempts-1 {
			log8.BaseLogger.Warn().Msgf("Connection attempt %d/%d failed: %v, retrying...",
				attempt+1, p.config.RetryAttempts, err)
			time.Sleep(p.config.RetryDelay)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create connection after %d attempts: %w", p.config.RetryAttempts, err)
	}

	channel, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create channel: %w", err)
	}

	now := time.Now()
	pooledConn := &PooledConnection{
		conn:      conn,
		channel:   channel,
		inUse:     false,
		createdAt: now,
		lastUsed:  now,
		isHealthy: true,
	}

	log8.BaseLogger.Debug().Msg("Created new pooled connection")
	return pooledConn, nil
}

// Get retrieves a connection from the pool
func (p *ConnectionPool) Get() (PooledAmqpInterface, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to find an available healthy connection
	for _, pooledConn := range p.pool {
		pooledConn.mu.Lock()
		if !pooledConn.inUse && pooledConn.isHealthy && p.isConnectionValid(pooledConn) {
			pooledConn.inUse = true
			pooledConn.lastUsed = time.Now()
			pooledConn.usageCount++
			pooledConn.mu.Unlock()

			p.totalBorrowed++

			// Create a wrapper that implements PooledAmqpInterface
			wrapper := NewPooledAmqp(pooledConn, p)
			log8.BaseLogger.Debug().Msg("Retrieved existing connection from pool")
			return wrapper, nil
		}
		pooledConn.mu.Unlock()
	}

	// No available connection, try to create a new one if under max limit
	if len(p.pool) < p.config.MaxConnections {
		pooledConn, err := p.createConnection()
		if err != nil {
			return nil, fmt.Errorf("failed to create new pooled connection: %w", err)
		}

		pooledConn.inUse = true
		pooledConn.lastUsed = time.Now()
		pooledConn.usageCount++
		p.pool = append(p.pool, pooledConn)
		p.totalCreated++
		p.totalBorrowed++

		wrapper := NewPooledAmqp(pooledConn, p)
		log8.BaseLogger.Debug().Msg("Created new connection for pool")
		return wrapper, nil
	}

	return nil, fmt.Errorf("connection pool exhausted: %d connections in use", len(p.pool))
}

// Return returns a connection to the pool.
// This basically set the 'inUse' property to 'false' so the connection becomes free and available to use/fetch from the pool.
func (p *ConnectionPool) Return(conn PooledAmqpInterface) {
	if wrapper, ok := conn.(*PooledAmqp); ok {
		wrapper.pooledConn.mu.Lock()
		wrapper.pooledConn.inUse = false
		wrapper.pooledConn.lastUsed = time.Now()
		wrapper.pooledConn.mu.Unlock()

		p.mu.Lock()
		p.totalReturned++
		p.mu.Unlock()

		log8.BaseLogger.Debug().Msg("Returned connection to pool")
	}
}

// isConnectionValid checks if a pooled connection is still valid
func (p *ConnectionPool) isConnectionValid(pooledConn *PooledConnection) bool {
	if pooledConn.conn.IsClosed() {
		return false
	}

	// Check max lifetime
	if time.Since(pooledConn.createdAt) > p.config.MaxLifetime {
		return false
	}

	// Check max idle time
	if time.Since(pooledConn.lastUsed) > p.config.MaxIdleTime {
		return false
	}

	return true
}

// startHealthCheck starts the periodic health check routine
func (p *ConnectionPool) startHealthCheck() {
	p.healthTicker = time.NewTicker(p.config.HealthCheckPeriod)

	go func() {
		defer p.healthTicker.Stop()

		for {
			select {
			case <-p.ctx.Done():
				return
			case <-p.healthTicker.C:
				p.HealthCheck()
			}
		}
	}()
}

// HealthCheck performs health checks on all connections in the pool
func (p *ConnectionPool) HealthCheck() {
	p.mu.Lock()
	defer p.mu.Unlock()

	var healthyCount int
	var toRemove []*PooledConnection

	for i, pooledConn := range p.pool {
		pooledConn.mu.Lock()

		if !pooledConn.inUse && (!p.isConnectionValid(pooledConn) || !pooledConn.isHealthy) {
			toRemove = append(toRemove, pooledConn)
			log8.BaseLogger.Debug().Msgf("Marking connection %d for removal (invalid or unhealthy)", i)
		} else if pooledConn.isHealthy {
			healthyCount++
		}

		pooledConn.mu.Unlock()
	}

	// Remove invalid connections
	for _, connToRemove := range toRemove {
		p.removeConnection(connToRemove)
	}

	// Ensure we have minimum connections
	currentCount := len(p.pool)
	if currentCount < p.config.MinConnections {
		needed := p.config.MinConnections - currentCount
		log8.BaseLogger.Info().Msgf("Pool below minimum, creating %d new connections", needed)

		for i := 0; i < needed; i++ {
			if newConn, err := p.createConnection(); err == nil {
				p.pool = append(p.pool, newConn)
				p.totalCreated++
				healthyCount++
			} else {
				log8.BaseLogger.Error().Msgf("Failed to create replacement connection: %v", err)
			}
		}
	}

	log8.BaseLogger.Debug().Msgf("Health check completed: %d healthy, %d total connections",
		healthyCount, len(p.pool))
}

// removeConnection removes and closes a connection from the pool
func (p *ConnectionPool) removeConnection(connToRemove *PooledConnection) {
	// Remove from pool slice
	for i, pooledConn := range p.pool {
		if pooledConn == connToRemove {
			p.pool = append(p.pool[:i], p.pool[i+1:]...)
			break
		}
	}

	// Close the connection
	connToRemove.mu.Lock()
	if connToRemove.channel != nil {
		connToRemove.channel.Close()
	}
	if connToRemove.conn != nil {
		connToRemove.conn.Close()
	}
	connToRemove.mu.Unlock()

	p.totalDestroyed++
}

// Stats returns statistics about the connection pool
func (p *ConnectionPool) Stats() ConnectionPoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var active, idle, healthy int

	for _, pooledConn := range p.pool {
		pooledConn.mu.RLock()
		if pooledConn.inUse {
			active++
		} else {
			idle++
		}
		if pooledConn.isHealthy {
			healthy++
		}
		pooledConn.mu.RUnlock()
	}

	return ConnectionPoolStats{
		ActiveConnections:  active,
		IdleConnections:    idle,
		TotalCreated:       p.totalCreated,
		TotalDestroyed:     p.totalDestroyed,
		TotalBorrowed:      p.totalBorrowed,
		TotalReturned:      p.totalReturned,
		HealthyConnections: healthy,
	}
}

// Close closes the connection pool and all its connections
func (p *ConnectionPool) Close() {
	log8.BaseLogger.Info().Msg("Closing connection pool")

	p.cancel()

	if p.healthTicker != nil {
		p.healthTicker.Stop()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, pooledConn := range p.pool {
		pooledConn.mu.Lock()
		if pooledConn.channel != nil {
			pooledConn.channel.Close()
		}
		if pooledConn.conn != nil {
			pooledConn.conn.Close()
		}
		pooledConn.mu.Unlock()
	}

	p.pool = nil
	log8.BaseLogger.Info().Msg("Connection pool closed")
}
