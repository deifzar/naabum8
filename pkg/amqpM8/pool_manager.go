package amqpM8

import (
	"deifzar/naabum8/pkg/log8"
	"fmt"
	"sync"
)

// GlobalPoolManager manages connection pools across the application
type GlobalPoolManager struct {
	pools map[string]ConnectionPoolInterface
	mu    sync.RWMutex
}

var (
	globalManager *GlobalPoolManager
	managerOnce   sync.Once
)

// GetGlobalPoolManager returns the singleton pool manager instance
func GetGlobalPoolManager() *GlobalPoolManager {
	managerOnce.Do(func() {
		globalManager = &GlobalPoolManager{
			pools: make(map[string]ConnectionPoolInterface),
		}
	})
	return globalManager
}

// InitializePool creates and registers a new connection pool
func (pm *GlobalPoolManager) InitializePool(name, location string, port int, username, password string, config ConnectionPoolConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.pools[name]; exists {
		return fmt.Errorf("pool with name '%s' already exists", name)
	}

	pool, err := NewConnectionPool(location, port, username, password, config)
	if err != nil {
		return fmt.Errorf("failed to create connection pool '%s': %w", name, err)
	}

	pm.pools[name] = pool
	log8.BaseLogger.Info().Msgf("Initialized connection pool '%s'", name)

	return nil
}

// GetPool returns a connection pool by name
func (pm *GlobalPoolManager) GetPool(name string) (ConnectionPoolInterface, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pool, exists := pm.pools[name]
	if !exists {
		return nil, fmt.Errorf("pool with name '%s' not found", name)
	}

	return pool, nil
}

// GetConnection gets a connection from the specified pool
func (pm *GlobalPoolManager) GetConnection(poolName string) (PooledAmqpInterface, error) {
	pool, err := pm.GetPool(poolName)
	if err != nil {
		return nil, err
	}

	return pool.Get()
}

// ReturnConnection returns a connection to the specified pool
func (pm *GlobalPoolManager) ReturnConnection(poolName string, conn PooledAmqpInterface) error {
	pool, err := pm.GetPool(poolName)
	if err != nil {
		return err
	}

	pool.Return(conn)
	return nil
}

// GetAllPoolStats returns statistics for all pools
func (pm *GlobalPoolManager) GetAllPoolStats() map[string]ConnectionPoolStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := make(map[string]ConnectionPoolStats)
	for name, pool := range pm.pools {
		stats[name] = pool.Stats()
	}

	return stats
}

// GetPoolStats returns statistics for a specific pool
func (pm *GlobalPoolManager) GetPoolStats(poolName string) (ConnectionPoolStats, error) {
	pool, err := pm.GetPool(poolName)
	if err != nil {
		return ConnectionPoolStats{}, err
	}

	return pool.Stats(), nil
}

// ListPools returns the names of all registered pools
func (pm *GlobalPoolManager) ListPools() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	names := make([]string, 0, len(pm.pools))
	for name := range pm.pools {
		names = append(names, name)
	}

	return names
}

// ClosePool closes and removes a specific pool
func (pm *GlobalPoolManager) ClosePool(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pool, exists := pm.pools[name]
	if !exists {
		return fmt.Errorf("pool with name '%s' not found", name)
	}

	pool.Close()
	delete(pm.pools, name)
	log8.BaseLogger.Info().Msgf("Closed and removed connection pool '%s'", name)

	return nil
}

// CloseAllPools closes all connection pools
func (pm *GlobalPoolManager) CloseAllPools() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	log8.BaseLogger.Info().Msgf("Closing %d connection pools", len(pm.pools))

	for name, pool := range pm.pools {
		pool.Close()
		log8.BaseLogger.Info().Msgf("Closed connection pool '%s'", name)
	}

	pm.pools = make(map[string]ConnectionPoolInterface)
	log8.BaseLogger.Info().Msg("All connection pools closed")
}

// HealthCheckAllPools performs health checks on all pools
func (pm *GlobalPoolManager) HealthCheckAllPools() {
	pm.mu.RLock()
	pools := make([]ConnectionPoolInterface, 0, len(pm.pools))
	for _, pool := range pm.pools {
		pools = append(pools, pool)
	}
	pm.mu.RUnlock()

	for _, pool := range pools {
		pool.HealthCheck()
	}
}

// GetDefaultConnection gets a connection from the default pool
func GetDefaultConnection() (PooledAmqpInterface, error) {
	manager := GetGlobalPoolManager()
	return manager.GetConnection("default")
}

// WithPooledConnection executes a function with a pooled connection and ensures it's returned
func WithPooledConnection(fn func(PooledAmqpInterface) error) error {
	conn, err := GetDefaultConnection()
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Error().Msg("Failed to get connection from pool")
		return err
	}

	// Ensure connection is returned to pool after use
	defer func() {
		if pooledConn, ok := conn.(*PooledAmqp); ok {
			pooledConn.ReturnToPool()
		}
	}()

	return fn(conn)
}
