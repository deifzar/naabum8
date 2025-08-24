package amqpM8

import (
	"deifzar/naabum8/pkg/configparser"
	"deifzar/naabum8/pkg/log8"
	"fmt"
	"time"
)

// InitializeConnectionPool initializes the RabbitMQ connection pool from configuration
func InitializeConnectionPool() error {
	v, err := configparser.InitConfigParser()
	if err != nil {
		return fmt.Errorf("failed to initialize config parser: %w", err)
	}

	location := v.GetString("RabbitMQ.location")
	port := v.GetInt("RabbitMQ.port")
	username := v.GetString("RabbitMQ.username")
	password := v.GetString("RabbitMQ.password")

	// Create custom config for this application's needs
	config := ConnectionPoolConfig{
		MaxConnections:    v.GetInt("RabbitMQ.pool.max_connections"),
		MinConnections:    v.GetInt("RabbitMQ.pool.min_connections"),
		MaxIdleTime:       v.GetDuration("RabbitMQ.pool.max_idle_time"),
		MaxLifetime:       v.GetDuration("RabbitMQ.pool.max_lifetime"),
		HealthCheckPeriod: v.GetDuration("RabbitMQ.pool.health_check_period"),
		ConnectionTimeout: v.GetDuration("RabbitMQ.pool.connection_timeout"),
		RetryAttempts:     v.GetInt("RabbitMQ.pool.retry_attempts"),
		RetryDelay:        v.GetDuration("RabbitMQ.pool.retry_delay"),
	}

	// Use defaults if not configured
	if config.MaxConnections == 0 {
		config.MaxConnections = 10
	}
	if config.MinConnections == 0 {
		config.MinConnections = 2
	}
	if config.MaxIdleTime == 0 {
		config.MaxIdleTime = 15 * time.Minute
	}
	if config.MaxLifetime == 0 {
		config.MaxLifetime = 1 * time.Hour
	}
	if config.HealthCheckPeriod == 0 {
		config.HealthCheckPeriod = 5 * time.Minute
	}
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 30 * time.Second
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 2 * time.Second
	}

	manager := GetGlobalPoolManager()
	err = manager.InitializePool("default", location, port, username, password, config)
	if err != nil {
		return fmt.Errorf("failed to initialize default connection pool: %w", err)
	}

	log8.BaseLogger.Info().Msgf("Connection pool initialized successfully with config: max=%d, min=%d, maxIdle=%v, maxLife=%v",
		config.MaxConnections, config.MinConnections, config.MaxIdleTime, config.MaxLifetime)

	return nil
}

// CleanupConnectionPool closes all connection pools - should be called during application shutdown
func CleanupConnectionPool() {
	manager := GetGlobalPoolManager()
	manager.CloseAllPools()
	log8.BaseLogger.Info().Msg("Connection pool cleanup completed")
}

// GetPoolHealthStatus returns health status of all pools
func GetPoolHealthStatus() map[string]interface{} {
	manager := GetGlobalPoolManager()
	stats := manager.GetAllPoolStats()

	healthStatus := make(map[string]interface{})
	for poolName, stat := range stats {
		healthStatus[poolName] = map[string]interface{}{
			"active_connections":  stat.ActiveConnections,
			"idle_connections":    stat.IdleConnections,
			"healthy_connections": stat.HealthyConnections,
			"total_created":       stat.TotalCreated,
			"total_destroyed":     stat.TotalDestroyed,
			"total_borrowed":      stat.TotalBorrowed,
			"total_returned":      stat.TotalReturned,
		}
	}

	return healthStatus
}
