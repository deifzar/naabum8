package amqpM8

import (
	"context"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ConsumerHealth tracks the health of individual consumers
type ConsumerHealth struct {
	ConsumerName string
	QueueName    string
	AutoACK      bool
	IsActive     bool
	LastSeen     time.Time
	MessageCount uint64
	ErrorCount   uint64
	RestartCount uint64
	CreatedAt    time.Time
}

// PooledAmqpInterface defines the interface for pooled AMQP operations
type PooledAmqpInterface interface {
	AddHandler(queueName string, handler func(msg amqp.Delivery) error)
	GetChannel() *amqp.Channel
	GetQueues() map[string]map[string]amqp.Queue
	GetBindings() map[string]map[string][]string
	GetExchanges() map[string]string
	GetExchangeTypeByExchangeName(exchangeName string) string
	GetQueueByExchangeNameAndQueueName(exchangeName string, queuename string) amqp.Queue
	GetBindingsByExchangeNameAndQueueName(exchangeName string, queuename string) []string
	GetConsumerByName(consumnerName string) []string
	GetConsumersForQueue(queueName string) []string
	SetExchange(exchangeName string, exchangeType string)
	SetQueueByExchangeName(exchangeName string, queueName string, queue amqp.Queue)
	SetBindingQueueByExchangeName(exchangeName string, queueName string, bindingKeys []string)
	SetConsumers(c map[string][]string)
	DeclareExchange(exchangeName string, exchangeType string) error
	DeclareQueue(exchangeName string, queueName string, prefetchCount int, queueArgs amqp.Table) error
	BindQueue(exchangeName string, queueName string, bindingKeys []string) error
	Publish(exchangeName string, routingKey string, payload any, source string) error
	Consume(consumerName, queueName string, autoACK bool) error
	ConsumeWithContext(ctx context.Context, consumerName, queueName string, autoACK bool) error
	ConsumeWithReconnect(ctx context.Context, consumerName, queueName string, autoACK bool) error
	GetNumberOfActiveConsumersByQueue(queueName string, queueArgs amqp.Table) int
	ExistQueue(queueName string, queueArgs amqp.Table) bool
	DeleteQueue(queueName string) error
	CancelConsumer(consumerName string) error
	CloseConnection()
	CloseChannel()

	// Connection monitoring methods
	IsConnected() bool
	GetConnectionStatus() map[string]interface{}

	// Consumer health monitoring methods
	GetConsumerHealth() map[string]*ConsumerHealth
	GetConsumerHealthByName(consumerName string) (*ConsumerHealth, bool)
	SetHealthCheckInterval(interval time.Duration)

	// Context management methods
	ShutdownConsumer(consumerName string) error
	ShutdownAllConsumers()
	GetActiveConsumers() []string
	IsConsumerActive(consumerName string) bool
}

// PooledAmqp wraps a pooled connection and implements PooledAmqpInterface
type PooledAmqp struct {
	pooledConn *PooledConnection
	pool       *ConnectionPool

	// Shared state across all pooled connections
	sharedState *SharedAmqpState

	// Local state for this wrapper instance (consumer-specific)
	consumers map[string][]string

	// Consumer health monitoring (lightweight for pooled connections)
	consumerHealth      map[string]*ConsumerHealth
	healthCheckInterval time.Duration
	mu                  sync.RWMutex
}

// NewPooledAmqp creates a new pooled AMQP instance around a pooled connection
func NewPooledAmqp(pooledConn *PooledConnection, pool *ConnectionPool) *PooledAmqp {
	return &PooledAmqp{
		pooledConn:          pooledConn,
		pool:                pool,
		sharedState:         GetSharedState(), // Use global shared state
		consumers:           make(map[string][]string),
		consumerHealth:      make(map[string]*ConsumerHealth),
		healthCheckInterval: 30 * time.Minute,
	}
}

// AddHandler adds a message handler for a queue
func (w *PooledAmqp) AddHandler(queueName string, handler func(msg amqp.Delivery) error) {
	w.sharedState.AddHandler(queueName, handler)
}

// GetChannel returns the underlying AMQP channel
func (w *PooledAmqp) GetChannel() *amqp.Channel {
	return w.pooledConn.channel
}

// GetQueues returns the queues map
func (w *PooledAmqp) GetQueues() map[string]map[string]amqp.Queue {
	return w.sharedState.GetQueues()
}

// GetBindings returns the bindings map
func (w *PooledAmqp) GetBindings() map[string]map[string][]string {
	return w.sharedState.GetBindings()
}

// GetExchanges returns the exchanges map
func (w *PooledAmqp) GetExchanges() map[string]string {
	return w.sharedState.GetExchanges()
}

// GetExchangeTypeByExchangeName returns the exchange type for a given exchange name
func (w *PooledAmqp) GetExchangeTypeByExchangeName(exchangeName string) string {
	return w.sharedState.GetExchangeTypeByExchangeName(exchangeName)
}

// GetQueueByExchangeNameAndQueueName returns a queue by exchange and queue name
func (w *PooledAmqp) GetQueueByExchangeNameAndQueueName(exchangeName string, queuename string) amqp.Queue {
	return w.sharedState.GetQueueByExchangeNameAndQueueName(exchangeName, queuename)
}

// GetBindingsByExchangeNameAndQueueName returns bindings for a queue
func (w *PooledAmqp) GetBindingsByExchangeNameAndQueueName(exchangeName string, queuename string) []string {
	return w.sharedState.GetBindingsByExchangeNameAndQueueName(exchangeName, queuename)
}

// GetConsumerByName returns consumer info by name
func (w *PooledAmqp) GetConsumerByName(consumerName string) []string {
	return w.sharedState.GetConsumerByName(consumerName)
}

// GetConsumersForQueue returns all consumers for a specific queue
func (w *PooledAmqp) GetConsumersForQueue(queueName string) []string {
	return w.sharedState.GetConsumersForQueue(queueName)
}

// SetExchange sets an exchange
func (w *PooledAmqp) SetExchange(exchangeName string, exchangeType string) {
	w.sharedState.SetExchange(exchangeName, exchangeType)
}

// SetQueueByExchangeName sets a queue for an exchange
func (w *PooledAmqp) SetQueueByExchangeName(exchangeName string, queueName string, queue amqp.Queue) {
	w.sharedState.SetQueueByExchangeName(exchangeName, queueName, queue)
}

// SetBindingQueueByExchangeName sets binding keys for a queue
func (w *PooledAmqp) SetBindingQueueByExchangeName(exchangeName string, queueName string, bindingKeys []string) {
	w.sharedState.SetBindingQueueByExchangeName(exchangeName, queueName, bindingKeys)
}

// SetConsumers sets the consumers map
func (w *PooledAmqp) SetConsumers(c map[string][]string) {
	w.sharedState.SetConsumers(c)
}

// DeleteConsumerByName delete consumer name from consumers map
func (w *PooledAmqp) DeleteConsumerByName(cname string) {
	w.sharedState.DeleteConsumerByName(cname)
}

// DeclareExchange declares an exchange
func (w *PooledAmqp) DeclareExchange(exchangeName string, exchangeType string) error {
	if exchangeName == "" || exchangeType == "" {
		return fmt.Errorf("exchange name and type cannot be empty")
	}

	log8.BaseLogger.Info().Msgf("Creating Exchange with name `%s`", exchangeName)
	err := w.pooledConn.channel.ExchangeDeclare(
		exchangeName, // name
		exchangeType, // type
		true,         // durable
		false,        // auto-deleted
		false,        // internal
		false,        // no-wait
		nil,          // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to declare exchange: %w", err)
	}

	log8.BaseLogger.Info().Msgf("Exchange successfully created with name `%s`", exchangeName)
	w.SetExchange(exchangeName, exchangeType)

	// Initialize maps for this exchange in shared state
	w.sharedState.InitializeExchange(exchangeName)

	return nil
}

// DeclareQueue declares a queue
func (w *PooledAmqp) DeclareQueue(exchangeName string, queueName string, prefetchCount int, queueArgs amqp.Table) error {
	log8.BaseLogger.Info().Msgf("Creating and binding Queue with name `%s` in Exchange `%s`", queueName, exchangeName)

	q, err := w.pooledConn.channel.QueueDeclare(
		queueName, // name
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		queueArgs, // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to declare queue: %w", err)
	}

	log8.BaseLogger.Info().Msgf("Queue successfully created with name `%s` in Exchange `%s`", queueName, exchangeName)

	if prefetchCount > 0 {
		log8.BaseLogger.Info().Msgf("Queue `%s` with Qos control due to prefetch value of `%d`", queueName, prefetchCount)
		err = w.pooledConn.channel.Qos(
			prefetchCount, // prefetch count
			0,             // prefetch size
			false,         // global
		)
		if err != nil {
			return fmt.Errorf("queue `%s` failed to set qos control: %w", queueName, err)
		}
	}

	w.SetQueueByExchangeName(exchangeName, queueName, q)
	return nil
}

// BindQueue binds a queue to an exchange
func (w *PooledAmqp) BindQueue(exchangeName string, queueName string, bindingKeys []string) error {
	log8.BaseLogger.Info().Msgf("Binding Queue `%s` with Exchange `%s` and Binding keys `%v`", queueName, exchangeName, bindingKeys)

	for _, bkey := range bindingKeys {
		err := w.pooledConn.channel.QueueBind(
			queueName,    // queue name
			bkey,         // routing key
			exchangeName, // exchange
			false,
			nil,
		)
		if err != nil {
			return fmt.Errorf("failed to bind queue `%s` with exchange `%s` and binding key `%s`: %w", queueName, exchangeName, bkey, err)
		}
	}

	log8.BaseLogger.Info().Msgf("Success binding Queue `%s` and Exchange `%s`", queueName, exchangeName)
	w.SetBindingQueueByExchangeName(exchangeName, queueName, bindingKeys)
	return nil
}

// Return the number of active consumers if the queue exists. It will return an error if the queue does not exist.
func (w *PooledAmqp) GetNumberOfActiveConsumersByQueue(queueName string, queueArgs amqp.Table) int {
	log8.BaseLogger.Info().Msgf("Checking how many active consumers the queue `%s` has", queueName)

	queue, err := w.pooledConn.channel.QueueDeclarePassive(
		queueName, // name
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		queueArgs, // arguments
	)
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Info().Msgf("Queue `%s` does not exist", queueName)
		return 0
	}

	return queue.Consumers
}

// ExistQueue checks if a queue exists
func (w *PooledAmqp) ExistQueue(queueName string, queueArgs amqp.Table) bool {
	log8.BaseLogger.Info().Msgf("Checking if queue `%s` exists", queueName)

	_, err := w.pooledConn.channel.QueueDeclarePassive(
		queueName, // name
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		queueArgs, // arguments
	)

	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Info().Msgf("Queue `%s` does not exist", queueName)
		return false
	}

	log8.BaseLogger.Info().Msgf("Queue `%s` exists", queueName)
	return true
}

// DeleteQueue deletes a queue
func (w *PooledAmqp) DeleteQueue(queueName string) error {
	_, err := w.pooledConn.channel.QueueDelete(
		queueName, // name
		false,     // ifUnused
		false,     // ifEmpty
		false,     // noWait
	)
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Warn().Msgf("Queue `%s` cannot be deleted", queueName)
		return err
	}
	// Delete relevant shared states values
	w.sharedState.DeleteQueueByName(queueName)

	log8.BaseLogger.Info().Msgf("Queue `%s` deleted", queueName)
	return nil
}

// CancelConsumer cancels a consumer
func (w *PooledAmqp) CancelConsumer(consumerName string) error {
	w.pooledConn.mu.Lock()
	defer w.pooledConn.mu.Unlock()
	if w.pooledConn.channel != nil || w.pooledConn.channel.IsClosed() {
		log8.BaseLogger.Warn().Msgf("Channel is nil or closed, cannot cancel consumer with name %s", consumerName)
		err := fmt.Errorf("channel is nil or closed, cannot cancel consumer with name %s", consumerName)
		return err
	}
	err := w.pooledConn.channel.Cancel(consumerName, true)
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Warn().Msgf("Consumer `%s` cannot be cancelled", consumerName)
		return err
	}
	// Delete relevant shared state values
	w.sharedState.DeleteConsumerByName(consumerName)

	log8.BaseLogger.Info().Msgf("Consumer `%s` cancelled", consumerName)
	return nil
}

// Publish publishes a message to an exchange calling internally PublishWithContext.
func (w *PooledAmqp) Publish(exchangeName string, routingKey string, payload any, source string) error {
	msg := model8.AmqpM8Message{
		Channel:   routingKey,
		Payload:   payload,
		Timestamp: time.Now(),
		Source:    source,
	}

	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("publishing into exchange `%s` with routing key `%s` failed to marshal payload: %w", exchangeName, routingKey, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = w.pooledConn.channel.PublishWithContext(ctx,
		exchangeName, // exchange
		routingKey,   // routing key
		false,        // mandatory
		false,        // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "application/json",
			Body:         bytes,
		},
	)

	if err != nil {
		// Mark connection as potentially unhealthy
		w.pooledConn.mu.Lock()
		w.pooledConn.isHealthy = false
		w.pooledConn.mu.Unlock()
	}

	return err
}

// Consume starts consuming messages from a queue calling internally ConsumeWithContext
func (w *PooledAmqp) Consume(consumerName, queueName string, autoACK bool) error {
	return w.ConsumeWithContext(context.Background(), consumerName, queueName, autoACK)
}

// ConsumeWithContext starts consuming messages with a context
func (w *PooledAmqp) ConsumeWithContext(ctx context.Context, consumerName, queueName string, autoACK bool) error {
	msgs, err := w.pooledConn.channel.Consume(
		queueName,    // queue
		consumerName, // consumer
		autoACK,      // auto-ack
		false,        // exclusive
		false,        // no-local
		false,        // no-wait
		nil,          // args
	)
	if err != nil {
		w.updateConsumerHealth(consumerName, false, 0, 1)
		return fmt.Errorf("consumer creation failed for queue `%s`: %w", queueName, err)
	}

	log8.BaseLogger.Info().Msgf("Success with consumer creation for queue `%s`", queueName)
	w.registerConsumerHealth(consumerName, queueName, autoACK)

	// Channel to communicate consumer completion/failure back to caller
	done := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log8.BaseLogger.Error().Msgf("Consumer panic recovered for queue `%s`: %v", queueName, r)
				w.updateConsumerHealth(consumerName, false, 0, 1)
				done <- fmt.Errorf("consumer panic for queue `%s`: %v", queueName, r)
			} else {
				// Normal exit - send nil to indicate graceful shutdown
				done <- nil
			}
			w.markConsumerInactive(consumerName)
		}()

		for {
			select {
			case <-ctx.Done(): // context.Background() never gets cancelled
				log8.BaseLogger.Info().Msgf("Consumer `%s` shutting down gracefully", consumerName)
				if err := w.CancelConsumer(consumerName); err != nil {
					log8.BaseLogger.Error().Msgf("Error cancelling consumer `%s`: %v", consumerName, err)
				}
				return

			case msg, ok := <-msgs:
				if !ok {
					log8.BaseLogger.Warn().Msgf("Consumer for queue `%s` stopped - channel closed", queueName)
					// Publish message to other microservice so it does not stall the flow
					w.publishMessage("cptm8", "cptm8.naabum8.get.scan", nil, "asmm8")
					// Send error to indicate connection failure
					done <- fmt.Errorf("consumer for queue `%s` stopped - connection lost", queueName)
					return
				}

				w.updateConsumerLastSeen(consumerName)

				if handler, exists := w.sharedState.GetHandler(queueName); exists {
					if err := handler(msg); err != nil {
						log8.BaseLogger.Error().Msgf("Handler error for queue `%s`: %v", queueName, err)
						w.updateConsumerHealth(consumerName, true, 1, 1)
					} else {
						w.updateConsumerHealth(consumerName, true, 1, 0)
					}
				} else {
					log8.BaseLogger.Warn().Msgf("No handler found for queue `%s`", queueName)
					w.updateConsumerHealth(consumerName, true, 1, 1)
				}

				if !autoACK {
					msg.Ack(false)
				}
			}
		}
	}()

	// Block and wait for the consumer goroutine to complete or fail
	return <-done
}

// ConsumeWithReconnect starts consuming messages with automatic reconnection on connection failure
func (w *PooledAmqp) ConsumeWithReconnect(ctx context.Context, consumerName, queueName string, autoACK bool) error {
	log8.BaseLogger.Info().Msgf("Starting consumer `%s` for queue `%s` with auto-reconnect", consumerName, queueName)

	go func() {
		reconnectDelay := 5 * time.Second
		maxReconnectDelay := 60 * time.Second
		currentDelay := reconnectDelay

		for {
			select {
			case <-ctx.Done():
				log8.BaseLogger.Info().Msgf("Consumer `%s` shutting down gracefully due to context cancellation", consumerName)
				return
			default:
				// Clean up any existing consumers for this queue before creating new one
				// This ensures we maintain only one consumer per queue
				existingConsumers := w.GetConsumersForQueue(queueName)
				if len(existingConsumers) > 0 {
					log8.BaseLogger.Info().Msgf("Found %d existing consumer(s) for queue `%s`: %v", len(existingConsumers), queueName, existingConsumers)
					for _, existingConsumer := range existingConsumers {
						log8.BaseLogger.Info().Msgf("Cancelling existing consumer `%s` for queue `%s`", existingConsumer, queueName)
						if cancelErr := w.CancelConsumer(existingConsumer); cancelErr != nil {
							log8.BaseLogger.Warn().Msgf("Failed to cancel existing consumer `%s`: %v", existingConsumer, cancelErr)
							// Continue anyway - we'll try to create the new consumer
						} else {
							log8.BaseLogger.Info().Msgf("Successfully cancelled existing consumer `%s`", existingConsumer)
						}
					}
				}

				// Generate unique consumer tag for each attempt to avoid RabbitMQ conflicts
				uniqueConsumerName := w.generateUniqueConsumerTag(consumerName)
				log8.BaseLogger.Debug().Msgf("Using unique consumer tag `%s` for queue `%s`", uniqueConsumerName, queueName)

				// Check if connection is healthy before attempting to consume
				if !w.IsConnected() {
					log8.BaseLogger.Warn().Msgf("Connection unhealthy for consumer `%s`, attempting to repair connection", uniqueConsumerName)

					// Try to repair the connection instead of getting a new one
					if err := w.repairConnection(); err != nil {
						log8.BaseLogger.Error().Msgf("Failed to repair connection for consumer `%s`: %v. Retrying in %v", uniqueConsumerName, err, currentDelay)
						time.Sleep(currentDelay)
						// Exponential backoff with max limit
						currentDelay = time.Duration(float64(currentDelay) * 1.5)
						if currentDelay > maxReconnectDelay {
							currentDelay = maxReconnectDelay
						}
						continue
					}

					log8.BaseLogger.Info().Msgf("Successfully repaired connection for consumer `%s`", uniqueConsumerName)
				}

				// Reset delay on successful connection
				currentDelay = reconnectDelay

				// Attempt to start consuming with unique consumer tag
				err := w.ConsumeWithContext(ctx, uniqueConsumerName, queueName, autoACK)
				if err != nil {
					log8.BaseLogger.Error().Msgf("Consumer `%s` for queue `%s` failed: %v. Reconnecting in %v", uniqueConsumerName, queueName, err, currentDelay)

					// Mark connection as unhealthy
					w.pooledConn.mu.Lock()
					w.pooledConn.isHealthy = false
					w.pooledConn.mu.Unlock()

					time.Sleep(currentDelay)
					// Exponential backoff with max limit
					currentDelay = time.Duration(float64(currentDelay) * 1.5)
					if currentDelay > maxReconnectDelay {
						currentDelay = maxReconnectDelay
					}
					continue
				}

				log8.BaseLogger.Info().Msgf("Consumer `%s` successfully started for queue `%s`", uniqueConsumerName, queueName)
				// Consumer successfully started - exit the retry loop
				return
			}
		}
	}()

	return nil
}

// generateUniqueConsumerTag creates a unique consumer tag to avoid RabbitMQ conflicts
func (w *PooledAmqp) generateUniqueConsumerTag(baseConsumerName string) string {
	timestamp := time.Now().UnixNano()
	random := rand.Int63()

	// If no base name is provided, use a default prefix
	if baseConsumerName == "" {
		baseConsumerName = "consumer"
	}

	return fmt.Sprintf("%s-%d-%d", baseConsumerName, timestamp, random)
}

// repairConnection attempts to repair the current connection instead of getting a new one
func (w *PooledAmqp) repairConnection() error {
	log8.BaseLogger.Info().Msg("Attempting to repair connection")

	w.pooledConn.mu.Lock()
	defer w.pooledConn.mu.Unlock()

	// Close existing connection and channel if they exist
	if w.pooledConn.channel != nil {
		w.pooledConn.channel.Close()
		w.pooledConn.channel = nil
	}
	if w.pooledConn.conn != nil {
		w.pooledConn.conn.Close()
		w.pooledConn.conn = nil
	}

	// Get connection string from pool configuration
	connString := w.pool.connString

	// Create new connection
	conn, err := amqp.Dial(connString)
	if err != nil {
		w.pooledConn.isHealthy = false
		return fmt.Errorf("failed to dial RabbitMQ: %w", err)
	}

	// Create new channel
	channel, err := conn.Channel()
	if err != nil {
		conn.Close()
		w.pooledConn.isHealthy = false
		return fmt.Errorf("failed to create channel: %w", err)
	}

	// Update the connection
	w.pooledConn.conn = conn
	w.pooledConn.channel = channel
	w.pooledConn.isHealthy = true
	w.pooledConn.lastUsed = time.Now()

	log8.BaseLogger.Info().Msg("Connection repaired successfully")
	return nil
}

// CloseConnection returns the connection to the pool instead of closing it
// Return the connection to the pool means setting the 'inUse' property to false.
// IT DOES NOT CLOSE ANY CONNECTION.
func (w *PooledAmqp) CloseConnection() {
	// For pooled connections, we return to pool instead of closing
	w.pool.Return(w)
	log8.BaseLogger.Debug().Msg("Returned pooled connection instead of closing")
}

// ReturnToPool explicitly returns the connection to the pool (clearer intent than CloseConnection).
// The function simply calls Return from connection_pool, which sets the property 'inUse' to 'false'
func (w *PooledAmqp) ReturnToPool() {
	w.pool.Return(w)
	// log8.BaseLogger.Debug().Msg("Explicitly returned pooled connection to pool")
}

// CloseChannel does NOTHING for pooled connections (channel is managed by pool).
// This method is basically here just to make PooledAmqp an implementation of PooledAmqpInterface
func (w *PooledAmqp) CloseChannel() {
	log8.BaseLogger.Debug().Msg("CloseChannel called on pooled connection - no action taken")
}

// Connection monitoring methods
func (w *PooledAmqp) IsConnected() bool {
	w.pooledConn.mu.RLock()
	defer w.pooledConn.mu.RUnlock()
	return w.pooledConn.isHealthy && w.pooledConn.conn != nil && !w.pooledConn.conn.IsClosed()
}

func (w *PooledAmqp) GetConnectionStatus() map[string]interface{} {
	w.pooledConn.mu.RLock()
	defer w.pooledConn.mu.RUnlock()

	status := map[string]interface{}{
		"is_healthy":     w.pooledConn.isHealthy,
		"in_use":         w.pooledConn.inUse,
		"usage_count":    w.pooledConn.usageCount,
		"created_at":     w.pooledConn.createdAt,
		"last_used":      w.pooledConn.lastUsed,
		"connection_nil": w.pooledConn.conn == nil,
		"channel_nil":    w.pooledConn.channel == nil,
	}

	if w.pooledConn.conn != nil {
		status["connection_closed"] = w.pooledConn.conn.IsClosed()
	}

	return status
}

// Consumer health monitoring methods (simplified for pooled connections)
func (w *PooledAmqp) registerConsumerHealth(consumerName, queueName string, autoACK bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	w.consumerHealth[consumerName] = &ConsumerHealth{
		ConsumerName: consumerName,
		QueueName:    queueName,
		AutoACK:      autoACK,
		IsActive:     true,
		LastSeen:     now,
		CreatedAt:    now,
	}

	// Track consumer in shared state for proper cleanup
	w.sharedState.AddConsumerToQueue(queueName, consumerName)
	log8.BaseLogger.Debug().Msgf("Consumer `%s` registered for queue `%s` in shared state", consumerName, queueName)
}

func (w *PooledAmqp) updateConsumerHealth(consumerName string, isActive bool, messageIncrement, errorIncrement uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if health, exists := w.consumerHealth[consumerName]; exists {
		health.IsActive = isActive
		health.MessageCount += messageIncrement
		health.ErrorCount += errorIncrement
		if isActive {
			health.LastSeen = time.Now()
		}
	}
}

func (w *PooledAmqp) updateConsumerLastSeen(consumerName string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if health, exists := w.consumerHealth[consumerName]; exists {
		health.LastSeen = time.Now()
		health.IsActive = true
	}
}

func (w *PooledAmqp) markConsumerInactive(consumerName string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if health, exists := w.consumerHealth[consumerName]; exists {
		health.IsActive = false
	}

	// Clean up consumer from shared state when it becomes inactive
	w.sharedState.DeleteConsumerByName(consumerName)
	log8.BaseLogger.Debug().Msgf("Consumer `%s` marked inactive and removed from shared state", consumerName)
}

func (w *PooledAmqp) GetConsumerHealth() map[string]*ConsumerHealth {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make(map[string]*ConsumerHealth)
	for name, health := range w.consumerHealth {
		healthCopy := *health
		result[name] = &healthCopy
	}
	return result
}

func (w *PooledAmqp) GetConsumerHealthByName(consumerName string) (*ConsumerHealth, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if health, exists := w.consumerHealth[consumerName]; exists {
		healthCopy := *health
		return &healthCopy, true
	}
	return nil, false
}

func (w *PooledAmqp) SetHealthCheckInterval(interval time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.healthCheckInterval = interval
}

// Context management methods (simplified for pooled connections)
func (w *PooledAmqp) ShutdownConsumer(consumerName string) error {
	return w.CancelConsumer(consumerName)
}

func (w *PooledAmqp) ShutdownAllConsumers() {
	w.mu.RLock()
	consumerNames := make([]string, 0, len(w.consumerHealth))
	for name := range w.consumerHealth {
		consumerNames = append(consumerNames, name)
	}
	w.mu.RUnlock()

	for _, name := range consumerNames {
		if err := w.ShutdownConsumer(name); err != nil {
			log8.BaseLogger.Error().Msgf("Error shutting down consumer %s: %v", name, err)
		}
	}
}

func (w *PooledAmqp) GetActiveConsumers() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var active []string
	for name, health := range w.consumerHealth {
		if health.IsActive {
			active = append(active, name)
		}
	}
	return active
}

func (w *PooledAmqp) IsConsumerActive(consumerName string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if health, exists := w.consumerHealth[consumerName]; exists {
		return health.IsActive
	}
	return false
}

// publishMessage publishes message directly or from a pooled connection
func (w *PooledAmqp) publishMessage(exchange, routingKey string, payload interface{}, source string) {
	// Try to use the current connection if healthy
	if w.IsConnected() {
		err := w.publishDirect(exchange, routingKey, payload, source)
		if err == nil {
			log8.BaseLogger.Info().Msgf("Failover message published successfully to %s with routing key %s", exchange, routingKey)
			return
		}
		log8.BaseLogger.Warn().Msgf("Failed to publish failover message using current connection: %v", err)
	}

	// If current connection failed, try to get a different connection from the pool
	err := WithPooledConnection(func(conn PooledAmqpInterface) error {
		return conn.Publish(exchange, routingKey, payload, source)
	})

	if err != nil {
		log8.BaseLogger.Error().Msgf("Failed to publish failover message to %s: %v", exchange, err)
	} else {
		log8.BaseLogger.Info().Msgf("Failover message published successfully using pool connection to %s with routing key %s", exchange, routingKey)
	}
}

// publishDirect publishes directly using the current connection
func (w *PooledAmqp) publishDirect(exchange, routingKey string, payload interface{}, source string) error {
	var body []byte
	var err error

	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}
	}

	// Create message
	msg := amqp.Publishing{
		ContentType:  "application/json",
		Body:         body,
		DeliveryMode: amqp.Persistent,
		Timestamp:    time.Now(),
		AppId:        source,
	}

	// Publish the message
	return w.pooledConn.channel.Publish(
		exchange,   // exchange
		routingKey, // routing key
		false,      // mandatory
		false,      // immediate
		msg,        // message
	)
}
