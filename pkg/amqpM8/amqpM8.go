package amqpM8

import (
	"context"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"
	"encoding/json"
	"fmt"
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

type AmqpM8Imp struct {
	conn      *amqp.Connection
	ch        *amqp.Channel
	queues    map[string]map[string]amqp.Queue // exchange name > queue name > queue object
	bindings  map[string]map[string][]string   // exchange name > queue name > binding keys
	exchanges map[string]string                // exchange name > exchange type
	consumers map[string][]string              // consumer name > queue name, autoack

	handler map[string]func(msg amqp.Delivery) error

	// Connection monitoring
	connClosed    chan *amqp.Error
	channelClosed chan *amqp.Error
	isConnected   bool
	mu            sync.RWMutex

	// Consumer health monitoring
	consumerHealth      map[string]*ConsumerHealth
	healthCheckInterval time.Duration
	healthCheckCtx      context.Context
	healthCheckCancel   context.CancelFunc

	// Consumer context management
	consumerContexts map[string]context.CancelFunc
}

func NewAmqpM8(location string, port int, username, password string) (AmqpM8Interface, error) {
	connString := fmt.Sprintf("amqp://%s:%s@%s:%d/", username, password, location, port)
	var conn *amqp.Connection
	for retries := 0; retries < 10; retries++ {
		log8.BaseLogger.Info().Msg("Connecting to RabbitMQ server ...")
		c, err := amqp.Dial(connString)
		if err == nil {
			conn = c
			break // Connection successful
		}
		if retries == 9 {
			log8.BaseLogger.Debug().Msg(err.Error())
			return nil, err
		}
		log8.BaseLogger.Warn().Msgf("Failed to connect to RabbitMQ (attempt %d/10): %v", retries+1, err)
		time.Sleep(5 * time.Second)
	}
	ch, err := conn.Channel()
	log8.BaseLogger.Info().Msg("Creating channel in the RabbitMQ server ...")
	if err != nil {
		// return nil, fmt.Errorf("failed to open a channel: %w", err)
		return nil, fmt.Errorf("failed to create channel: %w", err)
	}

	h := make(map[string]func(msg amqp.Delivery) error)
	e := make(map[string]string)
	q := make(map[string]map[string]amqp.Queue)
	b := make(map[string]map[string][]string)
	c := make(map[string][]string)

	// Create health check context
	healthCtx, healthCancel := context.WithCancel(context.Background())

	amqpInstance := &AmqpM8Imp{
		conn:                conn,
		ch:                  ch,
		exchanges:           e,
		queues:              q,
		bindings:            b,
		consumers:           c,
		handler:             h,
		connClosed:          make(chan *amqp.Error),
		channelClosed:       make(chan *amqp.Error),
		isConnected:         true,
		consumerHealth:      make(map[string]*ConsumerHealth),
		healthCheckInterval: 30 * time.Second,
		healthCheckCtx:      healthCtx,
		healthCheckCancel:   healthCancel,
		consumerContexts:    make(map[string]context.CancelFunc),
	}

	// Set up connection monitoring
	amqpInstance.setupConnectionMonitoring()

	// Start consumer health monitoring
	amqpInstance.startHealthMonitoring()

	return amqpInstance, nil
}

func (a *AmqpM8Imp) AddHandler(queueName string, handler func(msg amqp.Delivery) error) {
	a.handler[queueName] = handler
}

func (a *AmqpM8Imp) GetChannel() *amqp.Channel {
	return a.ch
}

func (a *AmqpM8Imp) GetQueues() map[string]map[string]amqp.Queue {
	return a.queues
}
func (a *AmqpM8Imp) GetBindings() map[string]map[string][]string {
	return a.bindings
}
func (a *AmqpM8Imp) GetExchanges() map[string]string {
	return a.exchanges
}

func (a *AmqpM8Imp) GetExchangeTypeByExchangeName(exchangeName string) string {
	return a.exchanges[exchangeName]
}

func (a *AmqpM8Imp) GetQueueByExchangeNameAndQueueName(exchangeName string, queuename string) amqp.Queue {
	return a.queues[exchangeName][queuename]
}

func (a *AmqpM8Imp) GetBindingsByExchangeNameAndQueueName(exchangeName string, queuename string) []string {
	return a.bindings[exchangeName][queuename]
}

func (a *AmqpM8Imp) GetConsumerByName(consumnerName string) []string {
	return a.consumers[consumnerName]
}

func (a *AmqpM8Imp) SetConsumers(c map[string][]string) {
	a.consumers = c
}

func (a *AmqpM8Imp) SetExchange(exchangeName string, exchangeType string) {
	a.exchanges[exchangeName] = exchangeType
}

func (a *AmqpM8Imp) SetQueueByExchangeName(exchangeName string, queueName string, queue amqp.Queue) {
	a.queues[exchangeName] = make(map[string]amqp.Queue)
	a.queues[exchangeName][queueName] = queue
}

func (a *AmqpM8Imp) SetBindingQueueByExchangeName(exchangeName string, queueName string, bindingKeys []string) {
	a.bindings[exchangeName] = make(map[string][]string)
	a.bindings[exchangeName][queueName] = bindingKeys
}

func (a *AmqpM8Imp) DeclareExchange(exchangeName string, exchangeType string) error {
	if exchangeName != "" && exchangeType != "" {
		log8.BaseLogger.Info().Msgf("Creating Exchange with name `%s`", exchangeName)
		err := a.ch.ExchangeDeclare(
			exchangeName, // name
			exchangeType, // type
			true,         // durable
			false,        // auto-deleted
			false,        // internal
			false,        // no-wait
			nil,          // arguments
		)
		if err != nil {
			return fmt.Errorf("failed to decleare an exchange: %w", err)
		}
	} else {
		return fmt.Errorf("exchange name and type cannot be empty")
	}
	log8.BaseLogger.Info().Msgf("Exchange successfully created with name `%s`", exchangeName)
	a.SetExchange(exchangeName, exchangeType)
	a.queues[exchangeName] = make(map[string]amqp.Queue)
	a.bindings[exchangeName] = make(map[string][]string)
	return nil
}

/*
AddQueue create one queue and bind the queue to the exchange with exchangeName and the bindingKey parameters.
queueName -> "" or string
bindingKey -> "" or string
queueArgs -> nil or Table
prefetchCount -> 0 or >1
*/
func (a *AmqpM8Imp) DeclareQueue(exchangeName string, queueName string, prefetchCount int, queueArgs amqp.Table) error {
	log8.BaseLogger.Info().Msgf("Creating and binding Queue with name `%s` in Exchange `%s`", queueName, exchangeName)
	q, err := a.ch.QueueDeclare(
		queueName, // name
		false,     // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		queueArgs, // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to decleare a Queue: %w", err)
	}
	log8.BaseLogger.Info().Msgf("Queue successfully created, with name `%s` in Exchange `%s`", queueName, exchangeName)
	if prefetchCount > 0 {
		log8.BaseLogger.Info().Msgf("Queue `%s` with Qos control due to prefetch value of `%d`", queueName, prefetchCount)
		err = a.ch.Qos(
			prefetchCount, // prefetch count
			0,             // prefetch size
			false,         // global
		)
		if err != nil {
			return fmt.Errorf("queue `%s` failed to set qos control: %w", queueName, err)
		}
	}
	a.SetQueueByExchangeName(exchangeName, queueName, q)
	return nil
}

func (a *AmqpM8Imp) BindQueue(exchangeName string, queueName string, bindingKeys []string) error {
	log8.BaseLogger.Info().Msgf("Binding Queue `%s` with Exchange `%s` and Binding key `%s`", queueName, exchangeName, bindingKeys)
	for _, bkey := range bindingKeys {
		err := a.ch.QueueBind(
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
	log8.BaseLogger.Info().Msgf("Success creating and binding Queue `%s` and Exchange `%s`", queueName, exchangeName)
	a.SetBindingQueueByExchangeName(exchangeName, queueName, bindingKeys)
	return nil
}

func (a *AmqpM8Imp) ExistQueue(queueName string, queueArgs amqp.Table) bool {
	log8.BaseLogger.Info().Msgf("Checking if queue `%s` exists", queueName)
	_, err := a.ch.QueueDeclarePassive(
		queueName, // name
		false,     // durable
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

func (a *AmqpM8Imp) DeleteQueue(queueName string) error {
	_, err := a.ch.QueueDelete(
		queueName, // name
		false,     // ifUnused
		false,     // IfEmpty
		false,     // noWait
	)
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Warn().Msgf("Queue `%s` cannot be deleted", queueName)
		return err
	}
	log8.BaseLogger.Info().Msgf("Queue `%s` deleted", queueName)
	return nil
}

func (a *AmqpM8Imp) CancelConsumer(consumerName string) error {
	err := a.ch.Cancel(consumerName, true)
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Warn().Msgf("Consumer `%s` cannot be cancelled", consumerName)
		return err
	}
	log8.BaseLogger.Info().Msgf("Consumer `%s` cancelled", consumerName)
	return nil
}

// if exchangeName and exchangeType are nil. RoutingKey acts as a Queue name.
func (a *AmqpM8Imp) Publish(exchangeName string, routingKey string, payload any, source string) error {
	msg := model8.AmqpM8Message{
		Channel:   routingKey,
		Payload:   payload,
		Timestamp: time.Now(),
		Source:    source,
	}
	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("publishing into exchange `%s` with routing key `%s` failed to msg json marshal the payload with error: %w", exchangeName, routingKey, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = a.ch.PublishWithContext(ctx,
		exchangeName, // exchange
		routingKey,   // routing key
		false,        // mandatory
		false,        //immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "application/json",
			Body:         bytes,
		},
	)

	return err
}

func (a *AmqpM8Imp) Consume(consumerName, queueName string, autoACK bool) error {
	// Use default context that can be cancelled during shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Store context cancel function for graceful shutdown
	a.mu.Lock()
	a.consumerContexts[consumerName] = cancel
	a.mu.Unlock()

	return a.ConsumeWithContext(ctx, consumerName, queueName, autoACK)
}

func (a *AmqpM8Imp) ConsumeWithContext(ctx context.Context, consumerName, queueName string, autoACK bool) error {

	msgs, err := a.ch.Consume(
		queueName,    // queue
		consumerName, // consumer
		autoACK,      // auto-ack
		false,        // exclusive
		false,        // no-local
		false,        // no-wait
		nil,          // args
	)
	if err != nil {
		a.updateConsumerHealth(consumerName, false, 0, 1)
		return fmt.Errorf("consumer creation failed for queue `%s`: %w", queueName, err)
	}

	log8.BaseLogger.Info().Msgf("Success with consumer creation for queue `%s`", queueName)

	// Register consumer health tracking
	a.registerConsumer(consumerName, queueName, autoACK)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log8.BaseLogger.Error().Msgf("Consumer panic recovered for queue `%s`: %v", queueName, r)
				a.updateConsumerHealth(consumerName, false, 0, 1)
			}
			a.markConsumerInactive(consumerName)
			a.removeConsumerContext(consumerName)
		}()

		for {
			select {
			case <-ctx.Done():
				log8.BaseLogger.Info().Msgf("Consumer `%s` shutting down gracefully due to context cancellation", consumerName)
				// Cancel the consumer to stop receiving new messages
				if err := a.CancelConsumer(consumerName); err != nil {
					log8.BaseLogger.Error().Msgf("Error cancelling consumer `%s`: %v", consumerName, err)
				}
				return

			case msg, ok := <-msgs:
				if !ok {
					log8.BaseLogger.Warn().Msgf("Consumer for queue `%s` stopped - message channel closed", queueName)
					return
				}

				// Update last seen timestamp
				a.updateConsumerLastSeen(consumerName)

				// Process each msg with error handling
				if handler := a.handler[queueName]; handler != nil {
					if err := handler(msg); err != nil {
						log8.BaseLogger.Error().Msgf("Handler error for queue `%s`: %v", queueName, err)
						a.updateConsumerHealth(consumerName, true, 1, 1)
					} else {
						a.updateConsumerHealth(consumerName, true, 1, 0)
					}
				} else {
					log8.BaseLogger.Warn().Msgf("No handler found for queue `%s`", queueName)
					a.updateConsumerHealth(consumerName, true, 1, 1)
				}

				if !autoACK {
					msg.Ack(false)
				}
			}
		}
	}()

	return nil
}

func (a *AmqpM8Imp) CloseConnection() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.isConnected = false

	log8.BaseLogger.Info().Msg("Initiating graceful shutdown of RabbitMQ connection")

	// Gracefully shutdown all consumers
	a.shutdownAllConsumers()

	// Stop health monitoring
	if a.healthCheckCancel != nil {
		a.healthCheckCancel()
	}

	if a.conn != nil {
		a.conn.Close()
	}

	log8.BaseLogger.Info().Msg("RabbitMQ connection closed")
}

func (a *AmqpM8Imp) CloseChannel() {
	if a.ch != nil {
		a.ch.Close()
	}
}

// setupConnectionMonitoring sets up monitoring for connection and channel closures
func (a *AmqpM8Imp) setupConnectionMonitoring() {
	if a.conn != nil {
		a.conn.NotifyClose(a.connClosed)
	}
	if a.ch != nil {
		a.ch.NotifyClose(a.channelClosed)
	}

	go a.monitorConnection()
}

// monitorConnection monitors connection and channel state
func (a *AmqpM8Imp) monitorConnection() {
	for {
		select {
		case err := <-a.connClosed:
			a.mu.Lock()
			a.isConnected = false
			a.mu.Unlock()

			if err != nil {
				log8.BaseLogger.Error().Msgf("RabbitMQ connection closed unexpectedly: %v", err)
			} else {
				log8.BaseLogger.Info().Msg("RabbitMQ connection closed gracefully")
			}
			return // Exit monitoring when connection closes

		case err := <-a.channelClosed:
			if err != nil {
				log8.BaseLogger.Error().Msgf("RabbitMQ channel closed unexpectedly: %v", err)
			} else {
				log8.BaseLogger.Info().Msg("RabbitMQ channel closed gracefully")
			}
			// Channel can be recreated without closing connection monitoring
		}
	}
}

// IsConnected returns the current connection status
func (a *AmqpM8Imp) IsConnected() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.isConnected && a.conn != nil && !a.conn.IsClosed()
}

// GetConnectionStatus returns detailed connection information
func (a *AmqpM8Imp) GetConnectionStatus() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := map[string]interface{}{
		"is_connected":   a.isConnected,
		"connection_nil": a.conn == nil,
		"channel_nil":    a.ch == nil,
	}

	if a.conn != nil {
		status["connection_closed"] = a.conn.IsClosed()
	}

	return status
}

// Consumer Health Monitoring Methods

// registerConsumer adds a consumer to health tracking
func (a *AmqpM8Imp) registerConsumer(consumerName, queueName string, autoACK bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	if health, exists := a.consumerHealth[consumerName]; exists {
		health.RestartCount++
		health.LastSeen = now
		health.IsActive = true
	} else {
		a.consumerHealth[consumerName] = &ConsumerHealth{
			ConsumerName: consumerName,
			QueueName:    queueName,
			AutoACK:      autoACK,
			IsActive:     true,
			LastSeen:     now,
			CreatedAt:    now,
		}
	}

	log8.BaseLogger.Info().Msgf("Registered consumer `%s` for health monitoring", consumerName)
}

// updateConsumerHealth updates consumer metrics
func (a *AmqpM8Imp) updateConsumerHealth(consumerName string, isActive bool, messageIncrement, errorIncrement uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if health, exists := a.consumerHealth[consumerName]; exists {
		health.IsActive = isActive
		health.MessageCount += messageIncrement
		health.ErrorCount += errorIncrement
		if isActive {
			health.LastSeen = time.Now()
		}
	}
}

// updateConsumerLastSeen updates the last seen timestamp
func (a *AmqpM8Imp) updateConsumerLastSeen(consumerName string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if health, exists := a.consumerHealth[consumerName]; exists {
		health.LastSeen = time.Now()
		health.IsActive = true
	}
}

// markConsumerInactive marks a consumer as inactive
func (a *AmqpM8Imp) markConsumerInactive(consumerName string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if health, exists := a.consumerHealth[consumerName]; exists {
		health.IsActive = false
		log8.BaseLogger.Warn().Msgf("Consumer `%s` marked as inactive", consumerName)
	}
}

// startHealthMonitoring starts the health check routine
func (a *AmqpM8Imp) startHealthMonitoring() {
	go func() {
		ticker := time.NewTicker(a.healthCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-a.healthCheckCtx.Done():
				log8.BaseLogger.Info().Msg("Consumer health monitoring stopped")
				return
			case <-ticker.C:
				a.performHealthChecks()
			}
		}
	}()

	log8.BaseLogger.Info().Msgf("Started consumer health monitoring (interval: %v)", a.healthCheckInterval)
}

// performHealthChecks checks the health of all consumers
func (a *AmqpM8Imp) performHealthChecks() {
	a.mu.RLock()
	consumers := make(map[string]*ConsumerHealth)
	for name, health := range a.consumerHealth {
		consumers[name] = health
	}
	a.mu.RUnlock()

	now := time.Now()
	staleThreshold := 2 * a.healthCheckInterval

	for consumerName, health := range consumers {
		timeSinceLastSeen := now.Sub(health.LastSeen)

		if health.IsActive && timeSinceLastSeen > staleThreshold {
			log8.BaseLogger.Warn().Msgf(
				"Consumer `%s` appears stale - last seen %v ago (threshold: %v)",
				consumerName, timeSinceLastSeen, staleThreshold,
			)
			a.markConsumerInactive(consumerName)
		}

		// Log periodic health summary for active consumers
		if health.IsActive {
			log8.BaseLogger.Debug().Msgf(
				"Consumer `%s` health: messages=%d, errors=%d, restarts=%d, last_seen=%v",
				consumerName, health.MessageCount, health.ErrorCount, health.RestartCount,
				timeSinceLastSeen.Round(time.Second),
			)
		}
	}
}

// GetConsumerHealth returns health information for all consumers
func (a *AmqpM8Imp) GetConsumerHealth() map[string]*ConsumerHealth {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make(map[string]*ConsumerHealth)
	for name, health := range a.consumerHealth {
		// Create a copy to avoid race conditions
		healthCopy := *health
		result[name] = &healthCopy
	}

	return result
}

// GetConsumerHealthByName returns health information for a specific consumer
func (a *AmqpM8Imp) GetConsumerHealthByName(consumerName string) (*ConsumerHealth, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if health, exists := a.consumerHealth[consumerName]; exists {
		healthCopy := *health
		return &healthCopy, true
	}

	return nil, false
}

// SetHealthCheckInterval allows customizing the health check frequency
func (a *AmqpM8Imp) SetHealthCheckInterval(interval time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.healthCheckInterval = interval
	log8.BaseLogger.Info().Msgf("Health check interval updated to %v", interval)
}

// Context Management Methods

// removeConsumerContext removes a consumer's context cancel function
func (a *AmqpM8Imp) removeConsumerContext(consumerName string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.consumerContexts, consumerName)
}

// shutdownAllConsumers gracefully shuts down all active consumers
func (a *AmqpM8Imp) shutdownAllConsumers() {
	log8.BaseLogger.Info().Msgf("Shutting down %d active consumers", len(a.consumerContexts))

	// Cancel all consumer contexts
	for consumerName, cancel := range a.consumerContexts {
		log8.BaseLogger.Info().Msgf("Shutting down consumer: %s", consumerName)
		cancel()
	}

	// Wait a short time for graceful shutdown
	time.Sleep(1 * time.Second)

	// Clear the contexts map
	a.consumerContexts = make(map[string]context.CancelFunc)
}

// ShutdownConsumer gracefully shuts down a specific consumer
func (a *AmqpM8Imp) ShutdownConsumer(consumerName string) error {
	a.mu.Lock()
	cancel, exists := a.consumerContexts[consumerName]
	a.mu.Unlock()

	if !exists {
		return fmt.Errorf("consumer `%s` not found or already shutdown", consumerName)
	}

	log8.BaseLogger.Info().Msgf("Initiating graceful shutdown for consumer: %s", consumerName)
	cancel()

	return nil
}

// ShutdownAllConsumers provides external access to graceful consumer shutdown
func (a *AmqpM8Imp) ShutdownAllConsumers() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.shutdownAllConsumers()
}

// GetActiveConsumers returns a list of currently active consumer names
func (a *AmqpM8Imp) GetActiveConsumers() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	consumers := make([]string, 0, len(a.consumerContexts))
	for consumerName := range a.consumerContexts {
		consumers = append(consumers, consumerName)
	}

	return consumers
}

// IsConsumerActive checks if a specific consumer is currently active
func (a *AmqpM8Imp) IsConsumerActive(consumerName string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	_, exists := a.consumerContexts[consumerName]
	return exists
}
