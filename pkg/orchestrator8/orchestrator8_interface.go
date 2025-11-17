package orchestrator8

import (
	amqpM8 "deifzar/naabum8/pkg/amqpM8"

	amqp "github.com/rabbitmq/amqp091-go"
)

type Orchestrator8Interface interface {
	// Brings up the RabbitMQ Exchanges declared in the configuration yaml file
	InitOrchestrator() error
	// This method defines the actions that customers carry when messages get published to the `cptm8` exchange.
	CreateHandleAPICallByService(service string) error
	// New method that returns a dedicated connection with handler registered
	createHandleAPICallByServiceWithConnection(service string) (amqpM8.PooledAmqpInterface, error)
	// AckScanCompletion acknowledges a scan message based on completion status
	AckScanCompletion(deliveryTag uint64, scanCompleted bool) error
	// NackScanMessage rejects a scan message without requeue (send to DLQ if configured)
	NackScanMessage(deliveryTag uint64, requeue bool) error
	// New method that uses existing connection with auto-reconnect
	activateConsumerByServiceWithReconnect(service string, conn amqpM8.PooledAmqpInterface) error
	ActivateQueueByService(service string) error
	ActivateConsumerByService(service string) error
	// PublishToExchange uses the connection pool to publish a message
	PublishToExchange(exchange string, routingkey string, payload any, source string) error
	ExistQueue(queueName string, queueArgs amqp.Table) bool
	ExistConsumersForQueue(queueName string, queueArgs amqp.Table) bool
	// BuildHandlers()
	// BuildConsumers()
}
