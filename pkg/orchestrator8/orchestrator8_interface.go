package orchestrator8

import amqp "github.com/rabbitmq/amqp091-go"

type Orchestrator8Interface interface {
	// Brings up the RabbitMQ Exchanges declared in the configuration yaml file
	InitOrchestrator() error
	// This method defines the actions that customers carry when messages get published to the `cptm8` exchange.
	CreateHandleAPICallByService(service string) error
	ActivateQueueByService(service string) error
	ActivateConsumerByService(service string) error
	DeactivateConsumerByService(service string) error
	PublishToExchange(exchange string, routingkey string, payload any, source string) error
	PublishToExchangeAndActivateConsumerByService(service string, exchange string, routingkey string, payload any, source string) error
	ExistQueue(queueName string, queueArgs amqp.Table) bool
	// BuildHandlers()
	// BuildConsumers()
}
