package orchestrator8

// It's advisable to use separate connections for Channel.Publish and Channel.Consume
// so not to have TCP pushback on publishing affect the ability to consume messages, so this parameter is here mostly for completeness.

import amqpM8 "deifzar/naabum8/pkg/amqpM8"

type Orchestrator8Interface interface {
	InitOrchestrator() error
	GetAmqp() amqpM8.AmqpM8Interface
	CreateHandleAPICallByService(service string)
	ActivateQueueByService(service string) error
	ActivateConsumerByService(service string)
	PublishToExchangeAndCloseChannelConnection(exchange string, routingkey string, payload any, source string) error
	PublishToExchangeAndActivateConsumerByService(service string, exchange string, routingkey string, payload any, source string) error
	DeactivateConsumerByService(service string) error
	// BuildHandlers()
	// BuildConsumers()
}
