package amqpM8

import (
	amqp "github.com/rabbitmq/amqp091-go"
)

type AmqpM8Interface interface {
	AddHandler(queueName string, handler func(msg amqp.Delivery) error)
	GetChannel() *amqp.Channel
	GetQueues() map[string]map[string]amqp.Queue
	GetBindings() map[string]map[string][]string
	GetExchanges() map[string]string
	GetExchangeTypeByExchangeName(exchangeName string) string
	GetQueueByExchangeNameAndQueueName(exchangeName string, queuename string) amqp.Queue
	GetBindingsByExchangeNameAndQueueName(exchangeName string, queuename string) []string
	GetConsumerByName(consumnerName string) []string
	SetExchange(exchangeName string, exchangeType string)
	SetQueueByExchangeName(exchangeName string, queueName string, queue amqp.Queue)
	SetBindingQueueByExchangeName(exchangeName string, queueName string, bindingKeys []string)
	SetConsumers(c map[string][]string)
	DeclareExchange(exchangeName string, exchangeType string) error
	DeclareQueue(exchangeName string, queueName string, prefetchCount int, queueArgs amqp.Table) error
	BindQueue(exchangeName string, queueName string, bindingKeys []string) error
	Publish(exchangeName string, routingKey string, payload any) error
	Consume(consumerName, queueName string, autoACK bool) error
	ExistQueue(queueName string, queueArgs amqp.Table) bool
	DeleteQueue(queueName string) error
	CancelConsumer(consumerName string) error
	CloseConnection()
	CloseChannel()
}
