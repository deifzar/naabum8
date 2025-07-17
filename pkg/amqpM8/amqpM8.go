package amqpM8

import (
	"context"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"
	"encoding/json"
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

type AmqpM8Imp struct {
	conn      *amqp.Connection
	ch        *amqp.Channel
	queues    map[string]map[string]amqp.Queue // exchange name > queue name > queue object
	bindings  map[string]map[string][]string   // exchange name > queue name > binding keys
	exchanges map[string]string                // exchange name > exchange type
	consumers map[string][]string              // consumer name > queue name, autoack

	handler map[string]func(msg amqp.Delivery) error
}

func NewAmqpM8(location string, port int, username, password string) (AmqpM8Interface, error) {
	connString := fmt.Sprintf("amqp://%s:%s@%s:%d/", username, password, location, port)
	conn, err := amqp.Dial(connString)
	log8.BaseLogger.Info().Msg("Connecting to RabbitMQ server ...")
	if err != nil {
		// return nil, fmt.Errorf("failed to connect to amqp server: %w", err)
		return nil, err
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

	return &AmqpM8Imp{conn: conn, ch: ch, exchanges: e, queues: q, bindings: b, consumers: c, handler: h}, nil
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
		return fmt.Errorf("consumer creation failed for queue `%s`: %w", queueName, err)
	}

	log8.BaseLogger.Info().Msgf("Success with consumer creation for queue `%s`", queueName)

	var forever chan struct{}

	go func() {
		for msg := range msgs {
			// Process each msg
			handler := a.handler[queueName]
			handler(msg)
			if !autoACK {
				msg.Ack(false)
				// msg.Nack(false,true)
			}
		}
	}()

	<-forever

	return nil
}

func (a *AmqpM8Imp) CloseConnection() {
	a.conn.Close()
}

func (a *AmqpM8Imp) CloseChannel() {
	a.ch.Close()
}
