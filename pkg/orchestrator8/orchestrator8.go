package orchestrator8

import (
	"bytes"
	"context"
	amqpM8 "deifzar/naabum8/pkg/amqpM8"
	"deifzar/naabum8/pkg/configparser"
	"deifzar/naabum8/pkg/log8"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/spf13/viper"
)

type Orchestrator8 struct {
	// Amqp   amqpM8.PooledAmqpInterface
	Config *viper.Viper
}

// NewOrchestrator8 creates a new orchestrator using connection pool
func NewOrchestrator8() (Orchestrator8Interface, error) {
	v, err := configparser.InitConfigParser()
	if err != nil {
		return &Orchestrator8{}, err
	}

	// Try to initialize the default pool (will do nothing if already exists)
	manager := amqpM8.GetGlobalPoolManager()
	poolExists := false
	for _, poolName := range manager.ListPools() {
		if poolName == "default" {
			poolExists = true
			break
		}
	}

	if !poolExists {
		err = amqpM8.InitializeConnectionPool()
		if err != nil {
			log8.BaseLogger.Debug().Msg(err.Error())
			return &Orchestrator8{}, err
		}
	}

	o := &Orchestrator8{Config: v}
	return o, nil
}

func (o *Orchestrator8) InitOrchestrator() error {
	exchanges := o.Config.GetStringMapString("ORCHESTRATORM8.Exchanges")

	return amqpM8.WithPooledConnection(func(am8 amqpM8.PooledAmqpInterface) error {
		for exname, extype := range exchanges {
			err := am8.DeclareExchange(exname, extype)
			if err != nil {
				log8.BaseLogger.Debug().Msg(err.Error())
				return err
			}
		}
		return nil
	})
}

func (o *Orchestrator8) ExistQueue(queueName string, queueArgs amqp.Table) bool {
	var exists bool

	err := amqpM8.WithPooledConnection(func(am8 amqpM8.PooledAmqpInterface) error {
		exists = am8.ExistQueue(queueName, queueArgs)
		return nil
	})

	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Error().Msgf("Error checking if queue `%s` exists", queueName)
		return false
	}

	return exists
}

func (o *Orchestrator8) ExistConsumersForQueue(queueName string, queueArgs amqp.Table) bool {
	var exists bool

	err := amqpM8.WithPooledConnection(func(am8 amqpM8.PooledAmqpInterface) error {
		c := am8.GetNumberOfActiveConsumersByQueue(queueName, queueArgs)
		exists = c > 0
		return nil
	})

	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Error().Msgf("Error checking if consumers exist for queue `%s`", queueName)
		return false
	}

	return exists
}

func (o *Orchestrator8) CreateHandleAPICallByService(service string) error {
	_, err := o.createHandleAPICallByServiceWithConnection(service)
	return err
}

func (o *Orchestrator8) createHandleAPICallByServiceWithConnection(service string) (amqpM8.PooledAmqpInterface, error) {
	handle := func(msg amqp.Delivery) error {
		services := o.Config.GetStringMapString("ORCHESTRATORM8.Services")
		routingKey := msg.RoutingKey // cptm8.asmm8.get.scan. or cptm.asmm8.post.scan or cptm8.naabum8.get.scan/domain/1337 or cptm8.num8.post.endpoint/17/scan
		instructions := strings.Split(routingKey, ".")
		log8.BaseLogger.Info().Msgf("RabbitMQ - Message received with routing key '%s'", routingKey)
		requestURL := fmt.Sprintf("%s/%s", services[instructions[1]], instructions[3])
		httpMethod := strings.ToLower(instructions[2])
		switch httpMethod {
		case "get":
			_, err := http.Get(requestURL)
			if err != nil {
				log8.BaseLogger.Debug().Msg(err.Error())
				log8.BaseLogger.Warn().Msgf("rabbitMQ - handler for routing key `%s` - Error making the HTTP request: %s.", routingKey, requestURL)
				return err
			}
		case "post":
			reader := bytes.NewReader(msg.Body)
			_, err := http.Post(requestURL, "application/json", reader)
			if err != nil {
				log8.BaseLogger.Debug().Msg(err.Error())
				log8.BaseLogger.Warn().Msgf("rabbitMQ - handler for routing key `%s` - Error making the HTTP request: %s.", routingKey, requestURL)
				return err
			}
		default:
			log8.BaseLogger.Warn().Msgf("rabbitMQ - handler for routing key `%s` - Empty HTTP request.", routingKey)
		}
		log8.BaseLogger.Info().Msgf("RabbitMQ - handler for routing key `%s` - Success with HTTP request: %s.", routingKey, requestURL)
		return nil
	}

	// Get a dedicated connection for the consumer (consumers need long-lived connections)
	am8, err := amqpM8.GetDefaultConnection()
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Error().Msgf("Failed to get dedicated connection for service `%s`", service)
		return nil, err
	}

	queue := o.Config.GetStringSlice("ORCHESTRATORM8." + service + ".Consumer")[0]
	am8.AddHandler(queue, handle)
	log8.BaseLogger.Info().Msgf("Handler registered for queue `%s` on dedicated connection", queue)

	return am8, nil
}

func (o *Orchestrator8) ActivateQueueByService(service string) error {
	queue := o.Config.GetStringSlice("ORCHESTRATORM8." + service + ".Queue")
	bindingkeys := o.Config.GetStringSlice("ORCHESTRATORM8." + service + ".Routing-keys")
	qargs := o.Config.GetStringMap("ORCHESTRATORM8." + service + ".Queue-arguments")
	prefetch_count, err := strconv.Atoi(queue[2])
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		return err
	}

	return amqpM8.WithPooledConnection(func(am8 amqpM8.PooledAmqpInterface) error {
		err := am8.DeclareQueue(queue[0], queue[1], prefetch_count, qargs)
		if err != nil {
			log8.BaseLogger.Debug().Msg(err.Error())
			return err
		}
		err = am8.BindQueue(queue[0], queue[1], bindingkeys)
		if err != nil {
			log8.BaseLogger.Debug().Msg(err.Error())
			return err
		}
		return nil
	})
}

func (o *Orchestrator8) ActivateConsumerByService(service string) error {
	// Use the new method with auto-reconnect for better reliability
	conn, err := o.createHandleAPICallByServiceWithConnection(service)
	if err != nil {
		return err
	}
	return o.activateConsumerByServiceWithReconnect(service, conn)
}

func (o *Orchestrator8) activateConsumerByServiceWithReconnect(service string, conn amqpM8.PooledAmqpInterface) error {
	log8.BaseLogger.Info().Msgf("Creating consumer with auto-reconnect for `%s` using existing connection...", service)
	params := o.Config.GetStringSlice("ORCHESTRATORM8." + service + ".Consumer")

	// Create a context that can be cancelled for graceful shutdown
	ctx := context.Background()

	qname := params[0]
	cname := params[0] // ConsumeWithReconnect generate unique consumer name using this value as a prefix
	autoACK, err := strconv.ParseBool(params[2])
	if err != nil {
		log8.BaseLogger.Warn().Msgf("setting autoACK to `true` due to failure parsing config autoACK value from queue `%s`", qname)
		autoACK = true
	}

	err = conn.ConsumeWithReconnect(ctx, cname, qname, autoACK)
	if err != nil {
		log8.BaseLogger.Error().Msgf("error creating consumer with auto-reconnect for queue `%s`", qname)
		return err
	}

	log8.BaseLogger.Info().Msgf("Created consumer with auto-reconnect for queue `%s` using existing connection", qname)
	return nil
}

// PublishToExchange uses the connection pool to publish a message
func (o *Orchestrator8) PublishToExchange(exchange string, routingkey string, payload any, source string) error {
	if exchange == "" || routingkey == "" {
		err := errors.New("impossible to route message to RabbitMQ. Missing parameters such as exchange and routing key details")
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Error().Msg("RabbitMQ publishing message has failed due to missing exchange and routing key parameters!")
		return err
	}

	return amqpM8.WithPooledConnection(func(conn amqpM8.PooledAmqpInterface) error {
		err := conn.Publish(exchange, routingkey, payload, source)
		if err != nil {
			log8.BaseLogger.Debug().Msg(err.Error())
			log8.BaseLogger.Error().Msgf("RabbitMQ publishing message `%s` failed!", payload)
			return err
		}
		log8.BaseLogger.Info().Msgf("RabbitMQ publishing message `%s` success!", payload)
		return nil
	})
}
