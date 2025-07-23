package orchestrator8

import (
	"bytes"
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
	Amqp   amqpM8.AmqpM8Interface
	Config *viper.Viper
}

func NewOrchestrator8() (Orchestrator8Interface, error) {

	v, err := configparser.InitConfigParser()
	if err != nil {
		return &Orchestrator8{}, err
	}

	location := v.GetString("RabbitMQ.location")
	port := v.GetInt("RabbitMQ.port")
	username := v.GetString("RabbitMQ.username")
	password := v.GetString("RabbitMQ.password")

	am8, err := amqpM8.NewAmqpM8(location, port, username, password)
	// defer am8.CloseConnection()
	// defer am8.CloseChannel()
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		return &Orchestrator8{}, err
	}

	o := &Orchestrator8{Amqp: am8, Config: v}
	return o, nil
}

func (o *Orchestrator8) InitOrchestrator() error {
	exchanges := o.Config.GetStringMapString("ORCHESTRATORM8.Exchanges")

	for exname, extype := range exchanges {
		err := o.Amqp.DeclareExchange(exname, extype)
		if err != nil {
			log8.BaseLogger.Debug().Msg(err.Error())
			return err
		}
	}
	return nil
}

func (o *Orchestrator8) GetAmqp() amqpM8.AmqpM8Interface {
	return o.Amqp
}

// This method defines the actions that customers carry when messages get published to the `cptm8` exchange.
func (o *Orchestrator8) CreateHandleAPICallByService(service string) {
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
	queue := o.Config.GetStringSlice("ORCHESTRATORM8." + service + ".Consumer")
	o.Amqp.AddHandler(queue[0], handle)
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
	err = o.Amqp.DeclareQueue(queue[0], queue[1], prefetch_count, qargs)
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		return err
	}
	err = o.Amqp.BindQueue(queue[0], queue[1], bindingkeys)
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		return err
	}
	return nil
}

func (o *Orchestrator8) ActivateConsumerByService(service string) {
	log8.BaseLogger.Info().Msgf("Creating consumer for `%s` ...", service)
	params := o.Config.GetStringSlice("ORCHESTRATORM8." + service + ".Consumer")
	go func(p []string) {
		qname := p[0]
		cname := p[1]
		autoACK, err := strconv.ParseBool(p[2])
		if err != nil {
			log8.BaseLogger.Warn().Msgf("setting autoACK to `false` due to failure parsing config autoACK value from queue `%s`", qname)
			autoACK = true
		}
		err = o.Amqp.Consume(cname, qname, autoACK)
		if err != nil {
			log8.BaseLogger.Debug().Msg(err.Error())
			log8.BaseLogger.Error().Msgf("error creating consumer for queue `%s`", qname)
		} else {
			log8.BaseLogger.Info().Msgf("Created consumer for queue `%s`", qname)
		}
	}(params)
}

func (o *Orchestrator8) DeactivateConsumerByService(service string) error {
	log8.BaseLogger.Info().Msgf("Deactivating consumer for `%s` ...", service)
	params := o.Config.GetStringSlice("ORCHESTRATORM8." + service + ".Consumer")
	err := o.Amqp.CancelConsumer(params[1])
	return err
}

func (o *Orchestrator8) PublishToExchangeAndCloseChannelConnection(exchange string, routingkey string, payload any, source string) error {
	defer o.Amqp.CloseConnection()
	defer o.Amqp.CloseChannel()
	if exchange != "" && routingkey != "" {
		err := o.Amqp.Publish(exchange, routingkey, payload, source)
		if err != nil {
			log8.BaseLogger.Debug().Msg(err.Error())
			log8.BaseLogger.Error().Msgf("RabbitMQ publishing message `%s` failed!", payload)
			return err
		}
		log8.BaseLogger.Info().Msgf("RabbitMQ publishing message `%s` success!", payload)
		return nil
	} else {
		err := errors.New("impossible to route message to RabbitMQ. Missing paramaters such as exchange and routing key details")
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Error().Msg("RabbitMQ publishing message has failed due to missing exchange and routing key parameters!")
		return err
	}
}

func (o *Orchestrator8) PublishToExchangeAndActivateConsumerByService(service string, exchange string, routingkey string, payload any, source string) error {
	if service != "" && exchange != "" && routingkey != "" {
		err := o.Amqp.Publish(exchange, routingkey, payload, source)
		if err != nil {
			log8.BaseLogger.Debug().Msg(err.Error())
			log8.BaseLogger.Error().Msgf("RabbitMQ publishing message `%s` failed!", payload)
			return err
		}
		log8.BaseLogger.Info().Msgf("RabbitMQ publishing message `%s` success!", payload)
		// Activate queue and consumer but do not close the connection so the consumer remains active
		o.ActivateQueueByService(service)
		o.CreateHandleAPICallByService(service)
		o.ActivateConsumerByService(service)
		return nil
	} else {
		err := errors.New("impossible to route message to RabbitMQ. Missing paramaters such as exchange and routing key details")
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Error().Msg("RabbitMQ publishing message has failed due to missing exchange and routing key parameters!")
		return err
	}
}
