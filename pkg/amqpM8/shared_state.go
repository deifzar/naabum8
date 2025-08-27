package amqpM8

import (
	"sync"

	amqp "github.com/rabbitmq/amqp091-go"
)

// SharedAmqpState manages shared state across all pooled AMQP connections
type SharedAmqpState struct {
	mu        sync.RWMutex
	queues    map[string]map[string]amqp.Queue         // [exchange_name][queue_name] Queue Object
	bindings  map[string]map[string][]string           // [exchange_name][queue_name][binding_keys ...]
	exchanges map[string]string                        // [exchange_name]exchange_type
	consumers map[string][]string                      // [queue_name][consumer_name ...]
	handlers  map[string]func(msg amqp.Delivery) error // [queue_name] func
}

// Global shared state instance
var globalSharedState *SharedAmqpState
var sharedStateOnce sync.Once

// GetSharedState returns the global shared state instance (singleton)
func GetSharedState() *SharedAmqpState {
	sharedStateOnce.Do(func() {
		globalSharedState = &SharedAmqpState{
			queues:    make(map[string]map[string]amqp.Queue),
			bindings:  make(map[string]map[string][]string),
			exchanges: make(map[string]string),
			consumers: make(map[string][]string),
			handlers:  make(map[string]func(msg amqp.Delivery) error),
		}
	})
	return globalSharedState
}

// Queue management methods
func (s *SharedAmqpState) GetQueues() map[string]map[string]amqp.Queue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to prevent external modification
	result := make(map[string]map[string]amqp.Queue)
	for exchangeName, queues := range s.queues {
		result[exchangeName] = make(map[string]amqp.Queue)
		for queueName, queue := range queues {
			result[exchangeName][queueName] = queue
		}
	}
	return result
}

func (s *SharedAmqpState) SetQueueByExchangeName(exchangeName string, queueName string, queue amqp.Queue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queues[exchangeName] == nil {
		s.queues[exchangeName] = make(map[string]amqp.Queue)
	}
	s.queues[exchangeName][queueName] = queue
}

func (s *SharedAmqpState) GetQueueByExchangeNameAndQueueName(exchangeName string, queueName string) amqp.Queue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if exchangeQueues, exists := s.queues[exchangeName]; exists {
		return exchangeQueues[queueName]
	}
	return amqp.Queue{}
}

// Binding management methods
func (s *SharedAmqpState) GetBindings() map[string]map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to prevent external modification
	result := make(map[string]map[string][]string)
	for exchangeName, bindings := range s.bindings {
		result[exchangeName] = make(map[string][]string)
		for queueName, bindingKeys := range bindings {
			result[exchangeName][queueName] = append([]string(nil), bindingKeys...)
		}
	}
	return result
}

func (s *SharedAmqpState) SetBindingQueueByExchangeName(exchangeName string, queueName string, bindingKeys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bindings[exchangeName] == nil {
		s.bindings[exchangeName] = make(map[string][]string)
	}
	s.bindings[exchangeName][queueName] = append([]string(nil), bindingKeys...)
}

func (s *SharedAmqpState) GetBindingsByExchangeNameAndQueueName(exchangeName string, queueName string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if exchangeBindings, exists := s.bindings[exchangeName]; exists {
		return append([]string(nil), exchangeBindings[queueName]...)
	}
	return nil
}

// Exchange management methods
func (s *SharedAmqpState) GetExchanges() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to prevent external modification
	result := make(map[string]string)
	for name, exchangeType := range s.exchanges {
		result[name] = exchangeType
	}
	return result
}

func (s *SharedAmqpState) SetExchange(exchangeName string, exchangeType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exchanges[exchangeName] = exchangeType
}

func (s *SharedAmqpState) GetExchangeTypeByExchangeName(exchangeName string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exchanges[exchangeName]
}

// Handler management methods
func (s *SharedAmqpState) AddHandler(queueName string, handler func(msg amqp.Delivery) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[queueName] = handler
}

func (s *SharedAmqpState) GetHandler(queueName string) (func(msg amqp.Delivery) error, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	handler, exists := s.handlers[queueName]
	return handler, exists
}

func (s *SharedAmqpState) GetConsumerByName(consumerName string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.consumers[consumerName]
}

func (s *SharedAmqpState) SetConsumers(c map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consumers = c
}

func (s *SharedAmqpState) AddConsumerToQueue(queueName, consumerName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumers[queueName] == nil {
		s.consumers[queueName] = make([]string, 0)
	}
	s.consumers[queueName] = append(s.consumers[queueName], consumerName)
}

func (s *SharedAmqpState) GetConsumersForQueue(queueName string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if consumers, exists := s.consumers[queueName]; exists {
		// Return a copy to prevent external modification
		result := make([]string, len(consumers))
		copy(result, consumers)
		return result
	}
	return nil
}

func (s *SharedAmqpState) DeleteQueueByName(qname string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bindingsAux := make(map[string]map[string][]string)
	queuesAux := make(map[string]map[string]amqp.Queue)
	consumersAux := make(map[string][]string)
	handlersAux := make(map[string]func(msg amqp.Delivery) error)

	for exchange, queues := range s.bindings {
		bindingsAux[exchange] = make(map[string][]string)
		for q, bindings := range queues {
			if q != qname {
				bindingsAux[exchange][q] = bindings
			}
		}
	}

	for exchange, queues := range s.queues {
		queuesAux[exchange] = make(map[string]amqp.Queue)
		for q, qObject := range queues {
			if q != qname {
				queuesAux[exchange][q] = qObject
			}
		}
	}

	for q, c := range s.consumers {
		if q != qname {
			consumersAux[q] = c
		}
	}

	for q, h := range s.handlers {
		if q != qname {
			handlersAux[q] = h
		}
	}

	s.bindings = bindingsAux
	s.queues = queuesAux
	s.consumers = consumersAux
	s.handlers = handlersAux
}

func (s *SharedAmqpState) DeleteConsumerByName(cname string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for q, consumers := range s.consumers {
		for i, c := range consumers {
			if c == cname {
				s.consumers[q] = append(s.consumers[q][:i], s.consumers[q][i+1:]...)
			}
		}
	}
}

// Initialize shared state maps for a new exchange
func (s *SharedAmqpState) InitializeExchange(exchangeName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queues[exchangeName] == nil {
		s.queues[exchangeName] = make(map[string]amqp.Queue)
	}
	if s.bindings[exchangeName] == nil {
		s.bindings[exchangeName] = make(map[string][]string)
	}
}
