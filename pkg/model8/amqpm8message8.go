package model8

import (
	"time"
)

type AmqpM8Message struct {
	Channel   string    `json:"channel,omitempty"`
	Payload   any       `json:"payload,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Source    string    `json:"source,omitempty"`
}
