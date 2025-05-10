package model8

import "github.com/gofrs/uuid/v5"

type Endpoint8 struct {
	Id         uuid.UUID `json:"id"`
	Endpoint   string    `json:"endpoint"`
	Live       bool      `json:"live"`
	Hostnameid uuid.UUID `json:"hostnameid"`
}
