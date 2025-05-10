package model8

import "github.com/gofrs/uuid/v5"

type Service8 struct {
	Id         uuid.UUID `json:"id"`
	IPaddress  string    `json:"ipaddress"`
	Protocol   string    `json:"protocol"`
	Service    string    `json:"service"`
	Port       uint      `json:"port"`
	Tls        bool      `json:"tls"`
	Live       bool      `json:"live"`
	Hostnameid uuid.UUID `json:"hostnameid"`
}
