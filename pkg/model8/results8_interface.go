package model8

import (
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
)

type Model8Results8Interface interface {
	GetIPsFromHostname(string) chan string
	HasIPSFromHostname(string) bool
	GetIPsPorts(string) chan *result.HostResult
	HasIPsPorts(string) bool
	AddPort(string, string, *port.Port)
	SetPorts(string, string, []*port.Port)
	IPHasPort(string, string, *port.Port) bool
	AddIpToHostname(string, string)
	HasIP(string, string) bool
	IsEmpty() bool
	Len() int
	GetPortCount(string, string) int
	AddSkipped(string, string)
	HasSkipped(string, string) bool
	JSONEncodeToString() string
}
