package model8

import (
	"deifzar/naabum8/pkg/log8"
	"encoding/json"
	"sync"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"golang.org/x/exp/maps"
)

type Results8 struct {
	sync.RWMutex
	Hostnames        map[string]map[string]struct{}              `json:"hostnames"`
	HostnamesIPPorts map[string]map[string]map[string]*port.Port `json:"hostnamesIPPorts"`
	Skipped          map[string]map[string]struct{}              `json:"skipped"`
}

func NewModel8Result8() Model8Results8Interface {
	return &Results8{
		Hostnames:        make(map[string]map[string]struct{}),
		HostnamesIPPorts: make(map[string]map[string]map[string]*port.Port),
		Skipped:          make(map[string]map[string]struct{}),
	}
}

func (r *Results8) InitResult8() {
	r.Hostnames = make(map[string]map[string]struct{})
	r.HostnamesIPPorts = make(map[string]map[string]map[string]*port.Port)
	r.Skipped = make(map[string]map[string]struct{})
	// return &Results8{hostnames: hostnames, ipPorts: ipPorts, skipped: skipped}
}

// GetIPs from hostnames
func (r *Results8) GetIPsFromHostname(h string) chan string {
	r.Lock()

	out := make(chan string)

	go func() {
		defer close(out)
		defer r.Unlock()

		for ip := range r.Hostnames[h] {
			out <- ip
		}
	}()

	return out
}

func (r *Results8) HasIPSFromHostname(h string) bool {
	r.RLock()
	defer r.RUnlock()

	return len(r.Hostnames[h]) > 0
}

// GetIpsPorts returns the ips and ports
func (r *Results8) GetIPsPorts(h string) chan *result.HostResult {
	r.RLock()

	out := make(chan *result.HostResult)

	go func() {
		defer close(out)
		defer r.RUnlock()

		for ip, ports := range r.HostnamesIPPorts[h] {
			if r.HasSkipped(h, ip) {
				continue
			}
			out <- &result.HostResult{IP: ip, Ports: maps.Values(ports)}
		}
	}()

	return out
}

func (r *Results8) HasIPsPorts(h string) bool {
	r.RLock()
	defer r.RUnlock()

	return len(r.HostnamesIPPorts[h]) > 0
}

// AddPort to a specific hostname and its ip
func (r *Results8) AddPort(h, ip string, p *port.Port) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.HostnamesIPPorts[h]; !ok {
		r.HostnamesIPPorts[h] = make(map[string]map[string]*port.Port)
	}
	if _, ok := r.HostnamesIPPorts[h][ip]; !ok {
		r.HostnamesIPPorts[h][ip] = make(map[string]*port.Port)
	}
	if _, ok := r.Hostnames[h]; !ok {
		r.Hostnames[h] = make(map[string]struct{})
	}
	r.HostnamesIPPorts[h][ip][p.String()] = p
	r.Hostnames[h][ip] = struct{}{}
}

// SetPorts for a specific ip
func (r *Results8) SetPorts(h, ip string, ports []*port.Port) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.HostnamesIPPorts[ip]; !ok {
		r.HostnamesIPPorts[h][ip] = make(map[string]*port.Port)
	}

	for _, p := range ports {
		r.HostnamesIPPorts[h][ip][p.String()] = p
	}
	r.Hostnames[h][ip] = struct{}{}
}

// IPHasPort checks if an ip has a specific port
func (r *Results8) IPHasPort(h, ip string, p *port.Port) bool {
	r.RLock()
	defer r.RUnlock()

	ipPorts, hasports := r.HostnamesIPPorts[h][ip]
	if !hasports {
		return false
	}
	_, hasport := ipPorts[p.String()]

	return hasport
}

// AddIp adds an ip to the results
func (r *Results8) AddIpToHostname(h, ip string) {
	r.Lock()
	defer r.Unlock()

	r.Hostnames[h][ip] = struct{}{}
}

// HasIP checks if an ip has been seen previously in the host
func (r *Results8) HasIP(h, ip string) bool {
	r.RLock()
	defer r.RUnlock()

	_, ok := r.Hostnames[h][ip]
	return ok
}

func (r *Results8) IsEmpty() bool {
	return r.Len() == 0
}

func (r *Results8) Len() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.Hostnames)
}

// GetPortCount returns the number of ports discovered for a hostname and ip
func (r *Results8) GetPortCount(h, ip string) int {
	r.RLock()
	defer r.RUnlock()

	return len(r.HostnamesIPPorts[h][ip])
}

// AddSkipped adds an ip to the skipped list
func (r *Results8) AddSkipped(h, ip string) {
	r.Lock()
	defer r.Unlock()

	r.Skipped[h][ip] = struct{}{}
}

// HasSkipped checks if an ip has been skipped
func (r *Results8) HasSkipped(hostname string, ip string) bool {
	r.RLock()
	defer r.RUnlock()

	_, ok := r.Skipped[hostname][ip]
	return ok
}

// Convert to String HostnamesIPPorts
func (r *Results8) JSONEncodeToString() string {
	b, err := json.Marshal(r.HostnamesIPPorts)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
	}
	return string(b)
}
