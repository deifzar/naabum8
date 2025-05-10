package controller8

import (
	"database/sql"
	"deifzar/naabum8/pkg/db8"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"
	"deifzar/naabum8/pkg/utils"

	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/httpx/runner"
)

type Controller8Httpx8 struct {
	Db            *sql.DB
	Host          []string
	PortList      customport.CustomPorts
	Endpoint      map[string][]string
	runnerOptions *runner.Options
	OutputResult  model8.Model8Results8Interface
}

func NewController8Httpx8(db *sql.DB, host []string, portList string) Controller8Httpx8Interface {
	var customports customport.CustomPorts
	customports.Set(portList)
	return &Controller8Httpx8{
		Db:       db,
		Host:     host,
		PortList: customports,
		Endpoint: make(map[string][]string, len(host)),
	}
}

func (m *Controller8Httpx8) InitRunnerOptions() {

	m.runnerOptions = &runner.Options{
		Methods:           "GET",
		InputTargetHost:   m.Host,
		TechDetect:        true,
		Unsafe:            true,
		CustomPorts:       m.PortList,
		Verbose:           false,
		LeaveDefaultPorts: true,
		OnResult: func(r runner.Result) {
			// handle error
			if r.Err != nil {
				log8.BaseLogger.Error().Msgf("%s: %s\n", r.Input, r.Err)
				return
			}
			if r.Scheme == "http" && r.Port == "80" {
				r.URL = "http://" + r.Input
			}
			if r.Scheme == "https" && r.Port == "443" {
				r.URL = "https://" + r.Input
			}
			m.Endpoint[r.Input] = append(m.Endpoint[r.Input], r.URL)
		},
	}
}

func (m *Controller8Httpx8) Run() error {
	err := m.runnerOptions.ValidateOptions()
	if err != nil {
		return err
	} else {
		httpxRunner, err := runner.New(m.runnerOptions)
		if err != nil {
			log8.BaseLogger.Debug().Stack().Msg(err.Error())
			return err
		}
		defer httpxRunner.Close()
		httpxRunner.RunEnumeration()
		return nil
	}
}

func (m *Controller8Httpx8) UpdateDB() error {
	DB := m.Db
	deadHTTPEndpoints := make(map[string][]string)
	prevHTTPEndpoints, err := m.GetPrevHTTPEndpoints()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	dbEndpoint8 := db8.NewDb8Endpoint8(DB)
	dbHostname8 := db8.NewDb8Hostname8(DB)
	for _, name := range m.Host {
		deadHTTPEndpoints[name] = utils.Difference(prevHTTPEndpoints[name], m.Endpoint[name])
		if deadHTTPEndpoints[name] != nil {
			err = dbEndpoint8.UpdateMultipleByEndpoint(deadHTTPEndpoints[name], false)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				log8.BaseLogger.Warn().Msgf("There was an error updating dead HTTP endpoints under '%s'.\n", name)
				continue
			}
		} else {
			log8.BaseLogger.Info().Msgf("All HTTP Endpoints under the hostname '%s' remain live.\n", name)
			err = dbEndpoint8.UpdateMultipleByEndpoint(prevHTTPEndpoints[name], true)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				log8.BaseLogger.Warn().Msgf("There was an error updating all live HTTP endpoints under '%s'.\n", name)
				continue
			}
		}
		if m.Endpoint[name] != nil {
			h, err := dbHostname8.GetOneHostnameByName(name)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				log8.BaseLogger.Warn().Msgf("Before inserting new HTTP endpoints, there was an error when fetching the hostname details for '%s'.\n", name)
				continue
			}
			err = dbEndpoint8.InsertMultiple(m.Endpoint[name], h.Id)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				log8.BaseLogger.Warn().Msgf("There was an error inserting NEW live HTTP endpoints under '%s'.\n", name)
				continue
			}
		} else {
			log8.BaseLogger.Info().Msgf("There are not new HTTP endpoints under '%s'.\n", name)
		}
	}
	return nil
}

func (m *Controller8Httpx8) GetPrevHTTPEndpoints() (map[string][]string, error) {
	DB := m.Db
	prevHTTPEndpoints := make(map[string][]string)
	dbEndpoint8 := db8.NewDb8Endpoint8(DB)
	dbHostname8 := db8.NewDb8Hostname8(DB)
	for _, name := range m.Host {
		h, err := dbHostname8.GetOneHostnameByName(name)
		if err != nil {
			log8.BaseLogger.Error().Msgf("Error fetching hostname details for '%s'.\n", name)
			return nil, err
		}
		httpEndpoint8Array, err := dbEndpoint8.GetAllHTTPByHostnameID(h.Id)
		if err != nil {
			log8.BaseLogger.Warn().Msgf("Error fetching http endpoints by hostname id: '%s'.\n", name)
			return nil, err
		}
		for _, httpE := range httpEndpoint8Array {
			prevHTTPEndpoints[name] = append(prevHTTPEndpoints[name], httpE.Endpoint)
		}
	}
	return prevHTTPEndpoints, nil
}
