package controller8

import (
	"context"
	"database/sql"
	"deifzar/naabum8/pkg/cleanup8"
	"deifzar/naabum8/pkg/db8"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"
	"deifzar/naabum8/pkg/notification8"
	"deifzar/naabum8/pkg/orchestrator8"
	"deifzar/naabum8/pkg/utils"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"github.com/spf13/viper"

	"github.com/gofrs/uuid/v5"
)

type Controller8Naabum8 struct {
	Db            *sql.DB
	Config        *viper.Viper
	Orch          orchestrator8.Orchestrator8Interface
	runnerOptions *runner.Options
	OutputResult  model8.Model8Results8Interface
}

func NewController8Naabum8(db *sql.DB, cnfg *viper.Viper) Controller8Naabum8Interface {
	orch, err := orchestrator8.NewOrchestrator8()
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		log8.BaseLogger.Fatal().Msg("Error initializing orchestrator8 in controller constructor")
	}
	return &Controller8Naabum8{Db: db, Config: cnfg, Orch: orch}
}

// Launch port scan across all the enabled systems
func (m *Controller8Naabum8) Naabum8Scan(c *gin.Context) {
	// Clean up old files in tmp directory (older than 24 hours)
	cleanup := cleanup8.NewCleanup8()
	if err := cleanup.CleanupDirectory("tmp", 24*time.Hour); err != nil {
		log8.BaseLogger.Error().Err(err).Msg("Failed to cleanup tmp directory")
		// Don't return error here as cleanup failure shouldn't prevent startup
	}
	// Check that RabbitMQ relevant Queue is available.
	// If relevant queue does not exist, inform the user that there is one Naabum8 running at this moment and advise the user to wait for the latest results.

	queue_consumer := m.Config.GetStringSlice("ORCHESTRATORM8.naabum8.Queue")
	qargs_consumer := m.Config.GetStringMap("ORCHESTRATORM8.naabum8.Queue-arguments")
	publishingdetails := m.Config.GetStringSlice("ORCHESTRATORM8.naabum8.Publisher")
	if m.Orch.ExistQueue(queue_consumer[1], qargs_consumer) {
		DB := m.Db
		// Set Runner options from config file.
		err := m.initRunnerOptions()
		if err != nil {
			// move on and call katanam8 scan
			log8.BaseLogger.Debug().Stack().Msg(err.Error())
			log8.BaseLogger.Info().Msg("500 HTTP Response - Naabum8 Scan failed - Init runner options")
			m.Orch.PublishToExchange(publishingdetails[0], publishingdetails[1], nil, publishingdetails[2])
			notification8.PoolHelper.PublishSysErrorNotification("Naabum8Scan - Naabum8 Scan failed - Init runner options", "urgent", "naabum8")
			c.JSON(http.StatusInternalServerError, gin.H{"status": "failed", "msg": "Naabum8 Scan failed - Something wrong with the runner options"})
			return
		}
		hostname8 := db8.NewDb8Hostname8(DB)
		hostname8ModelSlice, err := hostname8.GetAllEnabled()
		if err != nil {
			// move on and call katanam8 scan
			log8.BaseLogger.Debug().Stack().Msg(err.Error())
			log8.BaseLogger.Info().Msg("500 HTTP Response - Naabum8 Scan - Failed to get the hostnames in scope.")
			m.Orch.PublishToExchange(publishingdetails[0], publishingdetails[1], nil, publishingdetails[2])
			notification8.PoolHelper.PublishSysErrorNotification("Naabum8Scan - Failed to get the hostnames in scope", "urgent", "naabum8")
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "msg": "Naabum8 scan failed - Something wrong fetching the hostnames in scope."})
			return
		}
		if len(hostname8ModelSlice) < 1 {
			m.Orch.PublishToExchange(publishingdetails[0], publishingdetails[1], nil, publishingdetails[2])
			notification8.PoolHelper.PublishSysWarningNotification("No targets in scope for a port scan. Make sure the client has enabled the scan on newly discovery assets.", "normal", "naabum8")
			log8.BaseLogger.Info().Msg("Naabu8 scans success. No targets in scope.")
			c.JSON(http.StatusAccepted, gin.H{"status": "success", "msg": "Naabum8 scans success. No targets in scope."})
			return
		}
		// add hostnames to scan
		for _, h := range hostname8ModelSlice {
			m.runnerOptions.Host = append(m.runnerOptions.Host, h.Name)
		}
		err = m.Orch.ActivateQueueByService("naabum8")
		if err != nil {
			log8.BaseLogger.Fatal().Msg("HTTP 500 Response - Naabum8 scans failed - Error bringing up the RabbitMQ queues for the Naabum8 service.")
			m.Orch.PublishToExchange(publishingdetails[0], publishingdetails[1], nil, publishingdetails[2])
			notification8.PoolHelper.PublishSysErrorNotification("Naabum8Scan - Error bringing up the RabbitMQ queues for the Naabum8 service", "urgent", "naabum8")
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "msg": "Num8 Scans failed. Error bringing up the RabbitMQ queues for the Naabum8 service."})
			return
		}
		log8.BaseLogger.Info().Msg("Naabum8 scans API call success")
		c.JSON(http.StatusOK, gin.H{"msg": "Naabum8 scans success ... Check notifications for scans updates."})
		// scan
		go m.runNaabu8(true, true)
	} else {
		// move on and call katanam8 scan
		log8.BaseLogger.Info().Msg("Naabum8 Scan API call forbidden")
		m.Orch.PublishToExchange(publishingdetails[0], publishingdetails[1], nil, publishingdetails[2])
		notification8.PoolHelper.PublishSysErrorNotification("Naabum8Scan - Launching Naabum8 Scan is not possible at this moment due to non-existent RabbitMQ queues.", "urgent", "naabum8")
		c.JSON(http.StatusForbidden, gin.H{"status": "forbidden", "msg": "Num8 Scans failed - Launching Naabum8 Scan is not possible at this moment due to non-existent RabbitMQ queues."})
		return
	}
}

// Launch port scan across all the enabled systems under the main domain
func (m *Controller8Naabum8) Naabum8Domain(c *gin.Context) {
	// Clean up old files in tmp directory (older than 24 hours)
	cleanup := cleanup8.NewCleanup8()
	if err := cleanup.CleanupDirectory("tmp", 24*time.Hour); err != nil {
		log8.BaseLogger.Error().Err(err).Msg("Failed to cleanup tmp directory")
		// Don't return error here as cleanup failure shouldn't prevent startup
	}
	DB := m.Db
	var uri model8.Domain8Uri
	if err := c.ShouldBindUri(&uri); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "msg": "Naabum8 Scan Domain failed - Check URL parameters."})
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Info().Msg("400 HTTP Response - Naabum8 Scan Domain")
		return
	}
	// Set Runner options from config file.
	err := m.initRunnerOptions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "msg": "Naabum8 Scan Domain failed - Init runner options failed"})
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Info().Msg("500 HTTP Response - Naabum8 Scan Domain - Init runner options failed")
		return
	}
	// Get hostnames by domain from DB
	hostname8 := db8.NewDb8Hostname8(DB)
	id, err := uuid.FromString(uri.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "msg": "Naabum8 Scan Domain failed - Check UUID URL parameters."})
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Info().Msg("400 HTTP Response - Naabum8 Scan Domain - UUID URL parameters wrong")
		return
	}
	get, err := hostname8.GetAllEnabledByParentID(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "msg": "Naabum8 Scan Domain -> Failed get hostnames"})
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Info().Msg("500 HTTP Response - Naabum8 Scan Domain - Something wrong fetching hostnames")
		return
	}
	if len(get) < 1 {
		log8.BaseLogger.Warn().Msg("202 HTTP Response - Naabum8 Scan Domain - No hostnames to scan.")
		c.JSON(http.StatusAccepted, gin.H{"status": "success", "data": nil, "msg": "Naabum8 Scan Domain - Not hostnames to scan."})
		return
	}
	// add hostnames to scan
	for _, h := range get {
		m.runnerOptions.Host = append(m.runnerOptions.Host, h.Name)
	}
	// Launch scan for all hostnames under the inquired domanin
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": nil, "msg": "OK! Launching port scans ... Check notifications for scans updates."})
	log8.BaseLogger.Info().Msg("Launching port scans across one domain.")
	go m.runNaabu8(false, true)
}

// Launch port scan across the hostnames submitted in the POST body
func (m *Controller8Naabum8) Naabum8Hostnames(c *gin.Context) {
	// Clean up old files in tmp directory (older than 24 hours)
	cleanup := cleanup8.NewCleanup8()
	if err := cleanup.CleanupDirectory("tmp", 24*time.Hour); err != nil {
		log8.BaseLogger.Error().Err(err).Msg("Failed to cleanup tmp directory")
		// Don't return error here as cleanup failure shouldn't prevent startup
	}
	DB := m.Db
	var post model8.PostHostname8
	if err := c.ShouldBindJSON(&post); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "failed", "msg": "Naabum8 scan failed - Check body parameters."})
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Info().Msg("400 HTTP Response - Naabum8 Scan Hostnames - Check URL parameters.")
		return
	}
	// Set Runner options from config file.
	err := m.initRunnerOptions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "failed", "msg": "Naabum8 Scan against hostname -> Init runner options failed"})
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Info().Msg("500 HTTP Response - Naabum8 Scan Hostnames - Init runner options failed")
		return
	}
	hostname8 := db8.NewDb8Hostname8(DB)
	// Verify that the post request has not been tampered.
	if hostname8.ValidPostBody(post) {
		// add hostnames to scan
		for _, p := range post.Target {
			m.runnerOptions.Host = append(m.runnerOptions.Host, p.Name)
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"status": "failed", "msg": "the hosts in the request do not seem valid."})
		log8.BaseLogger.Info().Msg("400 HTTP Response - Naabum8 Scan Hostnames - the hosts in the request do not seem valid.")
		return
	}
	if m.runnerOptions.Host == nil {
		log8.BaseLogger.Warn().Msg("202 HTTP Response - Naabum8 Scan Hostnames - No hostnames to scan.")
		c.JSON(http.StatusAccepted, gin.H{"status": "success", "data": nil, "msg": "Naabum8 Scan Hostnames - Not hostnames to scan."})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "OK! Launching port scans ... Check notifications for scans updates."})
	log8.BaseLogger.Info().Msg("Launching port scans across specific hostnames.")
	go m.runNaabu8(false, true)
	// Launch scan for the hostnames included in POST
}

func (m *Controller8Naabum8) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "naabum8",
	})
}

func (m *Controller8Naabum8) ReadinessCheck(c *gin.Context) {
	dbHealthy := true
	rbHealthy := true
	if err := m.Db.Ping(); err != nil {
		log8.BaseLogger.Error().Err(err).Msg("Database ping failed during readiness check")
		dbHealthy = false
	}
	dbStatus := "unhealthy"
	if dbHealthy {
		dbStatus = "healthy"
	}

	queue_consumer := m.Config.GetStringSlice("ORCHESTRATORM8.naabum8.Queue")
	qargs_consumer := m.Config.GetStringMap("ORCHESTRATORM8.naabum8.Queue-arguments")

	if !m.Orch.ExistQueue(queue_consumer[1], qargs_consumer) || !m.Orch.ExistConsumersForQueue(queue_consumer[1], qargs_consumer) {
		rbHealthy = false
	}

	rbStatus := "unhealthy"
	if rbHealthy {
		rbStatus = "healthy"
	}

	if dbHealthy && rbHealthy {
		c.JSON(http.StatusOK, gin.H{
			"status":    "ready",
			"timestamp": time.Now().Format(time.RFC3339),
			"service":   "naabum8",
			"checks": gin.H{
				"database": dbStatus,
				"rabbitmq": rbStatus,
			},
		})
	} else {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":    "not ready",
			"timestamp": time.Now().Format(time.RFC3339),
			"service":   "naabum8",
			"checks": gin.H{
				"database": dbStatus,
				"rabbitmq": rbStatus,
			},
		})
	}
}

func (m *Controller8Naabum8) initRunnerOptions() error {
	var err error
	// Init model8 results8
	m.OutputResult = model8.NewModel8Result8()

	// Output file
	// currenttime := time.Now()
	// suffix := fmt.Sprintf("%d-%d-%d-%d-%d", currenttime.Year(), currenttime.Month(), currenttime.Day(), currenttime.Hour(), currenttime.Minute())
	// // var writer io.WriteCloser
	// pathOutput := "./tmp/result-" + suffix + ".json"

	m.runnerOptions = &runner.Options{
		// Verbose:           o.Verbose,
		// NoColor:           o.NoColor,
		JSON: m.Config.GetBool("NAABUM8.JSON"),
		// Silent:            o.Silent,
		// Stdin:             o.Stdin,
		// Verify:            o.Verify,
		// Version:           o.Version,
		// Ping:              o.Ping,
		// Debug:             o.Debug,
		ExcludeCDN: m.Config.GetBool("NAABUM8.ExcludeCDN"),
		// Nmap:              o.Nmap,
		// InterfacesList:    o.InterfacesList,
		// Retries:           o.Retries,
		Rate:       m.Config.GetInt("NAABUM8.Rate"),
		Timeout:    m.Config.GetInt("NAABUM8.Timeout"),
		WarmUpTime: m.Config.GetInt("NAABUM8.WarmUpTime"),
		// Host:       m.Cnfg.NAABUM8.Host,
		// HostsFile:         o.HostsFile,
		// Output: m.Cnfg.NAABUM8.Output,
		// Output: pathOutput,
		Ports: m.Config.GetString("NAABUM8.Ports"),
		// PortsFile:         o.PortsFile,
		// ExcludePorts:      o.ExcludePorts,
		// ExcludeIps:        o.ExcludeIps,
		// ExcludeIpsFile:    o.ExcludeIpsFile,
		// TopPorts:          o.TopPorts,
		// PortThreshold:     o.PortThreshold,
		// SourceIP:          o.SourceIP,
		// SourcePort:        o.SourcePort,
		// Interface:         o.Interface,
		// ConfigFile:        o.ConfigFile,
		NmapCLI: m.Config.GetString("NAABUM8.NmapCLI"),
		Threads: m.Config.GetInt("NAABUM8.Threads"),
		// EnableProgressBar: o.EnableProgressBar,
		// StatsInterval:     o.StatsInterval,
		ScanAllIPS: m.Config.GetBool("NAABUM8.ScanAllIPS"),
		IPVersion:  m.Config.GetStringSlice("NAABUM8.IPVersion"),
		ScanType:   m.Config.GetString("NAABUM8.ScanType"),
		Proxy:      m.Config.GetString("NAABUM8.Proxy"),
		ProxyAuth:  m.Config.GetString("NAABUM8.ProxyAuth"),
		// Resolvers:         o.Resolvers,
		// // baseResolvers:               o.baseResolvers,
		OnResult: func(hr *result.HostResult) {
			for _, p := range hr.Ports {
				m.OutputResult.AddPort(hr.Host, hr.IP, p)
			}
		},
		// CSV:    o.CSV,
		// Resume: o.Resume,
		// // ResumeCfg:                   o.ResumeCfg,
		// Stream:                      o.Stream,
		// Passive:                     o.Passive,
		// OutputCDN:                   o.OutputCDN,
		// HealthCheck:                 o.HealthCheck,
		// OnlyHostDiscovery:           o.OnlyHostDiscovery,
		SkipHostDiscovery: m.Config.GetBool("NAABUM8.SkipHostDiscovery"),
		// TcpSynPingProbes:            o.TcpSynPingProbes,
		// TcpAckPingProbes:            o.TcpAckPingProbes,
		// IcmpEchoRequestProbe:        o.IcmpEchoRequestProbe,
		// IcmpTimestampRequestProbe:   o.IcmpTimestampRequestProbe,
		// IcmpAddressMaskRequestProbe: o.IcmpAddressMaskRequestProbe,
		// ArpPing:                     o.ArpPing,
		// IPv6NeighborDiscoveryPing:   o.IPv6NeighborDiscoveryPing,
		// DisableStdin:                o.DisableStdin,
		// ServiceDiscovery:            o.ServiceDiscovery,
		// ServiceVersion:              o.ServiceVersion,
		// ReversePTR:                  o.ReversePTR,
		// DisableUpdateCheck:          o.DisableUpdateCheck,
		// MetricsPort:                 o.MetricsPort,
	}

	// if o.InputReadTimeout != "" {
	// 	rO.InputReadTimeout, err = timeutil.ParseDuration(o.InputReadTimeout)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	return err
}

func (m *Controller8Naabum8) runNaabu8(fullscan bool, firstrun bool) {

	err := m.runnerOptions.ValidateOptions()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return
	}
	log8.BaseLogger.Info().Stack().Msg("port scans are about to kick off")
	naabuRunner, err := runner.NewRunner(m.runnerOptions)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return
	}
	defer naabuRunner.Close()
	err = naabuRunner.RunEnumeration(context.TODO())
	log8.BaseLogger.Info().Msg("Naabum8 scans running.")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return
	}
	log8.BaseLogger.Info().Msg("Naabum8 scans have completed")
	if firstrun && m.OutputResult.IsEmpty() {
		log8.BaseLogger.Info().Msg("Naabum8 scans have completed with empty results")
		// Is the port scan blocked by an ISP? Run port scan against only port 80 and 443.
		m.runnerOptions.Ports = "80,443"
		m.runNaabu8(fullscan, false)
	} else {
		portsHTTPxFormat := m.GetListOfFoundPortsHTTPxXFormat()
		// Parse Nmap results
		var nmapHosts []model8.Host
		nmap, err := os.ReadFile("./tmp/nmap-output.xml")
		if err != nil {
			log8.BaseLogger.Debug().Stack().Msg(err.Error())
			log8.BaseLogger.Warn().Msgf("error reading the nmap output: tmp/nmap-output.xml")
		} else {
			nmapObj, err := utils.NmapParse(nmap)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				log8.BaseLogger.Warn().Msgf("error parsing the nmap output: tmp/nmap-output.xml")
			} else {
				nmapHosts = nmapObj.Hosts
			}
		}
		m.workWithNaabuAndNmapResults(nmapHosts)
		log8.BaseLogger.Info().Msg("finished parsing naabu and nmap results")
		// Enumerating HTTP endpoints with HTTPx
		contrHttpx8 := NewController8Httpx8(m.Db, m.runnerOptions.Host, portsHTTPxFormat)
		contrHttpx8.InitRunnerOptions()
		err = contrHttpx8.Run()
		if err != nil {
			log8.BaseLogger.Debug().Stack().Msg(err.Error())
			// Send a notification informing that something is wrong with the enumeration of the HTTP endpoints
		}
		err = contrHttpx8.UpdateDB()
		if err != nil {
			log8.BaseLogger.Debug().Stack().Msg(err.Error())
			// Send a notification informing that something is wrong with the HTTP endpoints and the database
		}
		log8.BaseLogger.Info().Msg("HTTP endpoints successfully updated in DB")
	}
	// publish RabbitMQ message for katanam8 only if the Naabum8 scan is full
	if fullscan {
		// call katanam8 scan
		publishingdetails := m.Config.GetStringSlice("ORCHESTRATORM8.naabum8.Publisher")
		m.Orch.PublishToExchange(publishingdetails[0], publishingdetails[1], nil, publishingdetails[2])
		// discordBot.ChannelMessageSend(naabuM88Discord.GetChannelID(), m.OutputResult.JSONEncodeToString())
	}
}

func (m *Controller8Naabum8) updateService8AndHostnameinfo8ForTargetDB(hostname8 model8.Hostname8, service8List []model8.Service8, hostnameinfo8List []model8.Hostnameinfo8, softslice map[string]map[int]string) error {
	DB := m.Db
	serviceDB := db8.NewDb8Service8(DB)
	hostnameinfoDB := db8.NewDb8Hostnameinfo8(DB)
	// Insert hostname Info
	_, err := hostnameinfoDB.InsertBatch(hostnameinfo8List)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Error().Msgf("Error when inserting hostname info '%s' in DB\n", hostname8.Name)
		return err
	}
	// Set all hostname's services `live` column as FALSE
	err = serviceDB.SetLiveColumnByHostnameID(false, hostname8.Id)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Error().Msgf("Error when setting services live as FALSE for the hostname '%s' in DB\n", hostname8.Name)
		return err
	}
	// Update or insert found hostname's services `live` column as TRUE.
	err = serviceDB.InsertBatch(service8List)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Error().Msgf("Error when inserting services from the hostname '%s' in DB\n", hostname8.Name)
		return err
	}
	// update software details in Hostnameinfo
	if len(softslice) > 0 {
		for protocol, portslice := range softslice {
			if len(portslice) > 0 {
				for port, soft := range portslice {
					if soft != "" {
						latestsoftware, err := hostnameinfoDB.GetSoftware(hostname8.Id, protocol, port)
						if err != nil {
							log8.BaseLogger.Debug().Stack().Msg(err.Error())
							log8.BaseLogger.Error().Msgf("Error when fetching software from the hostname '%s' in DB\n", hostname8.Name)
							return err
						}
						latestsoftware = append(latestsoftware, soft)
						latestsoftware = utils.RemoveDuplicates(latestsoftware)
						_, err = hostnameinfoDB.UpdateSoftware(latestsoftware, hostname8.Id, protocol, port)
						if err != nil {
							log8.BaseLogger.Debug().Stack().Msg(err.Error())
							log8.BaseLogger.Error().Msgf("Error when updating software from the hostname '%s' in DB\n", hostname8.Name)
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

func (m *Controller8Naabum8) setService8AndHostnameinfo8ForTarget(hostname string, nmapHosts []model8.Host) ([]model8.Service8, []model8.Hostnameinfo8, map[string]map[int]string, error) {
	if m.OutputResult.HasIPSFromHostname(hostname) {
		if m.OutputResult.HasIPsPorts(hostname) {
			DB := m.Db
			hostnameDB := db8.NewDb8Hostname8(DB)
			h, err := hostnameDB.GetOneHostnameByName(hostname)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				log8.BaseLogger.Error().Msgf("Error fetching the hostname '%s' from DB when analysing results\n", hostname)
				return nil, nil, nil, err
			} else {
				var hostnameinfo8List []model8.Hostnameinfo8
				var service8List []model8.Service8
				softslice := make(map[string]map[int]string)
				softslice["tcp"] = make(map[int]string)
				softslice["udp"] = make(map[int]string)
				for r := range m.OutputResult.GetIPsPorts(hostname) {
					addressfound := false
					// finding hostname address in Nmap results.
					for _, nmaphost := range nmapHosts {
						for _, nmapaddress := range nmaphost.Addresses {
							if strings.EqualFold(r.IP, nmapaddress.Addr) {
								addressfound = true
								break
							}
						}
						if addressfound {
							// mapping ports, services and software from Nmap results
							for _, p := range r.Ports {
								for _, nmapport := range nmaphost.Ports {
									if nmapport.PortId == p.Port && strings.EqualFold(strings.ToLower(nmapport.Protocol), strings.ToLower(p.Protocol.String())) {
										service := strings.ToLower(nmapport.Service.Name)
										if nmapport.Service.Product != "" {
											if nmapport.Service.Version != "" {
												softslice[strings.ToLower(p.Protocol.String())][p.Port] = nmapport.Service.Product + " " + nmapport.Service.Version
											} else {
												softslice[strings.ToLower(p.Protocol.String())][p.Port] = nmapport.Service.Product
											}
										}
										service8List = append(service8List, model8.Service8{IPaddress: r.IP, Protocol: strings.ToLower(p.Protocol.String()), Port: uint(p.Port), Service: service, Tls: p.TLS, Live: true, Hostnameid: h.Id})

										break
									}
								}
								hostnameinfo8List = append(hostnameinfo8List, model8.Hostnameinfo8{Hostnameid: h.Id, Port: uint(p.Port), Protocol: strings.ToLower(p.Protocol.String())})
							}
						}
					}
				}
				return service8List, hostnameinfo8List, softslice, nil
			}
		}
		return nil, nil, nil, errors.New("target does not have ports open")
	}
	return nil, nil, nil, errors.New("target does not have IP address")
}

func (m *Controller8Naabum8) workWithNaabuAndNmapResults(nmapHosts []model8.Host) {
	if !m.OutputResult.IsEmpty() {
		for _, target := range m.runnerOptions.Host {
			service8List, hostnameinfo8List, softslice, err := m.setService8AndHostnameinfo8ForTarget(target, nmapHosts)
			if err != nil {
				continue
			}
			DB := m.Db
			hostnameDB := db8.NewDb8Hostname8(DB)
			h, err := hostnameDB.GetOneHostnameByName(target)
			if err != nil {
				continue
			}
			m.updateService8AndHostnameinfo8ForTargetDB(h, service8List, hostnameinfo8List, softslice)
		}
	}
}

func (m *Controller8Naabum8) GetListOfFoundPortsHTTPxXFormat() string {
	var portList []string
	var portHTTPx string
	if !m.OutputResult.IsEmpty() {
		for _, target := range m.runnerOptions.Host {
			if m.OutputResult.HasIPSFromHostname(target) {
				if m.OutputResult.HasIPsPorts(target) {
					for r := range m.OutputResult.GetIPsPorts(target) {
						for _, p := range r.Ports {
							portList = append(portList, "http:"+strconv.Itoa(p.Port), "https:"+strconv.Itoa(p.Port))
						}
					}
				}
			}
		}
		portList = utils.RemoveDuplicates(portList)
		portHTTPx = strings.Join(portList, ",")
	}
	return portHTTPx
}

// func (m *Controller8Naabum8) RabbitMQBringConsumerBackAndPublishMessage() error {
// 	// RabbitMQ queue and consumer for naabum8 should be back to be available.
// 	orchestrator8, err := orchestrator8.NewOrchestrator8()
// 	amqp8 := orchestrator8.GetAmqp()
// 	defer amqp8.CloseConnection()
// 	defer amqp8.CloseChannel()
// 	if err != nil {
// 		log8.BaseLogger.Debug().Msg(err.Error())
// 		log8.BaseLogger.Fatal().Msg("Error connecting to the RabbitMQ server.")
// 		return err
// 	}
// 	orchestrator8.CreateHandleCPTM8()
// 	orchestrator8.ActivateConsumerByService("naabum8")

// 	// Publish message
// 	queue := m.Config.GetStringSlice("ORCHESTRATORM8.katanam8.Queue")
// 	log8.BaseLogger.Info().Msg("RabbitMQ publishing message to queue for KatanaM8 service.")
// 	err = amqp8.Publish(queue[0], "cptm8.katanam8.get.scan", "")
// 	if err != nil {
// 		log8.BaseLogger.Debug().Msg(err.Error())
// 		log8.BaseLogger.Error().Msgf("rabbitMQ publishing message to queue for KatanaM8 service failed")
// 		return err
// 	}
// 	log8.BaseLogger.Info().Msg("RabbitMQ publishing message to KatanaM8 queue service success.")
// 	return nil
// }

// func (m *Controller8Naabum8) RabbitMQBringConsumerBack() error {

// 	// RabbitMQ queue and consumer for Naabum8 should be back to be available.
// 	orchestrator8, err := orchestrator8.NewOrchestrator8()
// 	if err != nil {
// 		log8.BaseLogger.Debug().Stack().Msg(err.Error())
// 		log8.BaseLogger.Fatal().Msg("Error connecting to the RabbitMQ server.")
// 		return err
// 	}
// 	orchestrator8.CreateHandleCPTM8()
// 	orchestrator8.ActivateConsumerByService("naabum8")

// 	return nil
// }

// func (m *Controller8Naabum8) RabbitMQPublishMessage() error {
// 	orchestrator8, err := orchestrator8.NewOrchestrator8()
// 	if err != nil {
// 		log8.BaseLogger.Debug().Stack().Msg(err.Error())
// 		log8.BaseLogger.Fatal().Msg("Error connecting to the RabbitMQ server.")
// 		return err
// 	}
// 	amqp8 := orchestrator8.GetAmqp()
// 	defer amqp8.CloseChannel()
// 	defer amqp8.CloseConnection()
// 	queue := m.Config.GetStringSlice("ORCHESTRATORM8.katanam8.Queue")
// 	log8.BaseLogger.Info().Msg("RabbitMQ publishing message to queue for KatanaM8 service.")
// 	err = amqp8.Publish(queue[0], "cptm8.katanam8.get.scan", "")
// 	if err != nil {
// 		log8.BaseLogger.Debug().Stack().Msg(err.Error())
// 		log8.BaseLogger.Error().Msgf("rabbitMQ publishing message to queue for KatanaM8 service failed")
// 		return err
// 	}
// 	log8.BaseLogger.Info().Msg("RabbitMQ publishing message to KatanaM8 queue service success.")
// 	return nil
// }
