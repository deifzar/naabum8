package configparser

import (
	"log"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// type Config struct {
// 	NAABUM8 struct {
// 		// Verbose flag indicates whether to show verbose output or not
// 		Verbose bool `yaml:"Verbose"`
// 		// No-Color disables the colored output
// 		NoColor bool `yaml:"NoColor"`
// 		// JSON specifies whether to use json for output format or text file
// 		JSON bool `yaml:"JSON"`
// 		// Silent suppresses any extra text and only writes found host:port to screen
// 		Silent bool `yaml:"Silent"`
// 		// Stdin specifies whether stdin input was given to the process
// 		Stdin bool `yaml:"Stdin"`
// 		// Verify is used to check if the ports found were valid using CONNECT method
// 		Verify bool `yaml:"Verify"`
// 		// Version specifies if we should just show version and exit
// 		Version bool `yaml:"Version"`
// 		// Ping uses ping probes to discover fastest active host and discover dead hosts
// 		Ping bool `yaml:"Ping"`
// 		// Prints out debug information
// 		Debug bool `yaml:"Debug"`
// 		// Excludes ip of knows CDN ranges for full port scan
// 		ExcludeCDN bool `yaml:"ExcludeCDN"`
// 		// Invoke nmap detailed scan on results
// 		Nmap bool `yaml:"Nmap"`
// 		// InterfacesList show interfaces list
// 		InterfacesList bool `yaml:"InterfacesList"`
// 		// Retries is the number of retries for the port
// 		Retries int `yaml:"Retries"`
// 		// Rate is the rate of port scan requests
// 		Rate int `yaml:"Rate"`
// 		// Timeout is the seconds to wait for ports to respond
// 		Timeout int `yaml:"Timeout"`
// 		// WarmUpTime between scan phases
// 		WarmUpTime int `yaml:"WarmUpTime"`
// 		// Host is the single host or comma-separated list of hosts to find ports for
// 		Host []string `yaml:"Host"`
// 		// HostsFile is the file containing list of hosts to find port for
// 		HostsFile string `yaml:"HostsFile"`
// 		// Output is the file to write found ports to.
// 		Output string `yaml:"Output"`
// 		// Ports is the ports to use for enumeration
// 		Ports string `yaml:"Ports"`
// 		// PortsFile is the file containing ports to use for enumeration
// 		PortsFile string `yaml:"PortsFile"`
// 		// ExcludePorts is the list of ports to exclude from enumeration
// 		ExcludePorts string `yaml:"ExcludePorts"`
// 		// Ips or cidr to be excluded from the scan
// 		ExcludeIps string `yaml:"ExcludeIps"`
// 		// File containing Ips or cidr to exclude from the scan
// 		ExcludeIpsFile string `yaml:"ExcludeIpsFile"`
// 		// Tops ports to scan
// 		TopPorts string `yaml:"TopPorts"`
// 		// PortThreshold is the number of ports to find before skipping the host
// 		PortThreshold int `yaml:"PortThreshold"`
// 		// SourceIP to use in TCP packets
// 		SourceIP string `yaml:"SourceIP"`
// 		// Source Port to use in packets
// 		SourcePort string `yaml:"SourcePort"`
// 		// Interface to use for TCP packets
// 		Interface string `yaml:"Interface"`
// 		// Config file contains a scan configuration
// 		ConfigFile string `yaml:"ConfigFile"`
// 		// Nmap command (has priority over config file)
// 		NmapCLI string `yaml:"NmapCLI"`
// 		// Internal worker threads
// 		Threads int `yaml:"Threads"`
// 		// Deprecated: stats are automatically available through local endpoint
// 		// Enable progress bar
// 		EnableProgressBar bool `yaml:"EnableProgressBar"`
// 		// Deprecated: stats are automatically available through local endpoint (maybe used on cloud?)
// 		// StatsInterval is the number of seconds to display stats after
// 		StatsInterval int `yaml:"StatsInterval"`
// 		// Scan all the ips
// 		ScanAllIPS bool `yaml:"ScanAllIPS"`
// 		// IP Version to use while resolving hostnames
// 		IPVersion []string `yaml:"IPVersion"`
// 		// Scan Type
// 		ScanType string `yaml:"ScanType"`
// 		// Socks5 proxy
// 		Proxy string `yaml:"Proxy"`
// 		// Socks5 proxy authentication (username:password)
// 		ProxyAuth string `yaml:"ProxyAuth"`
// 		// Resolvers (comma separated or file)
// 		Resolvers string `yaml:"Resolvers"`
// 		// baseResolvers []string
// 		// OnResult			OnResultCallback		`yaml:"OnResult"`
// 		CSV    bool `yaml:"CSV"`
// 		Resume bool `yaml:"Resume"`
// 		// ResumeCfg         	*ResumeCfg	`yaml:"ResumeCfg"`
// 		Stream  bool `yaml:"Stream"`
// 		Passive bool `yaml:"Passive"`
// 		// display cdn in use
// 		OutputCDN   bool `yaml:"OutputCDN"`
// 		HealthCheck bool `yaml:"HealthCheck"`
// 		// Perform only host discovery
// 		OnlyHostDiscovery bool `yaml:"OnlyHostDiscovery"`
// 		// Skip host discovery
// 		SkipHostDiscovery bool     `yaml:"SkipHostDiscovery"`
// 		TcpSynPingProbes  []string `yaml:"TcpSynPingProbes"`
// 		// UdpPingProbes    goflags.StringSlice - planned
// 		TcpAckPingProbes []string `yaml:"TcpAckPingProbes"`
// 		// STcpInitPingProbes          goflags.StringSlice - planned
// 		IcmpEchoRequestProbe      bool `yaml:"IcmpEchoRequestProbe"`
// 		IcmpTimestampRequestProbe bool `yaml:"IcmpTimestampRequestProbe"`
// 		// IpProtocolPingProbes        goflags.StringSlice - planned
// 		IcmpAddressMaskRequestProbe bool `yaml:"IcmpAddressMaskRequestProbe"`
// 		ArpPing                     bool `yaml:"ArpPing"`
// 		// HostDiscoveryIgnoreRST      bool - planned
// 		IPv6NeighborDiscoveryPing bool   `yaml:"IPv6NeighborDiscoveryPing"`
// 		InputReadTimeout          string `yaml:"InputReadTimeout"`
// 		// ServiceDiscovery enables service discovery on found open ports (matches port number with service)
// 		DisableStdin bool `yaml:"DisableStdin"`
// 		// ServiceVersion attempts to discover service running on open ports with active/passive probes
// 		ServiceDiscovery bool `yaml:"ServiceDiscovery"`
// 		// ReversePTR lookup for ips
// 		ServiceVersion bool `yaml:"ServiceVersion"`
// 		//DisableUpdateCheck disables automatic update check
// 		ReversePTR bool `yaml:"ReversePTR"`
// 		// MetricsPort with statistics
// 		DisableUpdateCheck bool `yaml:"DisableUpdateCheck"`
// 		MetricsPort        int  `yaml:"MetricsPort"`
// 	} `yaml:"NAABUM8"`

// 	DatabaseConfig struct {
// 		Location string `yaml:"location"`
// 		Port     int    `yaml:"port"`
// 		Database string `yaml:"database"`
// 		Username string `yaml:"username"`
// 		Password string `yaml:"password"`
// 	} `yaml:"DatabaseConfig"`
// }

// func ParseConfig(path string) (*Config, error) {
// 	// Read file data
// 	data, err := os.ReadFile(path)
// 	if err != nil {
// 		// log.Fatalf("error: %v", err)
// 		return nil, err
// 	}

// 	// Initialize configuration
// 	var config *Config

// 	// Unmarshal YAML data into Config struct
// 	err = yaml.Unmarshal(data, &config)
// 	if err != nil {
// 		// log.Fatalf("error: %v", err)
// 		return nil, err
// 	}
// 	return config, nil
// }

func InitConfigParser() (*viper.Viper, error) {
	var err error
	v := viper.New()
	v.AddConfigPath(".")
	v.SetConfigType("yaml")
	v.SetConfigName("configuration")
	v.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Config file has changed:", e.Name)
	})
	v.WatchConfig()
	// If a config file is found, read it in.
	err = v.ReadInConfig()
	return v, err
}
