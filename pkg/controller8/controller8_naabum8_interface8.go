package controller8

import (
	"deifzar/naabum8/pkg/model8"
	"deifzar/naabum8/pkg/orchestrator8"

	"github.com/gin-gonic/gin"
)

type Controller8Naabum8Interface interface {
	Naabum8Scan(*gin.Context)
	Naabum8Domain(*gin.Context)
	Naabum8Hostnames(*gin.Context)
	initRunnerOptions() error
	runNaabu8(fullscan bool, orch8 orchestrator8.Orchestrator8Interface, firstrun bool)
	workWithNaabuAndNmapResults([]model8.Host)
	setService8AndHostnameinfo8ForTarget(hostname string, nmapHosts []model8.Host) ([]model8.Service8, []model8.Hostnameinfo8, map[string]map[int]string, error)
	updateService8AndHostnameinfo8ForTargetDB(hostname8 model8.Hostname8, service8List []model8.Service8, hostnameinfo8List []model8.Hostnameinfo8, softslice map[string]map[int]string) error
	// RabbitMQBringConsumerBackAndPublishMessage() error
	// RabbitMQBringConsumerBack() error
	// RabbitMQPublishMessage() error
}
