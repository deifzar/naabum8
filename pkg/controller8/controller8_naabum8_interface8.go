package controller8

import (
	"deifzar/naabum8/pkg/model8"

	"github.com/gin-gonic/gin"
)

type Controller8Naabum8Interface interface {
	Naabum8Scan(*gin.Context)
	Naabum8Domain(*gin.Context)
	Naabum8Hostnames(*gin.Context)
	HealthCheck(c *gin.Context)
	ReadinessCheck(c *gin.Context)
	initRunnerOptions() error
	runNaabu8(fullscan bool, firstrun bool)
	updateServicesInfoFromNmapResults(nmapOutput []model8.Host) error
	returnService8AndHostnameinfo8FromNmapOutputByHostname(hostname string, nmapOutput []model8.Host) ([]model8.Service8, []model8.Hostnameinfo8, map[string]map[int]string, error)
	updateService8AndHostnameinfo8ByHostnameObject(hostname8 model8.Hostname8, service8List []model8.Service8, hostnameinfo8List []model8.Hostnameinfo8, softslice map[string]map[int]string) error
	handleErrorOnFullscan(fullscan bool, message string, urgency string)
	sendWarningNotification(fullscan bool, message string, urgency string)
	// RabbitMQBringConsumerBackAndPublishMessage() error
	// RabbitMQBringConsumerBack() error
	// RabbitMQPublishMessage() error
}
