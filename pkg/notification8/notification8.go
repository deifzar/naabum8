package notification8

import (
	"fmt"

	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"
	"deifzar/naabum8/pkg/orchestrator8"
)

// NotificationService provides methods for sending notifications
type NotificationService struct {
	orchestrator orchestrator8.Orchestrator8Interface
}

// PublishNotification publishes a notification using the RabbitMQ connection pool
// routing key totally customisable. Examples:
// "app.*.*"" -> the notification via the web app only
// "email.*.*", "#.urgent", "#.critical", "#.high" -> the notification via email
func PublishNotification(routingKey string, eventType model8.Notificationevent, severity string, userRole model8.Roletype, source string, message string) error {
	metadata := model8.NotificationMetadata8{
		Severity:    severity,
		Channeltype: model8.App,
		Eventtype:   eventType,
	}

	notification := model8.Notification8{
		Userrole: userRole,
		Type:     eventType,
		Message:  message,
		Metadata: metadata,
	}

	orchestrator8, err := orchestrator8.NewOrchestrator8()
	if err != nil {
		return fmt.Errorf("failed to create orchestrator with pool: %w", err)
	}

	err = orchestrator8.PublishToExchange("notification", routingKey, notification, source)
	if err != nil {
		log8.BaseLogger.Error().Err(err).Msg("Failed to publish notification")
		return fmt.Errorf("failed to publish notification: %w", err)
	}

	return nil
}

// NotificationPoolHelper provides static helper methods using connection pool
type NotificationPoolHelper struct{}

// PublishSecurityNotificationAdmin sends a security notification to admins using connection pool
func (NotificationPoolHelper) PublishSecurityNotificationAdmin(message string, severity string, source string) error {
	return PublishNotification("app.security."+severity, model8.Security, severity, model8.RoleAdmin, source, message)
}

// PublishSecurityNotificationUser sends a security notification to users using connection pool
func (NotificationPoolHelper) PublishSecurityNotificationUser(message string, severity string, source string) error {
	return PublishNotification("app.security."+severity, model8.Security, severity, model8.RoleUser, source, message)
}

// PublishSysErrorNotification sends an error notification to admins using connection pool
func (NotificationPoolHelper) PublishSysErrorNotification(message string, severity string, source string) error {
	return PublishNotification("app.error."+severity, model8.Error, severity, model8.RoleAdmin, source, message)
}

// PublishSysWarningNotification sends a warning notification to admins using connection pool
func (NotificationPoolHelper) PublishSysWarningNotification(message string, severity string, source string) error {
	return PublishNotification("app.warning."+severity, model8.Warning, severity, model8.RoleAdmin, source, message)
}

var PoolHelper NotificationPoolHelper
