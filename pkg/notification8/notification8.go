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

// NewNotificationService creates a new notification service instance
func NewNotificationService() (*NotificationService, error) {
	orchestrator, err := orchestrator8.NewOrchestrator8()
	if err != nil {
		return nil, fmt.Errorf("failed to create orchestrator: %w", err)
	}

	return &NotificationService{
		orchestrator: orchestrator,
	}, nil
}

// PublishNotification publishes an notification through the message queue
// routing key totally customisable. Examples:
// "app.*.*"" -> the notification via the web app only
// "email.*.*", "#.urgent", "#.critical", "#.high" -> the notification via email
func (ns *NotificationService) PublishNotification(routingKey string, eventType model8.Notificationevent, severity string, userRole model8.Roletype, source string, message string) error {
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

	err := ns.orchestrator.PublishToExchangeAndCloseChannelConnection("notification", routingKey, notification, source)
	if err != nil {
		log8.BaseLogger.Error().Err(err).Msg("Failed to publish notification")
		return fmt.Errorf("failed to publish notification: %w", err)
	}

	return nil
}

// NotificationHelper provides static helper methods for common notification scenarios
type NotificationHelper struct{}

// PublishErrorNotification sends a `security` notification to the web app to admin users. If severity is `urgent`, `critical` or `high`, the notification will be sent via email too
func (NotificationHelper) PublishSecurityNotificationAdmin(message string, severity string, source string) error {
	service, err := NewNotificationService()
	if err != nil {
		return fmt.Errorf("failed to create notification service: %w", err)
	}

	return service.PublishNotification("app.security."+severity, model8.Security, severity, model8.RoleAdmin, message, source)
}

// PublishErrorNotification sends a `security` notification to the web app to normal users. If severity is `urgent`, `critical` or `high`, the notification will be sent via email too
func (NotificationHelper) PublishSecurityNotificationUser(message string, severity string, source string) error {
	service, err := NewNotificationService()
	if err != nil {
		return fmt.Errorf("failed to create notification service: %w", err)
	}

	return service.PublishNotification("app.security."+severity, model8.Security, severity, model8.RoleUser, message, source)
}

// PublishErrorNotification sends an error notification to admins
func (NotificationHelper) PublishSysErrorNotification(message string, severity string, source string) error {
	service, err := NewNotificationService()
	if err != nil {
		return fmt.Errorf("failed to create notification service: %w", err)
	}

	return service.PublishNotification("app.error."+severity, model8.Error, severity, model8.RoleAdmin, message, source)
}

// PublishWarningNotification sends a warning notification to admins
func (NotificationHelper) PublishSysWarningNotification(message string, severity string, source string) error {
	service, err := NewNotificationService()
	if err != nil {
		return fmt.Errorf("failed to create notification service: %w", err)
	}

	return service.PublishNotification("app.warning."+severity, model8.Warning, severity, model8.RoleAdmin, message, source)
}

// Global helper instance
var Helper NotificationHelper
