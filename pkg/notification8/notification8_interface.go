package notification8

import "deifzar/naabum8/pkg/model8"

// NotificationServiceInterface defines the contract for notification services
type NotificationServiceInterface interface {
	// PublishNotification publishes an notification through the message queue
	// routing key totally customisable. Examples:
	// "app.*.*"" -> the notification via the web app only
	// "email.*.*", "#.urgent", "#.critical", "#.high" -> the notification via email
	PublishNotification(routingKey string, eventType model8.Notificationevent, severity string, userRole model8.Roletype, source string, message string) error
}

// NotificationHelperInterface defines the contract for notification helpers
type NotificationHelperInterface interface {
	// PublishErrorNotification sends a `security` notification to the web app to admin users. If severity is `urgent`, `critical` or `high`, the notification will be sent via email too
	PublishSecurityNotificationAdmin(message string, severity string, source string) error

	// PublishErrorNotification sends a `security` notification to the web app to normal users. If severity is `urgent`, `critical` or `high`, the notification will be sent via email too
	PublishSecurityNotificationUser(message string, severity string, source string) error

	// PublishErrorNotification sends an error notification to admins
	PublishSysErrorNotification(message string, severity string, source string) error

	// PublishWarningNotification sends a warning notification to admins
	PublishSysWarningNotification(message string, severity string, source string) error
}
