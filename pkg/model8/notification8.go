package model8

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type Notificationevent string
type Notificationchannel string
type Roletype string

const (
	Message  Notificationevent = "message"        // message chat event type.
	Security Notificationevent = "security"       // security discovery event type.
	Error    Notificationevent = "system_error"   // error application event type.
	Warning  Notificationevent = "system_warning" // warning application event type.
)

const (
	App   Notificationchannel = "app"
	Email Notificationchannel = "email"
	Sms   Notificationchannel = "sms"
)

const (
	RoleUser  Roletype = "user"  // standard
	RoleAdmin Roletype = "admin" // Admin
)

type NotificationMetadata8 struct {
	Room         string              `json:"room,omitempty"`
	Relativepath string              `json:"relativepath,omitempty"`
	Senderid     *uuid.UUID          `json:"senderid,omitempty"`
	Sendername   string              `json:"sendername,omitempty"`
	Senderemail  string              `json:"senderemail,omitempty"`
	Senderimage  string              `json:"senderimage,omitempty"`
	Severity     string              `json:"severity,omitempty"`
	Channeltype  Notificationchannel `json:"channeltype,omitempty"`
	Eventtype    Notificationevent   `json:"eventtype,omitempty"`
}

type Notification8 struct {
	Id         *uuid.UUID            `json:"id,omitempty"`
	Userid     *uuid.UUID            `json:"userid,omitempty"`
	Userrole   Roletype              `json:"userrole,omitempty"`
	Type       Notificationevent     `json:"type"`
	Message    string                `json:"message"`
	Metadata   NotificationMetadata8 `json:"metadata,omitempty"`
	Read       bool                  `json:"read,omitempty"`
	Created_at *time.Time            `json:"created_at,omitempty"`
}
