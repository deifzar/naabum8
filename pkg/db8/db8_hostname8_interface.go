package db8

import (
	"deifzar/naabum8/pkg/model8"

	"github.com/gofrs/uuid/v5"
)

type Db8Hostname8Interface interface {
	GetAllHostnameByParentID(uuid.UUID) ([]model8.Hostname8, error)
	GetAllEnabled() ([]model8.Hostname8, error)
	GetAllEnabledByParentID(uuid.UUID) ([]model8.Hostname8, error)
	GetOneHostnameByID(uuid.UUID) (model8.Hostname8, error)
	GetOneHostnameByName(string) (model8.Hostname8, error)
	ValidPostBody(model8.PostHostname8) bool
	UpdateHostname(uuid.UUID, uuid.UUID, model8.PHostname8) (model8.Hostname8, error)
}
