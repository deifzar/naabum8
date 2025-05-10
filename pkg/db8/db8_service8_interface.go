package db8

import (
	"deifzar/naabum8/pkg/model8"

	"github.com/gofrs/uuid/v5"
)

type Db8Service8Interface interface {
	GetAllByHostnameID(uuid.UUID) ([]model8.Service8, error)
	GetOneServiceByID(uuid.UUID) (model8.Service8, error)
	InsertService(string, string, string, uint, bool, bool, uuid.UUID) error
	InsertBatch([]model8.Service8) error
	DeleteServiceByHostnameID(uuid.UUID) error
	SetLiveColumnByHostnameID(bool, uuid.UUID) error
	UpdateLatest(uuid.UUID, []model8.Service8) error
}
