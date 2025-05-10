package db8

import (
	"deifzar/naabum8/pkg/model8"

	"github.com/gofrs/uuid/v5"
)

type Db8Endpoint8Interface interface {
	GetAllByDomainID(uuid.UUID) ([]model8.Endpoint8, error)
	GetAllHTTPByDomainID(uuid.UUID) ([]model8.Endpoint8, error)
	GetAllByHostnameID(uuid.UUID) ([]model8.Endpoint8, error)
	GetAllHTTPByHostnameID(uuid.UUID) ([]model8.Endpoint8, error)
	GetOneEndpointByID(uuid.UUID) (model8.Endpoint8, error)
	InsertOne(string, uuid.UUID) error
	InsertMultiple([]string, uuid.UUID) error
	InsertBatch([]model8.Endpoint8) error
	UpdateOneByEndpoint(string, bool) error
	UpdateMultipleByEndpoint([]string, bool) error
}
