package db8

import (
	"deifzar/naabum8/pkg/model8"

	"github.com/gofrs/uuid/v5"
)

type Db8Domain8Interface interface {
	GetAllDomain() ([]model8.Domain8, error)
	GetAllEnabled(bool) ([]model8.Domain8, error)
	GetOneDomain(uuid.UUID) (model8.Domain8, error)
}
