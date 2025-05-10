package db8

import (
	"deifzar/naabum8/pkg/model8"

	"github.com/gofrs/uuid/v5"
	_ "github.com/lib/pq"
)

type Db8Hostnameinfo8Interface interface {
	InsertBatch([]model8.Hostnameinfo8) (bool, error)
	UpdateSoftware([]string, uuid.UUID, string, int) (bool, error)
	GetSoftware(uuid.UUID, string, int) ([]string, error)
}
