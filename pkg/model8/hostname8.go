package model8

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type Hostname8 struct {
	Id             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	Foundfirsttime time.Time `json:"foundfirsttime"`
	Live           bool      `json:"live"`
	Domainid       uuid.UUID `json:"domainid"`
	Enabled        bool      `json:"enabled"`
}

type PHostname8 struct {
	Id   string `json:"id" binding:"uuid,required"`
	Name string `json:"name" binding:"required"`
	// IpAddress      string    `json:"ipAddress"`
	// FoundFirstTime time.Time `json:"foundFirstTime"`
	// Live          bool      `json:"live"`
	// ParentDomainID int `json:"parentDomain_id"`
}

type PostHostname8 struct {
	Target []PHostname8 `json:"target" binding:"required,dive"`
}
