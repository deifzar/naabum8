package model8

import (
	"github.com/gofrs/uuid/v5"
)

type Domain8 struct {
	Id          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Companyname string    `json:"companyname"`
	Enabled     bool      `json:"enabled"`
}

type Domain8Uri struct {
	ID string `uri:"id" binding:"required,uuid"`
}
