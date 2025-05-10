package model8

import (
	"github.com/gofrs/uuid/v5"
)

type Hostnameinfo8 struct {
	Id         uuid.UUID `json:"id"`
	Software   []string  `json:"software"`
	Notes      string    `json:"notes"`
	Port       uint      `json:"port"`
	Protocol   string    `json:"protocol"`
	Hostnameid uuid.UUID `json:"hostnameid"`
}
