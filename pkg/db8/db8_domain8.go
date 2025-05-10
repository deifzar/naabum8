package db8

import (
	"database/sql"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"

	"github.com/gofrs/uuid/v5"
)

type Db8Domain8 struct {
	Db *sql.DB
}

func NewDb8Domain8(db *sql.DB) Db8Domain8Interface {
	return &Db8Domain8{Db: db}
}

func (m *Db8Domain8) GetAllDomain() ([]model8.Domain8, error) {
	query, err := m.Db.Query("SELECT id, name, companyname FROM cptm8domain")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Domain8{}, err
	}
	var domains []model8.Domain8
	if query != nil {
		for query.Next() {
			var (
				id          uuid.UUID
				name        string
				companyname string
				enabled     bool
			)
			err := query.Scan(&id, &name, &companyname, &enabled)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			d := model8.Domain8{Id: id, Name: name, Companyname: companyname, Enabled: enabled}
			domains = append(domains, d)
		}
	}
	return domains, nil
}

func (m *Db8Domain8) GetAllEnabled(enabled bool) ([]model8.Domain8, error) {
	query, err := m.Db.Query("SELECT id, name, companyname, enabled FROM cptm8domain WHERE enabled = $1", enabled)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Domain8{}, err
	}
	var domains []model8.Domain8
	if query != nil {
		for query.Next() {
			var (
				id          uuid.UUID
				name        string
				companyname string
				enabled     bool
			)
			err := query.Scan(&id, &name, &companyname, &enabled)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			d := model8.Domain8{Id: id, Name: name, Companyname: companyname, Enabled: enabled}
			domains = append(domains, d)
		}
	}
	return domains, nil
}

func (m *Db8Domain8) GetOneDomain(id uuid.UUID) (model8.Domain8, error) {
	query, err := m.Db.Query("SELECT id, name, companyname, enabled FROM cptm8domain WHERE id = $1", id)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return model8.Domain8{}, err
	}
	var domain model8.Domain8
	if query != nil {
		for query.Next() {
			var (
				id          uuid.UUID
				name        string
				companyname string
				enabled     bool
			)
			err := query.Scan(&id, &name, &companyname, &enabled)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return model8.Domain8{}, err
			}
			domain = model8.Domain8{Id: id, Name: name, Companyname: companyname, Enabled: enabled}
		}
	}
	return domain, nil
}
