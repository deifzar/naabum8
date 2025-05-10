package db8

import (
	"database/sql"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"
	"time"

	"github.com/gofrs/uuid/v5"
)

type Db8Hostname8 struct {
	Db *sql.DB
}

func NewDb8Hostname8(db *sql.DB) Db8Hostname8Interface {
	return &Db8Hostname8{Db: db}
}

func (m *Db8Hostname8) GetAllHostnameByParentID(domainid uuid.UUID) ([]model8.Hostname8, error) {
	query, err := m.Db.Query("SELECT id, name, foundfirsttime, live, domainid, enabled FROM ONLY cptm8hostname WHERE domainid = $1", domainid)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Hostname8{}, err
	}
	var hostnames []model8.Hostname8
	if query != nil {
		for query.Next() {
			var (
				id             uuid.UUID
				name           string
				foundfirsttime time.Time
				live           bool
				domainid       uuid.UUID
				enabled        bool
			)
			err := query.Scan(&id, &name, &foundfirsttime, &live, &domainid, &enabled)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			h := model8.Hostname8{Id: id, Name: name, Foundfirsttime: foundfirsttime, Live: live, Domainid: domainid, Enabled: enabled}
			hostnames = append(hostnames, h)
		}
	}
	return hostnames, nil
}

// GetAllEnabled retrieves all hostnames that are enabled and the parent domain is enabled
func (m *Db8Hostname8) GetAllEnabled() ([]model8.Hostname8, error) {
	query, err := m.Db.Query("SELECT id, name, foundfirsttime, live, domainid, enabled FROM ONLY cptm8hostname WHERE enabled = true AND domainid IN (SELECT id FROM cptm8domain WHERE enabled = true)")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Hostname8{}, err
	}
	var hostnames []model8.Hostname8
	if query != nil {
		for query.Next() {
			var (
				id             uuid.UUID
				name           string
				foundfirsttime time.Time
				live           bool
				domainid       uuid.UUID
				enabled        bool
			)
			err := query.Scan(&id, &name, &foundfirsttime, &live, &domainid, &enabled)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			h := model8.Hostname8{Id: id, Name: name, Foundfirsttime: foundfirsttime, Live: live, Domainid: domainid, Enabled: enabled}
			hostnames = append(hostnames, h)
		}
	}
	return hostnames, nil
}

func (m *Db8Hostname8) GetAllEnabledByParentID(domainid uuid.UUID) ([]model8.Hostname8, error) {
	query, err := m.Db.Query("SELECT id, name, foundfirsttime, live, domainid, enabled FROM ONLY cptm8hostname WHERE domainid = $1 and enabled = true", domainid)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Hostname8{}, err
	}
	var hostnames []model8.Hostname8
	if query != nil {
		for query.Next() {
			var (
				id             uuid.UUID
				name           string
				foundfirsttime time.Time
				live           bool
				domainid       uuid.UUID
				enabled        bool
			)
			err := query.Scan(&id, &name, &foundfirsttime, &live, &domainid, &enabled)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			h := model8.Hostname8{Id: id, Name: name, Foundfirsttime: foundfirsttime, Live: live, Domainid: domainid, Enabled: enabled}
			hostnames = append(hostnames, h)
		}
	}
	return hostnames, nil
}

func (m *Db8Hostname8) GetOneHostnameByID(id uuid.UUID) (model8.Hostname8, error) {
	query, err := m.Db.Query("SELECT id, name, foundFirstTime, live, domainid, enabled FROM ONLY cptm8hostname WHERE id = $1", id)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return model8.Hostname8{}, err
	}
	var hostname model8.Hostname8
	if query != nil {
		for query.Next() {
			var (
				id             uuid.UUID
				name           string
				foundfirsttime time.Time
				live           bool
				domainid       uuid.UUID
				enabled        bool
			)
			err := query.Scan(&id, &name, &foundfirsttime, &live, &domainid, &enabled)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return model8.Hostname8{}, err
			}
			hostname = model8.Hostname8{Id: id, Name: name, Foundfirsttime: foundfirsttime, Live: live, Domainid: domainid, Enabled: enabled}
		}
	}
	return hostname, nil
}

func (m *Db8Hostname8) GetOneHostnameByName(name string) (model8.Hostname8, error) {
	query, err := m.Db.Query("SELECT id, name, foundfirsttime, live, domainid, enabled FROM ONLY cptm8hostname WHERE name = $1", name)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return model8.Hostname8{}, err
	}
	var hostname model8.Hostname8
	if query != nil {
		for query.Next() {
			var (
				id             uuid.UUID
				name           string
				foundfirsttime time.Time
				live           bool
				domainid       uuid.UUID
				enabled        bool
			)
			err := query.Scan(&id, &name, &foundfirsttime, &live, &domainid, &enabled)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return model8.Hostname8{}, err
			}
			hostname = model8.Hostname8{Id: id, Name: name, Foundfirsttime: foundfirsttime, Live: live, Domainid: domainid, Enabled: enabled}
		}
	}
	return hostname, nil
}

func (m *Db8Hostname8) ValidPostBody(post model8.PostHostname8) bool {
	for _, p := range post.Target {
		var id uuid.UUID
		pid, err := uuid.FromString(p.Id)
		if err != nil {
			return false
		}
		err = m.Db.QueryRow("SELECT id FROM ONLY cptm8hostname WHERE id = $1 AND name = $2", pid, p.Name).Scan(&id)
		switch {
		case err == sql.ErrNoRows:
			return false
		case err != nil:
			return false
		default:
			continue
		}
	}
	return true
}

func (m *Db8Hostname8) UpdateHostname(domainid, id uuid.UUID, post model8.PHostname8) (model8.Hostname8, error) {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return model8.Hostname8{}, err
	}
	stmt, err := tx.Prepare("UPDATE cptm8hostname SET name = $1 WHERE domainid = $2 AND id = $3")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return model8.Hostname8{}, err
	}
	defer stmt.Close()
	var err2 error
	_, err2 = stmt.Exec(post.Name, domainid, id)
	if err2 != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Stack().Msg(err2.Error())
		return model8.Hostname8{}, err2
	}
	var h model8.Hostname8
	h, err = m.GetOneHostnameByID(id)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return model8.Hostname8{}, err
	}
	return h, nil
}
