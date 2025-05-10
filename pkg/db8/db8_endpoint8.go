package db8

import (
	"database/sql"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"

	"github.com/gofrs/uuid/v5"
)

type Db8Endpoint8 struct {
	Db *sql.DB
}

func NewDb8Endpoint8(db *sql.DB) Db8Endpoint8Interface {
	return &Db8Endpoint8{Db: db}
}

func (m *Db8Endpoint8) GetAllByDomainID(domainID uuid.UUID) ([]model8.Endpoint8, error) {
	query, err := m.Db.Query("SELECT id, endpoint, live, hostnameid FROM ONLY cptm8endpoint WHERE hostnameid IN (SELECT id FROM ONLY cptm8hostname WHERE domainid = $1)", domainID)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Endpoint8{}, err
	}
	var endpoints []model8.Endpoint8
	if query != nil {
		for query.Next() {
			var (
				id         uuid.UUID
				endpoint   string
				live       bool
				hostnameid uuid.UUID
			)
			err := query.Scan(&id, &endpoint, &live, &hostnameid)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			e := model8.Endpoint8{Id: id, Endpoint: endpoint, Live: live, Hostnameid: hostnameid}
			endpoints = append(endpoints, e)
		}
	}
	return endpoints, nil
}

func (m *Db8Endpoint8) GetAllHTTPByDomainID(domainID uuid.UUID) ([]model8.Endpoint8, error) {
	query, err := m.Db.Query("SELECT id, endpoint, live, hostnameid FROM ONLY cptm8endpoint WHERE endpoint LIKE 'http%' AND hostnameid IN (SELECT id FROM ONLY cptm8hostname WHERE domainid = $1)", domainID)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Endpoint8{}, err
	}
	var endpoints []model8.Endpoint8
	if query != nil {
		for query.Next() {
			var (
				id         uuid.UUID
				endpoint   string
				live       bool
				hostnameid uuid.UUID
			)
			err := query.Scan(&id, &endpoint, &live, &hostnameid)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			e := model8.Endpoint8{Id: id, Endpoint: endpoint, Live: live, Hostnameid: hostnameid}
			endpoints = append(endpoints, e)
		}
	}
	return endpoints, nil
}

func (m *Db8Endpoint8) GetAllByHostnameID(hostnameID uuid.UUID) ([]model8.Endpoint8, error) {
	query, err := m.Db.Query("SELECT id, endpoint, live, hostnameid FROM ONLY cptm8endpoint WHERE hostnameid = $1", hostnameID)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Endpoint8{}, err
	}
	var endpoints []model8.Endpoint8
	if query != nil {
		for query.Next() {
			var (
				id         uuid.UUID
				endpoint   string
				live       bool
				hostnameid uuid.UUID
			)
			err := query.Scan(&id, &endpoint, &live, &hostnameid)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			e := model8.Endpoint8{Id: id, Endpoint: endpoint, Live: live, Hostnameid: hostnameid}
			endpoints = append(endpoints, e)
		}
	}
	return endpoints, nil
}

func (m *Db8Endpoint8) GetAllHTTPByHostnameID(hostnameID uuid.UUID) ([]model8.Endpoint8, error) {
	query, err := m.Db.Query("SELECT id, endpoint, live, hostnameid FROM ONLY cptm8endpoint WHERE endpoint LIKE 'http%' AND hostnameid = $1", hostnameID)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Endpoint8{}, err
	}
	var endpoints []model8.Endpoint8
	if query != nil {
		for query.Next() {
			var (
				id         uuid.UUID
				endpoint   string
				live       bool
				hostnameid uuid.UUID
			)
			err := query.Scan(&id, &endpoint, &live, &hostnameid)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			e := model8.Endpoint8{Id: id, Endpoint: endpoint, Live: live, Hostnameid: hostnameid}
			endpoints = append(endpoints, e)
		}
	}
	return endpoints, nil
}

func (m *Db8Endpoint8) GetOneEndpointByID(endpointID uuid.UUID) (model8.Endpoint8, error) {
	query, err := m.Db.Query("SELECT id, endpoint, live, hostnameid FROM ONLY cptm8endpoint WHERE id = $1", endpointID)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return model8.Endpoint8{}, err
	}
	var e model8.Endpoint8
	if query != nil {
		for query.Next() {
			var (
				id         uuid.UUID
				endpoint   string
				live       bool
				hostnameid uuid.UUID
			)
			err := query.Scan(&id, &endpoint, &hostnameid)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return model8.Endpoint8{}, err
			}
			e = model8.Endpoint8{Id: id, Endpoint: endpoint, Live: live, Hostnameid: hostnameid}
		}
	}
	return e, nil
}

func (m *Db8Endpoint8) InsertOne(endpoint string, hostnameID uuid.UUID) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO cptm8endpoint (endpoint, live, hostnameid) VALUES ($1,true,$2) ON CONFLICT (endpoint) DO UPDATE SET live = EXCLUDED.live")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	defer stmt.Close()
	var err2 error
	_, err2 = stmt.Exec(endpoint, hostnameID)
	if err2 != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Stack().Msg(err2.Error())
		return err2
	}
	err2 = tx.Commit()
	if err2 != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Stack().Msg(err2.Error())
		return err
	}
	return nil
}

func (m *Db8Endpoint8) InsertMultiple(endpoints []string, hostnameID uuid.UUID) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO cptm8endpoint (endpoint, live, hostnameid) VALUES ($1, true, $2) ON CONFLICT (endpoint) DO UPDATE SET live = EXCLUDED.live")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	defer stmt.Close()
	var err2 error
	for _, ep := range endpoints {
		_, err2 := stmt.Exec(ep, hostnameID)
		if err2 != nil {
			_ = tx.Rollback()
			log8.BaseLogger.Debug().Stack().Msg(err2.Error())
			return err2
		}
	}
	err2 = tx.Commit()
	if err2 != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Stack().Msg(err2.Error())
		return err
	}
	return nil
}

func (m *Db8Endpoint8) InsertBatch(httpEndpoint8 []model8.Endpoint8) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO cptm8endpoint (endpoint, live, hostnameid) VALUES ($1,true,$2) ON CONFLICT (endpoint) DO UPDATE SET live = EXCLUDED.live")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	defer stmt.Close()
	var err2 error
	for _, h := range httpEndpoint8 {
		_, err2 = stmt.Exec(h.Endpoint, h.Hostnameid)
		if err2 != nil {
			_ = tx.Rollback()
			log8.BaseLogger.Debug().Stack().Msg(err2.Error())
			return err2
		}
	}
	err2 = tx.Commit()
	if err2 != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Stack().Msg(err2.Error())
		return err
	}
	return nil
}

func (m *Db8Endpoint8) UpdateOneByEndpoint(endpoint string, live bool) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	_, err = tx.Exec("UPDATE cptm8endpoint SET live = $1 WHERE endpoint = $2", live, endpoint)
	if err != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	err = tx.Commit()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	return nil
}

func (m *Db8Endpoint8) UpdateMultipleByEndpoint(endpoints []string, live bool) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	stmt, err := tx.Prepare("UPDATE cptm8endpoint SET live = $1 WHERE endpoint = $2")
	if err != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	defer stmt.Close()
	for _, ep := range endpoints {
		_, err2 := stmt.Exec(live, ep)
		if err2 != nil {
			_ = tx.Rollback()
			log8.BaseLogger.Debug().Stack().Msg(err2.Error())
			return err2
		}
	}
	err = tx.Commit()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	return nil
}
