package db8

import (
	"database/sql"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"

	"github.com/gofrs/uuid/v5"
)

type Db8Service8 struct {
	Db *sql.DB
}

func NewDb8Service8(db *sql.DB) Db8Service8Interface {
	return &Db8Service8{Db: db}
}

func (m *Db8Service8) GetAllByHostnameID(hostnameID uuid.UUID) ([]model8.Service8, error) {
	query, err := m.Db.Query("SELECT id, protocol, service, port, tls, live, hostnameid FROM ONLY cptm8service WHERE hostnameid = $1", hostnameID)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return []model8.Service8{}, err
	}
	var services []model8.Service8
	if query != nil {
		for query.Next() {
			var (
				id         uuid.UUID
				protocol   string
				service    string
				port       uint
				tls        bool
				live       bool
				hostnameid uuid.UUID
			)
			err := query.Scan(&id, &protocol, &service, &port, &tls, &live, &hostnameid)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
			s := model8.Service8{Id: id, Protocol: protocol, Service: service, Port: port, Tls: tls, Live: live, Hostnameid: hostnameid}
			services = append(services, s)
		}
	}
	return services, nil
}

func (m *Db8Service8) GetOneServiceByID(serviceID uuid.UUID) (model8.Service8, error) {
	query, err := m.Db.Query("SELECT id, protocol, service, port, tls, live, hostnameid FROM ONLY cptm8service WHERE id = $1", serviceID)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return model8.Service8{}, err
	}
	var e model8.Service8
	if query != nil {
		for query.Next() {
			var (
				id         uuid.UUID
				protocol   string
				service    string
				port       uint
				tls        bool
				live       bool
				hostnameid uuid.UUID
			)
			err := query.Scan(&id, &protocol, &service, &port, &live, &hostnameid)
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return model8.Service8{}, err
			}
			e = model8.Service8{Id: id, Protocol: protocol, Service: service, Port: port, Tls: tls, Live: live, Hostnameid: hostnameid}
		}
	}
	return e, nil
}

func (m *Db8Service8) InsertService(ipaddress string, protocol string, service string, port uint, tls bool, live bool, hostnameid uuid.UUID) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO cptm8service (ipaddress, protocol, service, port, tls, live, hostnameid) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (ipaddress,protocol,port,hostnameid) DO UPDATE SET live = EXCLUDED.live")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	defer stmt.Close()
	var err2 error
	_, err2 = stmt.Exec(ipaddress, protocol, service, port, tls, live, hostnameid)
	if err2 != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Stack().Msg(err2.Error())
		return err2
	}
	err2 = tx.Commit()
	if err2 != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Stack().Msg(err2.Error())
		return err2
	}
	return nil
}

func (m *Db8Service8) InsertBatch(service8 []model8.Service8) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO cptm8service(ipaddress, protocol, service, port, tls, live, hostnameid) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (ipaddress,protocol,port,hostnameid) DO UPDATE SET live = EXCLUDED.live, service = EXCLUDED.service")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	defer stmt.Close()
	var err2 error
	for _, s := range service8 {
		_, err2 = stmt.Exec(s.IPaddress, s.Protocol, s.Service, s.Port, s.Tls, s.Live, s.Hostnameid)
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
		return err2
	}
	return nil
}

func (m *Db8Service8) DeleteServiceByHostnameID(hostnameID uuid.UUID) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	_, err = tx.Exec("DELETE FROM ONLY cptm8service WHERE hostnameid = $1", hostnameID)
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

func (m *Db8Service8) SetLiveColumnByHostnameID(live bool, hostnameID uuid.UUID) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	_, err = tx.Exec("UPDATE cptm8service SET live = $1 WHERE hostnameid = $2", live, hostnameID)
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

func (m *Db8Service8) UpdateLatest(hostnameID uuid.UUID, service8 []model8.Service8) error {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO cptm8service (protocol, service, port, tls, hostnameid) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return err
	}
	defer stmt.Close()
	var err2 error
	for _, s := range service8 {
		_, err2 := stmt.Exec(s.Protocol, s.Service, s.Port, s.Tls, s.Hostnameid)
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
		return err2
	}
	return nil
}
