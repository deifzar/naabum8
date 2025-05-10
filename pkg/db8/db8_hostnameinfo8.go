package db8

import (
	"database/sql"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/model8"

	"github.com/gofrs/uuid/v5"
	"github.com/lib/pq"
)

type Db8Hostnameinfo8 struct {
	Db *sql.DB
}

func NewDb8Hostnameinfo8(db *sql.DB) Db8Hostnameinfo8Interface {
	return &Db8Hostnameinfo8{Db: db}
}

func (m *Db8Hostnameinfo8) GetSoftware(hid uuid.UUID, protocol string, port int) ([]string, error) {
	query, err := m.Db.Query("SELECT software FROM ONLY cptm8hostnameinfo WHERE hostnameid = $1 AND protocol = $2 AND port = $3", hid, protocol, port)
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return nil, err
	}
	var software []string
	if query != nil {
		for query.Next() {
			err := query.Scan(pq.Array(&software))
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				return nil, err
			}
		}
	}
	return software, nil
}

func (m *Db8Hostnameinfo8) UpdateSoftware(software []string, hid uuid.UUID, protocol string, port int) (bool, error) {
	tx, err := m.Db.Begin()
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		return false, err
	}
	stmt, err := tx.Prepare("INSERT INTO cptm8hostnameinfo (software, hostnameid, protocol, port) VALUES ($1, $2, $3, $4) ON CONFLICT (hostnameid, port, protocol) DO UPDATE SET software = EXCLUDED.software")
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		return false, err
	}
	defer stmt.Close()

	_, err2 := stmt.Exec(pq.Array(&software), hid, protocol, port)
	if err2 != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Msg(err2.Error())
		return false, err2
	}
	err = tx.Commit()
	if err != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Msg(err.Error())
		return false, err2
	}
	return true, nil
}

func (m *Db8Hostnameinfo8) InsertBatch(hostnameinfoList []model8.Hostnameinfo8) (bool, error) {
	tx, err := m.Db.Begin()
	if err != nil {
		return false, err
	}
	// enabled column value is `True` by default
	stmt, err := tx.Prepare("INSERT INTO cptm8hostnameinfo(hostnameid, port, protocol) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
	if err != nil {
		log8.BaseLogger.Debug().Msg(err.Error())
		return false, err
	}
	defer stmt.Close()
	var err2 error
	for _, hi := range hostnameinfoList {
		_, err2 = stmt.Exec(hi.Hostnameid, hi.Port, hi.Protocol)
		if err2 != nil {
			_ = tx.Rollback()
			log8.BaseLogger.Debug().Msg(err2.Error())
			return false, err2
		}
	}
	err2 = tx.Commit()
	if err2 != nil {
		_ = tx.Rollback()
		log8.BaseLogger.Debug().Msg(err2.Error())
		return false, err2
	}
	return true, nil
}
