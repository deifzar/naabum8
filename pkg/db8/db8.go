package db8

import (
	"database/sql"
	"deifzar/naabum8/pkg/log8"
	"fmt"

	_ "github.com/lib/pq"
)

type Db8 struct {
	location string
	port     int
	schema   string
	database string
	username string
	password string
}

func (d *Db8) InitDatabase8(l string, port int, sc, db, u, p string) {
	d.location = l
	d.port = port
	d.schema = sc
	d.database = db
	d.username = u
	d.password = p
}

func (d *Db8) SetLocation(l string) {
	d.location = l
}

func (d *Db8) GetLocation() string {
	return d.location
}

func (d *Db8) SetUsername(u string) {
	d.username = u
}

func (d *Db8) GetUsername() string {
	return d.username
}

func (d *Db8) SetPassword(p string) {
	d.password = p
}

func (d *Db8) GetPassword() string {
	return d.password
}

func (d *Db8) GetConnectionString() string {
	// "user=postgres dbname=yourdatabase sslmode=disable password=yourpassword host=localhost"
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable search_path=%s", d.location, d.port, d.username, d.password, d.database, d.schema)
	// return fmt.Sprintf("postgresql://%s:%s@%s/todos?sslmode=disable", d.location, d.username, d.password)
}

func (d *Db8) OpenConnection() (*sql.DB, error) {
	db, err := sql.Open("postgres", d.GetConnectionString())
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		return nil, err
	}
	return db, nil
}
