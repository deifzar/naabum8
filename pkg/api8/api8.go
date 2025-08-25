package api8

import (
	"database/sql"
	"deifzar/naabum8/pkg/cleanup8"
	"deifzar/naabum8/pkg/configparser"
	"deifzar/naabum8/pkg/controller8"
	"deifzar/naabum8/pkg/db8"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/orchestrator8"

	"github.com/spf13/viper"

	"os"
	"time"

	"github.com/gin-gonic/gin"
)

type Api8 struct {
	Cnfg   *viper.Viper
	DB     *sql.DB
	Router *gin.Engine
}

func (a *Api8) Init() error {
	// Create log and tmp directories if they don't exist
	if err := os.MkdirAll("log", 0755); err != nil {
		log8.BaseLogger.Error().Err(err).Msg("Failed to create log directory")
		return err
	}
	if err := os.MkdirAll("tmp", 0755); err != nil {
		log8.BaseLogger.Error().Err(err).Msg("Failed to create tmp directory")
		return err
	}

	// Clean up old files in tmp directory (older than 24 hours)
	cleanup := cleanup8.NewCleanup8()
	if err := cleanup.CleanupDirectory("tmp", 24*time.Hour); err != nil {
		log8.BaseLogger.Error().Err(err).Msg("Failed to cleanup tmp directory")
		// Don't return error here as cleanup failure shouldn't prevent startup
	}
	v, err := configparser.InitConfigParser()
	if err != nil {
		log8.BaseLogger.Debug().Stack().Msg(err.Error())
		log8.BaseLogger.Info().Msg("Error initialising the config parser.")
		return err
	}
	location := v.GetString("Database.location")
	port := v.GetInt("Database.port")
	schema := v.GetString("Database.schema")
	database := v.GetString("Database.database")
	username := v.GetString("Database.username")
	password := v.GetString("Database.password")

	var db db8.Db8
	db.InitDatabase8(location, port, schema, database, username, password)
	conn, err := db.OpenConnection()
	if err != err {
		log8.BaseLogger.Error().Msg("Error connecting into DB.")
		return err
	}
	orchestrator8, err := orchestrator8.NewOrchestrator8()
	if err != nil {
		log8.BaseLogger.Error().Msg("Error connecting to the RabbitMQ server.")
	}
	err = orchestrator8.InitOrchestrator()
	if err != nil {
		log8.BaseLogger.Error().Msg("Error bringing up the RabbitMQ exchanges.")
		return err
	}
	err = orchestrator8.ActivateQueueByService("naabum8")
	if err != nil {
		log8.BaseLogger.Error().Msg("Error bringing up the RabbitMQ queues for the `naabum8` service.")
		return err
	}
	err = orchestrator8.ActivateConsumerByService("naabum8")
	if err != nil {
		log8.BaseLogger.Error().Msg("Error activating consumer with dedicated connection for the `naabum8` service.")
		return err
	}

	a.Cnfg = v
	a.DB = conn
	return nil
}

func (a *Api8) Routes() {
	r := gin.Default()
	// scan
	contrNaabum8 := controller8.NewController8Naabum8(a.DB, a.Cnfg)
	r.GET("/scan", contrNaabum8.Naabum8Scan)
	r.POST("/scan", contrNaabum8.Naabum8Hostnames)
	r.GET("/scan/domain/:id", contrNaabum8.Naabum8Domain)

	a.Router = r
}

func (a *Api8) Run(addr string) {
	a.Router.Run(addr)
}
