package log8

import (
	"deifzar/naabum8/pkg/configparser"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
	"gopkg.in/natefinch/lumberjack.v2"
)

var once sync.Once

var BaseLogger zerolog.Logger

// NewLogger initializes the standard logger
func GetLogger(logFilePath string) zerolog.Logger {

	once.Do(func() {
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
		zerolog.TimeFieldFormat = time.RFC3339Nano

		fileLogger := &lumberjack.Logger{
			Filename:   logFilePath,
			MaxSize:    100, //
			MaxBackups: 3,
			// MaxAge:     14,
			Compress: false,
		}

		// Force the log file to have 0640 permissions
		// This overrides lumberjack's default 0600
		// Need 640 permissions for vector to be able read
		os.Chmod(logFilePath, 0640)

		var output io.Writer = zerolog.ConsoleWriter{
			Out:        fileLogger,
			TimeFormat: time.RFC3339,
		}

		var logLevel int

		v, err := configparser.InitConfigParser()
		if err != nil {
			// error reading the config file
			logLevel = int(zerolog.InfoLevel)
		} else {
			logLevel, err = strconv.Atoi(v.GetString("LOG_LEVEL"))
			if err != nil {
				logLevel = int(zerolog.InfoLevel) // default to INFO
			}
			if v.GetString("APP_ENV") != "PROD" {
				output = zerolog.MultiLevelWriter(fileLogger, os.Stderr)
			}
		}

		var gitRevision string

		buildInfo, ok := debug.ReadBuildInfo()
		if ok {
			for _, v := range buildInfo.Settings {
				if v.Key == "vcs.revision" {
					gitRevision = v.Value
					break
				}
			}
		}
		// // Zerolog ECS log definition
		// BaseLogger = ecszerolog.New(output).
		// 	Level(zerolog.Level(logLevel)).
		// 	With().
		// 	Str("API_service", "NAABUM8").
		// 	Str("key", gitRevision).
		// 	Str("go_version", buildInfo.GoVersion).
		// 	Logger()

		// Zerolog standard definition:
		BaseLogger = zerolog.New(output).
			Level(zerolog.Level(logLevel)).
			With().
			Timestamp().
			Caller().
			Str("API_service", "NAABUM8").
			Str("key", gitRevision).
			Str("go_version", buildInfo.GoVersion).
			Logger()

	}) // once.Do

	return BaseLogger
}
