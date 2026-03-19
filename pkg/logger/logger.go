package logger

import (
	stdlog "log"
	"os"
	"time"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

func Setup() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimestampFieldName = "time"
	zerolog.LevelFieldName = "level"
	zerolog.MessageFieldName = "message"

	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	zlog.Logger = logger

	stdlog.SetFlags(0)
	stdlog.SetOutput(logger)
}
