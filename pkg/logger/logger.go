package logger

import (
	"fmt"
	"io"
	stdlog "log"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

const (
	ConsoleLogEnv   = "GO_REPROXY_LOG"
	AdminHTTPLogEnv = "GO_REPROXY_ADMIN_HTTP_LOG"
)

func Setup() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimestampFieldName = "time"
	zerolog.LevelFieldName = "level"
	zerolog.MessageFieldName = "message"

	zerologWriter := io.Writer(io.Discard)
	if ConsoleLoggingEnabled() || BoolEnv(AdminHTTPLogEnv) {
		zerologWriter = os.Stdout
	}

	logger := zerolog.New(zerologWriter).With().Timestamp().Logger()
	zlog.Logger = logger

	stdlog.SetFlags(0)
	if ConsoleLoggingEnabled() {
		stdlog.SetOutput(logger)
		return
	}

	stdlog.SetOutput(io.Discard)
}

func ConsoleLoggingEnabled() bool {
	return BoolEnv(ConsoleLogEnv)
}

func BoolEnv(name string) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false
	}

	switch strings.ToLower(raw) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func Fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
