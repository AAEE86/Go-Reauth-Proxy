package middleware

import (
	"bufio"
	"fmt"
	"go-reauth-proxy/pkg/logger"
	"net"
	"net/http"
	"time"

	zlog "github.com/rs/zerolog/log"
)

const AdminHTTPLogEnv = logger.AdminHTTPLogEnv

type LogEntry struct {
	Time      string `json:"time"`
	Level     string `json:"level"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Duration  string `json:"duration"`
	UserAgent string `json:"user_agent"`
	RemoteIP  string `json:"remote_ip"`
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("the ResponseWriter doesn't support the Hijacker interface")
	}
	return hijacker.Hijack()
}

func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func Logger(next http.Handler) http.Handler {
	if !adminHTTPLoggingEnabled() {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		remoteIP := r.RemoteAddr
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
			remoteIP = host
		}

		event := zlog.Info()
		if rw.status >= 500 {
			event = zlog.Error()
		}
		if rw.status >= 400 && rw.status < 500 {
			event = zlog.Warn()
		}

		event.Str("component", "admin_http").
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", rw.status).
			Str("duration", duration.String()).
			Str("user_agent", r.UserAgent()).
			Str("remote_ip", remoteIP).
			Send()
	})
}

func adminHTTPLoggingEnabled() bool {
	return logger.ConsoleLoggingEnabled() || logger.BoolEnv(AdminHTTPLogEnv)
}
