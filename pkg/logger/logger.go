package logger

import (
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

const (
	ConsoleLogEnv   = "GO_REPROXY_LOG"
	AdminHTTPLogEnv = "GO_REPROXY_ADMIN_HTTP_LOG"
	DebugLogEnv     = "GO_REPROXY_DEBUG_LOG"
	DebugLogDirEnv  = "GO_REPROXY_DEBUG_LOG_DIR"

	DefaultDebugLogDir = "/tmp/__fnknock"
)

const debugDateLayout = "2006-01-02"

var (
	debugMu               sync.RWMutex
	debugEnabled          bool
	debugWriter           io.Writer = io.Discard
	debugLogger           zerolog.Logger
	debugWarnedWrite      atomic.Bool
	debugAdminPort        atomic.Pointer[debugAdminPortRedaction]
	debugRequestIDCounter atomic.Uint64
)

type debugAdminPortRedaction struct {
	port int
	text string
}

func Setup() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimestampFieldName = "time"
	zerolog.LevelFieldName = "level"
	zerolog.MessageFieldName = "message"

	configureDebugLoggerFromEnv()

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

type dailyFileWriter struct {
	baseDir     string
	mu          sync.Mutex
	currentDate string
	currentFile *os.File
	dirReady    bool
}

func newDailyFileWriter(baseDir string) *dailyFileWriter {
	return &dailyFileWriter{baseDir: baseDir}
}

func (w *dailyFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureDirLocked(); err != nil {
		return 0, err
	}
	if err := w.rotateLocked(time.Now()); err != nil {
		return 0, err
	}
	if w.currentFile == nil {
		return 0, fmt.Errorf("debug log file is not open")
	}
	return w.currentFile.Write(p)
}

func (w *dailyFileWriter) ensureDirLocked() error {
	if w.dirReady {
		return nil
	}
	if err := os.MkdirAll(w.baseDir, 0o755); err != nil {
		return err
	}
	w.dirReady = true
	return nil
}

func (w *dailyFileWriter) rotateLocked(now time.Time) error {
	date := now.Format(debugDateLayout)
	if w.currentDate == date && w.currentFile != nil {
		return nil
	}

	if w.currentFile != nil {
		_ = w.currentFile.Close()
		w.currentFile = nil
	}

	file, err := os.OpenFile(filepath.Join(w.baseDir, date+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	w.currentDate = date
	w.currentFile = file
	return nil
}

type warnOnceWriter struct {
	writer io.Writer
}

func (w warnOnceWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err != nil && debugWarnedWrite.CompareAndSwap(false, true) {
		_, _ = fmt.Fprintf(os.Stderr, "debug log write failed: %v\n", err)
	}
	return n, err
}

func configureDebugLoggerFromEnv() {
	if !BoolEnv(DebugLogEnv) {
		setDebugLogger(false, io.Discard)
		return
	}

	dir := strings.TrimSpace(os.Getenv(DebugLogDirEnv))
	if dir == "" {
		dir = DefaultDebugLogDir
	}
	setDebugLogger(true, warnOnceWriter{writer: newDailyFileWriter(dir)})
}

func setDebugLogger(enabled bool, writer io.Writer) {
	if writer == nil {
		writer = io.Discard
	}
	debugWarnedWrite.Store(false)
	logger := zerolog.New(writer).With().Timestamp().Logger().Level(zerolog.DebugLevel)

	debugMu.Lock()
	debugEnabled = enabled
	debugWriter = writer
	debugLogger = logger
	debugMu.Unlock()
}

func DebugEnabled() bool {
	debugMu.RLock()
	defer debugMu.RUnlock()
	return debugEnabled
}

func DebugEvent(component string, event string) *zerolog.Event {
	debugMu.RLock()
	enabled := debugEnabled
	logger := debugLogger
	debugMu.RUnlock()

	if !enabled {
		return nil
	}
	return logger.Debug().
		Str("component", SanitizeLogString(component)).
		Str("event", SanitizeLogString(event))
}

func SetDebugAdminPortForRedaction(port int) {
	if port > 0 && port <= 65535 {
		debugAdminPort.Store(&debugAdminPortRedaction{
			port: port,
			text: strconv.Itoa(port),
		})
		return
	}
	debugAdminPort.Store(nil)
}

func NextDebugRequestID() string {
	return strconv.FormatUint(debugRequestIDCounter.Add(1), 10)
}

func SanitizeLogString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	adminPort := debugAdminPort.Load()
	if adminPort == nil {
		return redactSensitiveString(value)
	}

	if port, ok := parsePort(value); ok && port == adminPort.port {
		return "[admin-port]"
	}

	portText := adminPort.text
	if strings.Contains(value, "://") {
		value = redactAdminPortInURLs(value, portText)
	}
	if strings.Contains(value, ":") && !strings.ContainsAny(value, " \t\r\n") {
		value = redactAdminPortInHostPorts(value, portText)
	}
	if strings.Contains(value, ":") {
		colonPort := ":" + portText
		if strings.Contains(value, colonPort) {
			value = strings.ReplaceAll(value, colonPort, ":[admin-port]")
		}
	}
	if strings.Contains(value, portText) {
		value = redactStandaloneAdminPort(value, portText)
	}
	return redactSensitiveString(value)
}

func SanitizePort(port int) any {
	adminPort := debugAdminPort.Load()
	if adminPort != nil && port > 0 && port == adminPort.port {
		return "[admin-port]"
	}
	return port
}

func SanitizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return SanitizeLogString(raw)
	}
	if parsed.RawQuery != "" {
		query := parsed.Query()
		for key := range query {
			if IsSensitiveName(key) {
				query.Set(key, "[redacted]")
			}
		}
		parsed.RawQuery = query.Encode()
	}
	return SanitizeLogString(parsed.String())
}

func SanitizeHeader(header http.Header) map[string]any {
	if len(header) == 0 {
		return map[string]any{}
	}

	out := make(map[string]any, len(header))
	for name, values := range header {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" {
			continue
		}
		if IsSensitiveName(canonical) {
			out[canonical] = "[redacted]"
			continue
		}
		copied := make([]string, 0, len(values))
		for _, value := range values {
			copied = append(copied, SanitizeLogString(value))
		}
		out[canonical] = copied
	}
	return out
}

func SanitizedHeaderNames(header http.Header) []string {
	if len(header) == 0 {
		return nil
	}
	names := make([]string, 0, len(header))
	for name := range header {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical != "" {
			names = append(names, canonical)
		}
	}
	return names
}

func IsSensitiveName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	switch len(name) {
	case len("cookie"):
		if equalFoldASCIIString(name, "cookie") {
			return true
		}
	case len("set-cookie"):
		if equalFoldASCIIString(name, "set-cookie") {
			return true
		}
	case len("authorization"):
		if equalFoldASCIIString(name, "authorization") {
			return true
		}
	case len("proxy-authorization"):
		if equalFoldASCIIString(name, "proxy-authorization") {
			return true
		}
	}
	return containsFoldASCIIString(name, "token") ||
		containsFoldASCIIString(name, "password") ||
		containsFoldASCIIString(name, "passwd") ||
		containsFoldASCIIString(name, "secret") ||
		containsFoldASCIIString(name, "api-key") ||
		containsFoldASCIIString(name, "apikey") ||
		containsFoldASCIIString(name, "access-key") ||
		containsFoldASCIIString(name, "private-key") ||
		containsFoldASCIIString(name, "session")
}

func redactSensitiveString(value string) string {
	if containsSensitiveHeaderMarker(value) {
		return "[redacted]"
	}
	return value
}

func containsSensitiveHeaderMarker(value string) bool {
	for i := 0; i < len(value); i++ {
		switch lowerASCIIByte(value[i]) {
		case 'a':
			if hasFoldASCIIPrefix(value[i:], "authorization:") {
				return true
			}
		case 'c':
			if hasFoldASCIIPrefix(value[i:], "cookie:") {
				return true
			}
		case 's':
			if hasFoldASCIIPrefix(value[i:], "set-cookie:") {
				return true
			}
		}
	}
	return false
}

func equalFoldASCIIString(a string, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCIIByte(a[i]) != lowerASCIIByte(b[i]) {
			return false
		}
	}
	return true
}

func containsFoldASCIIString(value string, search string) bool {
	if search == "" {
		return true
	}
	if len(search) > len(value) {
		return false
	}
	first := lowerASCIIByte(search[0])
	last := len(value) - len(search)
	for i := 0; i <= last; i++ {
		if lowerASCIIByte(value[i]) != first {
			continue
		}
		if hasFoldASCIIPrefix(value[i:], search) {
			return true
		}
	}
	return false
}

func hasFoldASCIIPrefix(value string, prefix string) bool {
	if len(prefix) > len(value) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if lowerASCIIByte(value[i]) != lowerASCIIByte(prefix[i]) {
			return false
		}
	}
	return true
}

func lowerASCIIByte(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

func redactAdminPortInURLs(value string, portText string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return value
	}
	if isLocalHost(parsed.Hostname()) && parsed.Port() == portText {
		return strings.Replace(value, ":"+portText, ":[admin-port]", 1)
	}
	return parsed.String()
}

func redactAdminPortInHostPorts(value string, portText string) string {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port != portText || !isLocalHost(host) {
		return value
	}
	return net.JoinHostPort(host, "[admin-port]")
}

func parsePort(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	port := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		port = port*10 + int(c-'0')
		if port > 65535 {
			return 0, false
		}
	}
	if port == 0 {
		return 0, false
	}
	return port, true
}

func redactStandaloneAdminPort(value string, portText string) string {
	if portText == "" {
		return value
	}

	var builder strings.Builder
	replaced := false
	start := 0
	for {
		idx := strings.Index(value[start:], portText)
		if idx == -1 {
			if !replaced {
				return value
			}
			builder.WriteString(value[start:])
			break
		}
		idx += start
		end := idx + len(portText)
		if isDigitBoundary(value, idx-1) && isDigitBoundary(value, end) {
			if !replaced {
				builder.Grow(len(value) + len("[admin-port]") - len(portText))
				replaced = true
			}
			builder.WriteString(value[start:idx])
			builder.WriteString("[admin-port]")
			start = end
			continue
		}
		if replaced {
			builder.WriteString(value[start:end])
		}
		start = end
	}
	return builder.String()
}

func isDigitBoundary(value string, index int) bool {
	if index < 0 || index >= len(value) {
		return true
	}
	return value[index] < '0' || value[index] > '9'
}

func isLocalHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if equalFoldASCIIString(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
