package gatewaylog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go-reauth-proxy/pkg/models"

	"github.com/rs/zerolog"
)

const (
	DefaultMaxDays = 7
	dateLayout     = "2006-01-02"
	fileExtension  = ".log"
	maxScanToken   = 8 * 1024 * 1024
)

type Entry struct {
	Time          string `json:"time,omitempty"`
	Level         string `json:"level,omitempty"`
	Method        string `json:"method,omitempty"`
	Scheme        string `json:"scheme,omitempty"`
	Host          string `json:"host,omitempty"`
	Path          string `json:"path,omitempty"`
	Query         string `json:"query,omitempty"`
	RequestURI    string `json:"request_uri,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Status        int    `json:"status"`
	DurationMs    int64  `json:"duration_ms"`
	RemoteIP      string `json:"remote_ip,omitempty"`
	RemoteAddr    string `json:"remote_addr,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
	Referer       string `json:"referer,omitempty"`
	LoggedIn      bool   `json:"logged_in"`
	AuthRequired  bool   `json:"auth_required"`
	AuthDecision  string `json:"auth_decision,omitempty"`
	AccessMode    string `json:"access_mode,omitempty"`
	RouteType     string `json:"route_type,omitempty"`
	RouteKey      string `json:"route_key,omitempty"`
	Upstream      string `json:"upstream,omitempty"`
	Matched       bool   `json:"matched"`
	BytesIn       uint64 `json:"bytes_in"`
	BytesOut      uint64 `json:"bytes_out"`
	TLS           bool   `json:"tls"`
	WebSocket     bool   `json:"websocket"`
	XForwardedFor string `json:"x_forwarded_for,omitempty"`
	XRealIP       string `json:"x_real_ip,omitempty"`
}

type ConfigInfo struct {
	Enabled bool   `json:"enabled"`
	MaxDays int    `json:"max_days"`
	LogsDir string `json:"logs_dir"`
}

type DirectoryInfo struct {
	LogsDir string `json:"logs_dir"`
}

type DatesResult struct {
	Today   string   `json:"today"`
	LogsDir string   `json:"logs_dir"`
	Dates   []string `json:"dates"`
}

type QueryResult struct {
	Date           string   `json:"date"`
	LogsDir        string   `json:"logs_dir"`
	AvailableDates []string `json:"available_dates"`
	Page           int      `json:"page"`
	Limit          int      `json:"limit"`
	Total          int      `json:"total"`
	Items          []Entry  `json:"items"`
}

type DeleteResult struct {
	Date           string   `json:"date"`
	LogsDir        string   `json:"logs_dir"`
	Deleted        bool     `json:"deleted"`
	AvailableDates []string `json:"available_dates"`
}

type DailyFileWriter struct {
	baseDir       string
	mu            sync.Mutex
	retentionDays int
	currentDate   string
	currentFile   *os.File
	lastCleanup   string
	dirReady      bool
}

func NewDailyFileWriter(baseDir string, retentionDays int) *DailyFileWriter {
	return &DailyFileWriter{
		baseDir:       baseDir,
		retentionDays: normalizeMaxDays(retentionDays),
	}
}

func (w *DailyFileWriter) SetRetentionDays(days int) {
	w.mu.Lock()
	w.retentionDays = normalizeMaxDays(days)
	w.mu.Unlock()
}

func (w *DailyFileWriter) Cleanup() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cleanupLocked(time.Now())
}

func (w *DailyFileWriter) DeleteDate(date string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentDate == date && w.currentFile != nil {
		_ = w.currentFile.Close()
		w.currentFile = nil
		w.currentDate = ""
	}

	logPath := w.pathForDate(date)
	if err := os.Remove(logPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (w *DailyFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	if err := w.ensureDirLocked(); err != nil {
		return 0, err
	}
	if err := w.rotateLocked(now); err != nil {
		return 0, err
	}
	if err := w.maybeCleanupLocked(now); err != nil {
		return 0, err
	}
	if w.currentFile == nil {
		return 0, fmt.Errorf("log file is not open")
	}
	return w.currentFile.Write(p)
}

func (w *DailyFileWriter) ensureDirLocked() error {
	if w.dirReady {
		return nil
	}
	if err := os.MkdirAll(w.baseDir, 0o755); err != nil {
		return err
	}
	w.dirReady = true
	return nil
}

func (w *DailyFileWriter) maybeCleanupLocked(now time.Time) error {
	date := now.Format(dateLayout)
	if w.lastCleanup == date {
		return nil
	}
	if err := w.cleanupLocked(now); err != nil {
		return err
	}
	w.lastCleanup = date
	return nil
}

func (w *DailyFileWriter) rotateLocked(now time.Time) error {
	date := now.Format(dateLayout)
	if w.currentDate == date && w.currentFile != nil {
		return nil
	}

	if w.currentFile != nil {
		_ = w.currentFile.Close()
		w.currentFile = nil
	}

	file, err := os.OpenFile(w.pathForDate(date), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}

	w.currentDate = date
	w.currentFile = file
	return nil
}

func (w *DailyFileWriter) cleanupLocked(now time.Time) error {
	entries, err := os.ReadDir(w.baseDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	retentionDays := normalizeMaxDays(w.retentionDays)
	cutoff := dayStart(now).AddDate(0, 0, -(retentionDays - 1))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		date, ok := parseFileDate(entry.Name())
		if !ok {
			continue
		}
		if date.Before(cutoff) {
			if err := os.Remove(filepath.Join(w.baseDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func (w *DailyFileWriter) pathForDate(date string) string {
	return filepath.Join(w.baseDir, date+fileExtension)
}

type Manager struct {
	mu      sync.RWMutex
	config  models.LoggingConfig
	logsDir string
	writer  *DailyFileWriter
	logger  zerolog.Logger
}

func NormalizeConfig(cfg models.LoggingConfig) models.LoggingConfig {
	cfg.MaxDays = normalizeMaxDays(cfg.MaxDays)
	return cfg
}

func DefaultLogsDir(runtimeDir string) string {
	return filepath.Join(runtimeDir, "logs")
}

func NewManager(logsDir string, cfg models.LoggingConfig) *Manager {
	normalized := NormalizeConfig(cfg)
	writer := NewDailyFileWriter(logsDir, normalized.MaxDays)
	logger := zerolog.New(writer).With().Timestamp().Logger()

	return &Manager{
		config:  normalized,
		logsDir: logsDir,
		writer:  writer,
		logger:  logger,
	}
}

func (m *Manager) GetConfigInfo() ConfigInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return ConfigInfo{
		Enabled: m.config.Enabled,
		MaxDays: m.config.MaxDays,
		LogsDir: m.logsDir,
	}
}

func (m *Manager) UpdateConfig(cfg models.LoggingConfig) ConfigInfo {
	normalized := NormalizeConfig(cfg)

	m.mu.Lock()
	m.config = normalized
	m.writer.SetRetentionDays(normalized.MaxDays)
	m.mu.Unlock()

	_ = m.writer.Cleanup()
	return m.GetConfigInfo()
}

func (m *Manager) LogsDir() string {
	return m.logsDir
}

func (m *Manager) Log(entry Entry) {
	m.mu.RLock()
	enabled := m.config.Enabled
	logger := m.logger
	m.mu.RUnlock()

	if !enabled {
		return
	}

	event := logger.Info()
	event.Str("method", entry.Method).
		Str("scheme", entry.Scheme).
		Str("host", entry.Host).
		Str("path", entry.Path).
		Str("query", entry.Query).
		Str("request_uri", entry.RequestURI).
		Str("protocol", entry.Protocol).
		Int("status", entry.Status).
		Int64("duration_ms", entry.DurationMs).
		Str("remote_ip", entry.RemoteIP).
		Str("remote_addr", entry.RemoteAddr).
		Str("user_agent", entry.UserAgent).
		Str("referer", entry.Referer).
		Bool("logged_in", entry.LoggedIn).
		Bool("auth_required", entry.AuthRequired).
		Str("auth_decision", entry.AuthDecision).
		Str("access_mode", entry.AccessMode).
		Str("route_type", entry.RouteType).
		Str("route_key", entry.RouteKey).
		Str("upstream", entry.Upstream).
		Bool("matched", entry.Matched).
		Uint64("bytes_in", entry.BytesIn).
		Uint64("bytes_out", entry.BytesOut).
		Bool("tls", entry.TLS).
		Bool("websocket", entry.WebSocket).
		Str("x_forwarded_for", entry.XForwardedFor).
		Str("x_real_ip", entry.XRealIP).
		Send()
}

func (m *Manager) GetDates() (DatesResult, error) {
	dates, err := m.listDates(true)
	if err != nil {
		return DatesResult{}, err
	}

	return DatesResult{
		Today:   time.Now().Format(dateLayout),
		LogsDir: m.logsDir,
		Dates:   dates,
	}, nil
}

func (m *Manager) Query(date string, page int, limit int, search string) (QueryResult, error) {
	selectedDate, err := normalizeDate(date)
	if err != nil {
		return QueryResult{}, err
	}

	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}

	items := make([]Entry, 0)
	logPath := filepath.Join(m.logsDir, selectedDate+fileExtension)
	file, err := os.Open(logPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return QueryResult{}, err
		}
	} else {
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), maxScanToken)
		search = strings.ToLower(strings.TrimSpace(search))

		for scanner.Scan() {
			line := scanner.Text()
			if search != "" && !strings.Contains(strings.ToLower(line), search) {
				continue
			}

			var entry Entry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				continue
			}
			items = append(items, entry)
		}

		if err := scanner.Err(); err != nil {
			return QueryResult{}, err
		}
	}

	reverseEntries(items)
	total := len(items)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	dates, err := m.listDates(true)
	if err != nil {
		return QueryResult{}, err
	}

	return QueryResult{
		Date:           selectedDate,
		LogsDir:        m.logsDir,
		AvailableDates: dates,
		Page:           page,
		Limit:          limit,
		Total:          total,
		Items:          items[start:end],
	}, nil
}

func (m *Manager) DeleteDate(date string) (DeleteResult, error) {
	selectedDate, err := normalizeDate(date)
	if err != nil {
		return DeleteResult{}, err
	}

	deleted, err := m.writer.DeleteDate(selectedDate)
	if err != nil {
		return DeleteResult{}, err
	}

	dates, err := m.listDates(true)
	if err != nil {
		return DeleteResult{}, err
	}

	return DeleteResult{
		Date:           selectedDate,
		LogsDir:        m.logsDir,
		Deleted:        deleted,
		AvailableDates: dates,
	}, nil
}

func (m *Manager) listDates(includeToday bool) ([]string, error) {
	entries, err := os.ReadDir(m.logsDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		entries = nil
	}

	dateSet := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		date, ok := parseFileDate(entry.Name())
		if !ok {
			continue
		}
		dateSet[date.Format(dateLayout)] = struct{}{}
	}

	if includeToday {
		dateSet[time.Now().Format(dateLayout)] = struct{}{}
	}

	dates := make([]string, 0, len(dateSet))
	for date := range dateSet {
		dates = append(dates, date)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dates)))
	return dates, nil
}

func normalizeMaxDays(days int) int {
	if days <= 0 {
		return DefaultMaxDays
	}
	return days
}

func dayStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

func parseFileDate(fileName string) (time.Time, bool) {
	if filepath.Ext(fileName) != fileExtension {
		return time.Time{}, false
	}

	base := strings.TrimSuffix(fileName, fileExtension)
	parsed, err := time.Parse(dateLayout, base)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func normalizeDate(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Now().Format(dateLayout), nil
	}

	parsed, err := time.Parse(dateLayout, raw)
	if err != nil {
		return "", fmt.Errorf("invalid date, expected format YYYY-MM-DD")
	}
	return parsed.Format(dateLayout), nil
}

func reverseEntries(items []Entry) {
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
}
