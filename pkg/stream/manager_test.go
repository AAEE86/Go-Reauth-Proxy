package stream

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
)

func TestHandleConnMarksLoggedInActiveOnSuccessfulAuth(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer authServer.Close()

	authURL, err := url.Parse(authServer.URL)
	if err != nil {
		t.Fatalf("failed to parse auth server url: %v", err)
	}
	authPort, err := strconv.Atoi(authURL.Port())
	if err != nil {
		t.Fatalf("failed to parse auth server port: %v", err)
	}

	upstreamListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start upstream listener: %v", err)
	}
	defer upstreamListener.Close()

	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		conn, err := upstreamListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		n, err := io.ReadFull(conn, buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()

	handler := proxy.NewHandler(7996, 7999, nil, &config.AppConfig{
		Rules:        []models.Rule{},
		HostRules:    []models.HostRule{},
		StreamRules:  []models.StreamRule{},
		DefaultRoute: "/__select__",
		AuthConfig: models.AuthConfig{
			AuthPort:     authPort,
			AuthURL:      "/",
			LoginURL:     "/login",
			LogoutURL:    "/api/auth/logout",
			PreflightURL: "/api/auth/preflight",
		},
	}, t.TempDir())

	manager := NewManager(handler)
	rule := models.StreamRule{
		ListenPort: 3306,
		Target:     upstreamListener.Addr().String(),
		UseAuth:    true,
	}

	manager.mu.Lock()
	manager.rules[rule.ListenPort] = rule
	manager.mu.Unlock()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.handleConn(serverConn, rule.ListenPort)
	}()

	want := []byte("ping")
	if _, err := clientConn.Write(want); err != nil {
		t.Fatalf("failed to write to stream client: %v", err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatalf("failed to read echoed data: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected echoed payload: got %q want %q", got, want)
	}

	_ = clientConn.Close()
	<-done
	<-upstreamDone

	stats := handler.GetTrafficStats(time.Now())
	if stats.ActiveConns != 1 {
		t.Fatalf("expected one active logged-in stream client, got %d", stats.ActiveConns)
	}
}
