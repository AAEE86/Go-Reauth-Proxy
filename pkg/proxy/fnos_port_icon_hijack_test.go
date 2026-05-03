package proxy

import (
	"encoding/json"
	"go-reauth-proxy/pkg/models"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestRewriteFnosPortIconHijackMessageRewritesEmptyHostPort(t *testing.T) {
	payload := []byte(`{
		"result":"succ",
		"data":{
			"list":[
				{
					"title":"Emby Server",
					"fullUrl":"",
					"uri":{
						"protocol":"http",
						"host":"",
						"port":"8096",
						"path":"/web/index.html"
					}
				}
			]
		}
	}`)
	targets := map[int]string{8096: "emby.example.com"}

	rewritten, changed, err := rewriteFnosPortIconHijackMessage(payload, targets, 18080)
	if err != nil {
		t.Fatalf("rewrite returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected payload to be rewritten")
	}

	var decoded struct {
		Data struct {
			List []struct {
				URI struct {
					Host string `json:"host"`
					Port string `json:"port"`
					Path string `json:"path"`
				} `json:"uri"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rewritten, &decoded); err != nil {
		t.Fatalf("rewritten JSON is invalid: %v", err)
	}
	if got := decoded.Data.List[0].URI.Host; got != "emby.example.com" {
		t.Fatalf("host = %q, want emby.example.com", got)
	}
	if got := decoded.Data.List[0].URI.Port; got != "18080" {
		t.Fatalf("port = %q, want 18080", got)
	}
	if got := decoded.Data.List[0].URI.Path; got != "" {
		t.Fatalf("path = %q, want empty string", got)
	}
}

func TestRewriteFnosPortIconHijackMessageSkipsNonEmptyHost(t *testing.T) {
	payload := []byte(`{"uri":{"host":"192.168.31.98","port":"8096"}}`)

	rewritten, changed, err := rewriteFnosPortIconHijackMessage(payload, map[int]string{8096: "emby.example.com"}, 18080)
	if err != nil {
		t.Fatalf("rewrite returned error: %v", err)
	}
	if changed {
		t.Fatal("expected payload to remain unchanged")
	}
	if string(rewritten) != string(payload) {
		t.Fatalf("payload changed unexpectedly: %s", rewritten)
	}
}

func TestBuildFnosPortIconHijackTargetsUsesHostRuleTargetPorts(t *testing.T) {
	targets := buildFnosPortIconHijackTargets([]models.HostRule{
		{Host: "Emby.Example.COM", Target: "http://127.0.0.1:8096"},
		{Host: "other.example.com", Target: "http://127.0.0.1:8096"},
		{Host: "jellyfin.example.com", Target: "https://192.168.31.98:8920"},
	})

	if got := targets[8096]; got != "emby.example.com" {
		t.Fatalf("target 8096 = %q, want emby.example.com", got)
	}
	if got := targets[8920]; got != "jellyfin.example.com" {
		t.Fatalf("target 8920 = %q, want jellyfin.example.com", got)
	}
}

func TestFnosPortIconHijackResponsePortUsesEdgeClientIPPort(t *testing.T) {
	handler := &Handler{
		ProxyPort: 18080,
		AuthConfig: models.AuthConfig{
			EdgeClientIPEnabled: true,
		},
	}

	if got := handler.fnosPortIconHijackResponsePort(); got != 80 {
		t.Fatalf("response port = %d, want 80", got)
	}
}

func TestFnosPortIconHijackWebSocketRewritesUpstreamMessages(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upstream upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		payload := []byte(`{"data":{"list":[{"uri":{"host":"","port":"8096","path":"/web/index.html"}}]}}`)
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Errorf("upstream write failed: %v", err)
		}
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	handler := &Handler{ProxyPort: 18080}
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := handler.proxyFnosPortIconHijackWebSocket(
			w,
			r,
			fnosPortIconHijackWebSocketOptions{targetURL: targetURL},
			map[int]string{8096: "emby.example.com"},
		)
		if err != nil && !isFNAppConnectionTermination(err) {
			t.Errorf("proxy websocket failed: %v", err)
		}
	}))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/websocket?type=main"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial proxy websocket: %v", err)
	}
	defer conn.Close()

	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read proxied websocket message: %v", err)
	}

	var decoded struct {
		Data struct {
			List []struct {
				URI struct {
					Host string `json:"host"`
					Port string `json:"port"`
					Path string `json:"path"`
				} `json:"uri"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(message, &decoded); err != nil {
		t.Fatalf("proxied message JSON is invalid: %v", err)
	}
	if got := decoded.Data.List[0].URI.Host; got != "emby.example.com" {
		t.Fatalf("host = %q, want emby.example.com", got)
	}
	if got := decoded.Data.List[0].URI.Port; got != "18080" {
		t.Fatalf("port = %q, want 18080", got)
	}
	if got := decoded.Data.List[0].URI.Path; got != "" {
		t.Fatalf("path = %q, want empty string", got)
	}
}
