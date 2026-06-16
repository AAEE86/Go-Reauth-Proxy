package admin

import (
	"bytes"
	"encoding/json"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
)

func TestGeneralBlacklistAdminHandlers(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	proxyHandler := proxy.NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	server := NewServer(proxyHandler, 7996, cfgManager, initialCfg, nil)

	body, _ := json.Marshal(generalBlacklistRequest{
		IPs:     []string{"203.0.113.30", "2001:db8::30"},
		Source:  models.GeneralBlacklistSourceActiveIP,
		Comment: "active clients",
	})
	addReq := httptest.NewRequest(http.MethodPost, "/api/general-blacklist", bytes.NewReader(body))
	addRec := httptest.NewRecorder()
	server.handleAddGeneralBlacklist(addRec, addReq)
	if addRec.Code != http.StatusOK {
		t.Fatalf("add status = %d, body = %s", addRec.Code, addRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/general-blacklist?page=1&limit=10&search=203.0.113", nil)
	listRec := httptest.NewRecorder()
	server.handleListGeneralBlacklist(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Success bool                        `json:"success"`
		Data    models.GeneralBlacklistList `json:"data"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if !listResp.Success || listResp.Data.Total != 1 || listResp.Data.Items[0].IP != "203.0.113.30" {
		t.Fatalf("list response = %#v, want one matching IP", listResp)
	}

	statusBody, _ := json.Marshal(generalBlacklistRequest{
		IPs: []string{"203.0.113.30:443", "198.51.100.1", "[2001:db8::30]"},
	})
	statusReq := httptest.NewRequest(http.MethodPost, "/api/general-blacklist/status", bytes.NewReader(statusBody))
	statusRec := httptest.NewRecorder()
	server.handleGeneralBlacklistStatus(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", statusRec.Code, statusRec.Body.String())
	}
	var statusResp struct {
		Success bool                          `json:"success"`
		Data    models.GeneralBlacklistStatus `json:"data"`
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if !statusResp.Success || len(statusResp.Data.Records) != 2 {
		t.Fatalf("status response = %#v, want two matching records", statusResp)
	}
	if _, exists := statusResp.Data.Records["198.51.100.1"]; exists {
		t.Fatalf("status response unexpectedly included missing IP: %#v", statusResp.Data.Records)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/general-blacklist/203.0.113.30", nil)
	deleteReq = mux.SetURLVars(deleteReq, map[string]string{"ip": "203.0.113.30"})
	deleteRec := httptest.NewRecorder()
	server.handleDeleteGeneralBlacklistIP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", deleteRec.Code, deleteRec.Body.String())
	}

	listReq = httptest.NewRequest(http.MethodGet, "/api/general-blacklist?page=1&limit=10", nil)
	listRec = httptest.NewRecorder()
	server.handleListGeneralBlacklist(listRec, listReq)
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response after delete: %v", err)
	}
	if listResp.Data.Total != 1 || listResp.Data.Items[0].IP != "2001:db8::30" {
		t.Fatalf("list after delete = %#v, want only IPv6 item", listResp.Data)
	}
}

func TestGeneralBlacklistAdminRejectsInvalidIP(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	proxyHandler := proxy.NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	server := NewServer(proxyHandler, 7996, cfgManager, initialCfg, nil)

	body, _ := json.Marshal(generalBlacklistRequest{IPs: []string{"127.0.0.1"}})
	req := httptest.NewRequest(http.MethodPost, "/api/general-blacklist", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAddGeneralBlacklist(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with JSON error; body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Success bool `json:"success"`
		Code    int  `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.Success || resp.Code != 400 {
		t.Fatalf("response = %#v, want success=false code=400", resp)
	}

	statusBody, _ := json.Marshal(generalBlacklistRequest{IPs: []string{"bad-ip", "127.0.0.1", "0.0.0.0"}})
	statusReq := httptest.NewRequest(http.MethodPost, "/api/general-blacklist/status", bytes.NewReader(statusBody))
	statusRec := httptest.NewRecorder()
	server.handleGeneralBlacklistStatus(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", statusRec.Code, statusRec.Body.String())
	}
	var statusResp struct {
		Success bool                          `json:"success"`
		Data    models.GeneralBlacklistStatus `json:"data"`
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if !statusResp.Success || len(statusResp.Data.Records) != 0 {
		t.Fatalf("status response = %#v, want empty success", statusResp)
	}
}
