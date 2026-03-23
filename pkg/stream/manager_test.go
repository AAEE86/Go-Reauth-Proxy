package stream

import (
	"net"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
)

func TestReconcileRejectsSameLocalTargetPort(t *testing.T) {
	manager := NewManager(&proxy.Handler{})

	err := manager.Reconcile([]models.StreamRule{{
		ListenPort: 6379,
		Target:     "127.0.0.1:6379",
		UseAuth:    true,
	}})
	if err == nil {
		t.Fatal("expected reconcile to reject same local target port")
	}
	if !strings.Contains(err.Error(), "cannot target the same local address") {
		t.Fatalf("expected same-local-target error, got %v", err)
	}
}

func TestReconcileRejectsOccupiedListenPort(t *testing.T) {
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to reserve a test port: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	manager := NewManager(&proxy.Handler{})
	defer manager.Stop()

	err = manager.Reconcile([]models.StreamRule{{
		ListenPort: port,
		Target:     "127.0.0.1:1",
		UseAuth:    true,
	}})
	if err == nil {
		t.Fatal("expected reconcile to reject an occupied listen port")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected occupied-port error, got %v", err)
	}
}

func TestReconcileBestEffortSkipsInvalidAndOccupiedRules(t *testing.T) {
	occupiedListener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to reserve occupied port: %v", err)
	}
	defer occupiedListener.Close()

	validListener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to reserve valid port candidate: %v", err)
	}
	validPort := validListener.Addr().(*net.TCPAddr).Port
	_ = validListener.Close()

	occupiedPort := occupiedListener.Addr().(*net.TCPAddr).Port
	manager := NewManager(&proxy.Handler{})
	defer manager.Stop()

	startedRules, warnings := manager.ReconcileBestEffort([]models.StreamRule{
		{
			ListenPort: validPort,
			Target:     "127.0.0.1:1",
			UseAuth:    true,
		},
		{
			ListenPort: 6379,
			Target:     "127.0.0.1:6379",
			UseAuth:    true,
		},
		{
			ListenPort: occupiedPort,
			Target:     "127.0.0.1:1",
			UseAuth:    true,
		},
	})

	if len(startedRules) != 1 {
		t.Fatalf("expected 1 started rule, got %d", len(startedRules))
	}
	if startedRules[0].ListenPort != validPort {
		t.Fatalf("expected valid port %d to start, got %+v", validPort, startedRules[0])
	}
	if len(warnings) != 2 {
		t.Fatalf("expected 2 startup warnings, got %d (%v)", len(warnings), warnings)
	}

	if _, ok := manager.currentRule(validPort); !ok {
		t.Fatalf("expected current rule for valid port %d", validPort)
	}
	if _, ok := manager.currentRule(6379); ok {
		t.Fatal("did not expect invalid self-loop rule to be active")
	}
	if _, ok := manager.currentRule(occupiedPort); ok {
		t.Fatal("did not expect occupied-port rule to be active")
	}
}
