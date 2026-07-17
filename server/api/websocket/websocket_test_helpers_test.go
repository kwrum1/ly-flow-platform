package websocket

import (
	"testing"
	"time"
)

func waitForConnectedClients(t *testing.T, hub *Hub, expected int) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if hub.ClientCount() == expected {
				return
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for %d connected WebSocket clients; got %d", expected, hub.ClientCount())
		}
	}
}
