package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (a *Agent) runRASPBridge() {
	addr := strings.TrimSpace(a.cfg.RASPBridgeAddr)
	if addr == "" {
		return
	}
	if err := validateRASPBridgeAddress(addr); err != nil {
		fmt.Printf("[rasp] local bridge disabled: %v\n", err)
		return
	}
	token := strings.TrimSpace(a.cfg.RASPBridgeToken)
	if token == "" {
		fmt.Printf("[rasp] local bridge disabled: authenticated token required\n")
		return
	}
	fallbackPath := "/opt/ly-agent/rasp/fallback/events.jsonl"
	if spoolDir := strings.TrimSpace(a.cfg.SpoolDir); spoolDir != "" {
		fallbackPath = filepath.Join(spoolDir, "rasp", "fallback-events.jsonl")
	}
	bridge, err := newRASPBridgeRuntime(a, raspBridgeRuntimeConfig{
		CurrentToken: token, FallbackPath: fallbackPath, QueueCapacity: raspBridgeDefaultQueueSize,
		TokenOverlap: raspBridgeTokenOverlap, Now: time.Now, Publisher: agentRASPBridgePublisher{agent: a}, StartWorker: true,
		Limits: agentRuntimeLimits(),
	})
	if err != nil {
		fmt.Printf("[rasp] local bridge disabled: %v\n", err)
		return
	}
	a.setRASPBridge(bridge)
	defer func() {
		bridge.Close()
		a.setRASPBridge(nil)
	}()
	listener, cleanup, err := listenRASPBridge(addr)
	if err != nil {
		fmt.Printf("[rasp] local bridge failed: %v\n", err)
		return
	}
	defer cleanup()
	server := &http.Server{
		Handler: bridge.Handler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	serveContext, stopServe := context.WithCancel(a.ctx)
	defer stopServe()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-serveContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	fmt.Printf("[rasp] authenticated local bridge listening on %s\n", addr)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("[rasp] local bridge failed: %v\n", err)
	}
	stopServe()
	<-shutdownDone
}

func validateRASPBridgeAddress(address string) error {
	if strings.HasPrefix(address, "unix://") {
		path := strings.TrimPrefix(address, "unix://")
		if !filepath.IsAbs(path) || path == "/" {
			return errors.New("RASP bridge Unix socket path must be absolute")
		}
		return nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(port) == "" {
		return errors.New("RASP bridge address must include loopback host and port")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("RASP bridge address must be loopback or local IPC")
	}
	return nil
}

func listenRASPBridge(address string) (net.Listener, func(), error) {
	if !strings.HasPrefix(address, "unix://") {
		listener, err := net.Listen("tcp", address)
		return listener, func() {}, err
	}
	path := strings.TrimPrefix(address, "unix://")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, func() {}, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, func() {}, errors.New("RASP bridge IPC path exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, func() {}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, func() {}, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, func() {}, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, func() {}, err
	}
	cleanup := func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}
	return listener, cleanup, nil
}
