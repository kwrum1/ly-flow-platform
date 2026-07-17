package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

type bootstrapTokenCommand struct {
	Mode auth.BootstrapIssueMode
	TTL  time.Duration
}

func parseBootstrapTokenCommand(args []string) (bootstrapTokenCommand, bool, error) {
	if len(args) == 0 || args[0] != "bootstrap-token" {
		return bootstrapTokenCommand{}, false, nil
	}
	if len(args) < 2 {
		return bootstrapTokenCommand{}, true, errors.New("usage: bootstrap-token <create|recover> [--ttl 15m]")
	}
	command := bootstrapTokenCommand{TTL: 15 * time.Minute}
	switch args[1] {
	case string(auth.BootstrapCreate):
		command.Mode = auth.BootstrapCreate
	case string(auth.BootstrapRecover):
		command.Mode = auth.BootstrapRecover
	default:
		return bootstrapTokenCommand{}, true, fmt.Errorf("unknown bootstrap-token subcommand %q", args[1])
	}
	flags := flag.NewFlagSet("bootstrap-token", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.DurationVar(&command.TTL, "ttl", 15*time.Minute, "bootstrap token lifetime")
	if err := flags.Parse(args[2:]); err != nil {
		return bootstrapTokenCommand{}, true, fmt.Errorf("parse bootstrap-token flags: %w", err)
	}
	if flags.NArg() != 0 || command.TTL <= 0 || command.TTL > 15*time.Minute {
		return bootstrapTokenCommand{}, true, auth.ErrBootstrapTTLInvalid
	}
	return command, true, nil
}

func serviceLockPath() string {
	if path := os.Getenv("LYFLOW_SERVICE_LOCK_PATH"); path != "" {
		return path
	}
	return "/run/lyflow/ly-server.lock"
}

func acquireServiceLock(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create service lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open service lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("ly-server must be stopped: %w", err)
	}
	return file, nil
}

func runBootstrapTokenCLI(args []string) (bool, error) {
	command, handled, err := parseBootstrapTokenCommand(args[1:])
	if !handled || err != nil {
		return handled, err
	}
	if os.Geteuid() != 0 {
		return true, errors.New("bootstrap-token commands require root")
	}
	lock, err := acquireServiceLock(serviceLockPath())
	if err != nil {
		return true, err
	}
	defer func() { _ = lock.Close() }()
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return true, fmt.Errorf("open controlling terminal: %w", err)
	}
	defer func() { _ = tty.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := openBootstrapPool(ctx)
	if err != nil {
		return true, err
	}
	defer pool.Close()
	store := auth.NewPostgresStore(pool)
	if err := store.InitSchema(ctx); err != nil {
		return true, fmt.Errorf("initialize auth schema: %w", err)
	}
	manager := auth.NewBootstrapTokenManager(store, auth.NewService("bootstrap-password-hasher", time.Hour), tty)
	if err := manager.Issue(ctx, command.Mode, command.TTL); err != nil {
		return true, err
	}
	return true, nil
}

func openBootstrapPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s", getEnv("DB_USER", "lyflow"), getEnv("DB_PASSWORD", "lyflow_secret_password"), getEnv("DB_HOST", "postgres"), toInt(getEnv("DB_PORT", "5432")), getEnv("DB_NAME", "lyflow"), getEnv("DB_SSLMODE", "disable"))
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse bootstrap database config: %w", err)
	}
	poolConfig.MaxConns = 1
	poolConfig.MinConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open bootstrap database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping bootstrap database: %w", err)
	}
	return pool, nil
}
