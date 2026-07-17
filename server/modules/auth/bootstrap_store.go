package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) CreateBootstrapToken(ctx context.Context, tokenHash [32]byte, expiresAt time.Time, recovered bool) error {
	if s == nil || s.db == nil {
		return errors.New("bootstrap store unavailable")
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin bootstrap issue: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var adminExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')`).Scan(&adminExists); err != nil {
		return fmt.Errorf("check bootstrap admin: %w", err)
	}
	if recovered != adminExists {
		return ErrBootstrapRecoveryState
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO bootstrap_tokens (state_key, token_hash, expires_at, used_at, recovered, created_at, updated_at)
		VALUES (1, $1, $2, NULL, $3, NOW(), NOW())
		ON CONFLICT (state_key) DO UPDATE SET token_hash = EXCLUDED.token_hash,
			expires_at = EXCLUDED.expires_at, used_at = NULL, recovered = EXCLUDED.recovered,
			created_at = NOW(), updated_at = NOW()
	`, tokenHash[:], expiresAt, recovered); err != nil {
		return fmt.Errorf("upsert bootstrap token: %w", err)
	}
	action := "bootstrap_token_created"
	if recovered {
		action = "bootstrap_token_recovered"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bootstrap_audit (action, occurred_at) VALUES ($1, NOW())`, action); err != nil {
		return fmt.Errorf("audit bootstrap issue: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit bootstrap issue: %w", err)
	}
	return nil
}

func (s *PostgresStore) ConsumeBootstrapToken(ctx context.Context, tokenHash [32]byte, now time.Time, username, passwordHash string) error {
	if s == nil || s.db == nil {
		return errors.New("bootstrap store unavailable")
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin bootstrap consume: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var storedHash []byte
	var expiresAt time.Time
	var usedAt sql.NullTime
	var recovered bool
	err = tx.QueryRow(ctx, `SELECT token_hash, expires_at, used_at, recovered FROM bootstrap_tokens WHERE state_key = 1 FOR UPDATE`).Scan(
		&storedHash, &expiresAt, &usedAt, &recovered,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBootstrapTokenInvalid
	}
	if err != nil {
		return fmt.Errorf("read bootstrap token: %w", err)
	}
	var stored [32]byte
	copy(stored[:], storedHash)
	if len(storedHash) != len(stored) || !compareBootstrapHash(stored, tokenHash) {
		return ErrBootstrapTokenInvalid
	}
	if usedAt.Valid {
		return ErrBootstrapTokenUsed
	}
	if !expiresAt.After(now) {
		return ErrBootstrapTokenExpired
	}
	if recovered {
		result, err := tx.Exec(ctx, `UPDATE users SET password_hash=$1, is_active=true, must_change_password=true, failed_login_count=0, locked_until=NULL, updated_at=$2 WHERE username=$3 AND role='admin'`, passwordHash, now, username)
		if err != nil {
			return fmt.Errorf("recover bootstrap admin: %w", err)
		}
		if result.RowsAffected() != 1 {
			return ErrBootstrapRecoveryState
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth_sessions WHERE user_id = (SELECT id FROM users WHERE username=$1 AND role='admin')`, username); err != nil {
			return fmt.Errorf("close recovered admin sessions: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx, `INSERT INTO users (username, password_hash, role, is_active, must_change_password, failed_login_count, created_at, updated_at) VALUES ($1, $2, 'admin', true, true, 0, $3, $3)`, username, passwordHash, now); err != nil {
			return fmt.Errorf("create bootstrap admin: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE bootstrap_tokens SET used_at=$1, updated_at=$1 WHERE state_key=1`, now); err != nil {
		return fmt.Errorf("close bootstrap token: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bootstrap_audit (action, occurred_at) VALUES ($1, $2)`, "bootstrap_token_consumed", now); err != nil {
		return fmt.Errorf("audit bootstrap consume: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit bootstrap consume: %w", err)
	}
	return nil
}

func (s *PostgresStore) BootstrapTokenActive(ctx context.Context, now time.Time) (bool, error) {
	var active bool
	err := s.db.QueryRow(ctx, `SELECT used_at IS NULL AND expires_at > $1 FROM bootstrap_tokens WHERE state_key=1`, now).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read bootstrap state: %w", err)
	}
	return active, nil
}

func (s *PostgresStore) RevokeBootstrapToken(ctx context.Context, tokenHash [32]byte, now time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE bootstrap_tokens SET used_at=$1, updated_at=$1 WHERE state_key=1 AND token_hash=$2 AND used_at IS NULL`, now, tokenHash[:])
	if err != nil {
		return fmt.Errorf("revoke bootstrap token: %w", err)
	}
	return nil
}
