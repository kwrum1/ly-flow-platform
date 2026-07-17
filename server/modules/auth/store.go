package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 用户存储接口
type Store interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, id int64) (*User, error)
	UpdateLastLogin(ctx context.Context, userID int64) error
}

// PostgresStore PostgreSQL存储实现
type PostgresStore struct {
	db *pgxpool.Pool
}

// NewPostgresStore 创建PostgreSQL存储
func NewPostgresStore(db *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{db: db}
}

// InitSchema 初始化数据库表
func (s *PostgresStore) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(20) NOT NULL DEFAULT 'viewer',
			is_active BOOLEAN NOT NULL DEFAULT true,
			must_change_password BOOLEAN NOT NULL DEFAULT false,
			failed_login_count INTEGER NOT NULL DEFAULT 0,
			locked_until TIMESTAMP,
			last_login_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`,
		`CREATE TABLE IF NOT EXISTS auth_sessions (
			token VARCHAR(64) PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON auth_sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON auth_sessions(expires_at)`,
		`CREATE TABLE IF NOT EXISTS bootstrap_tokens (
			state_key SMALLINT PRIMARY KEY CHECK (state_key = 1),
			token_hash BYTEA NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			recovered BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS bootstrap_audit (
			id BIGSERIAL PRIMARY KEY,
			action TEXT NOT NULL,
			occurred_at TIMESTAMPTZ NOT NULL
		)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// CreateUser 创建用户
func (s *PostgresStore) CreateUser(ctx context.Context, user *User) error {
	query := `
		INSERT INTO users (username, password_hash, role, is_active, must_change_password, failed_login_count, locked_until, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`
	now := time.Now()
	return s.db.QueryRow(
		ctx, query,
		user.Username, user.PasswordHash, user.Role, user.IsActive, user.MustChangePassword, user.FailedLoginCount, user.LockedUntil, now, now,
	).Scan(&user.ID)
}

// GetUserByUsername 通过用户名获取用户
func (s *PostgresStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	query := `
		SELECT id, username, password_hash, role, is_active, must_change_password, failed_login_count, locked_until, last_login_at, created_at, updated_at
		FROM users WHERE username = $1
	`
	user := &User{}
	err := s.db.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Role,
		&user.IsActive, &user.MustChangePassword, &user.FailedLoginCount, &user.LockedUntil,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return user, err
}

// GetUserByID 通过ID获取用户
func (s *PostgresStore) GetUserByID(ctx context.Context, id int64) (*User, error) {
	query := `
		SELECT id, username, password_hash, role, is_active, must_change_password, failed_login_count, locked_until, last_login_at, created_at, updated_at
		FROM users WHERE id = $1
	`
	user := &User{}
	err := s.db.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Role,
		&user.IsActive, &user.MustChangePassword, &user.FailedLoginCount, &user.LockedUntil,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return user, err
}

// UpdateLastLogin 更新最后登录时间
func (s *PostgresStore) UpdateLastLogin(ctx context.Context, userID int64) error {
	query := `UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1`
	_, err := s.db.Exec(ctx, query, userID)
	return err
}

func (s *PostgresStore) RecordFailedLogin(ctx context.Context, userID int64, lockThreshold int, lockDuration time.Duration) error {
	query := `
		UPDATE users
		SET failed_login_count = failed_login_count + 1,
			locked_until = CASE WHEN failed_login_count + 1 > $2 THEN NOW() + $3::interval ELSE locked_until END,
			updated_at = NOW()
		WHERE id = $1
	`
	interval := fmt.Sprintf("%d seconds", int(lockDuration.Seconds()))
	_, err := s.db.Exec(ctx, query, userID, lockThreshold, interval)
	return err
}

func (s *PostgresStore) ResetLoginFailures(ctx context.Context, userID int64) error {
	query := `UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = NOW() WHERE id = $1`
	_, err := s.db.Exec(ctx, query, userID)
	return err
}

func (s *PostgresStore) MarkPasswordChanged(ctx context.Context, userID int64, passwordHash string) error {
	query := `UPDATE users SET password_hash = $2, must_change_password = false, failed_login_count = 0, locked_until = NULL, updated_at = NOW() WHERE id = $1`
	_, err := s.db.Exec(ctx, query, userID, passwordHash)
	return err
}

// SessionStore 会话存储
type SessionStore struct {
	db *pgxpool.Pool
}

// NewSessionStore 创建会话存储
func NewSessionStore(db *pgxpool.Pool) *SessionStore {
	return &SessionStore{db: db}
}

// CreateSession 创建会话
func (s *SessionStore) CreateSession(ctx context.Context, token string, userID int64, expiresAt time.Time) error {
	query := `
		INSERT INTO auth_sessions (token, user_id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (token) DO UPDATE SET expires_at = $3
	`
	_, err := s.db.Exec(ctx, query, token, userID, expiresAt)
	return err
}

// GetSessionByToken 通过Token获取会话
func (s *SessionStore) GetSessionByToken(ctx context.Context, token string) (*Session, error) {
	query := `
		SELECT token, user_id, expires_at, created_at
		FROM auth_sessions
		WHERE token = $1 AND expires_at > NOW()
	`
	session := &Session{}
	err := s.db.QueryRow(ctx, query, token).Scan(
		&session.Token, &session.UserID, &session.ExpiresAt, &session.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTokenExpired
	}
	return session, err
}

// DeleteSession 删除会话
func (s *SessionStore) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM auth_sessions WHERE token = $1`
	_, err := s.db.Exec(ctx, query, token)
	return err
}

// DeleteUserSessions 删除用户的所有会话
func (s *SessionStore) DeleteUserSessions(ctx context.Context, userID int64) error {
	query := `DELETE FROM auth_sessions WHERE user_id = $1`
	_, err := s.db.Exec(ctx, query, userID)
	return err
}

// CleanExpiredSessions 清理过期会话
func (s *SessionStore) CleanExpiredSessions(ctx context.Context) error {
	_, err := s.db.Exec(ctx, "DELETE FROM auth_sessions WHERE expires_at < NOW()")
	return err
}

// InitDefaultAdmin 创建默认管理员账号（仅在不存在时创建）
func InitDefaultAdmin(store *PostgresStore, authService *Service) error {
	ctx := context.Background()
	password := strings.TrimSpace(os.Getenv("DEFAULT_ADMIN_PASSWORD"))
	if password == "" {
		password = "password"
	}

	existing, err := store.GetUserByUsername(ctx, "admin")
	if err == nil {
		if strings.EqualFold(strings.TrimSpace(os.Getenv("LYFLOW_RESET_ADMIN_PASSWORD")), "true") {
			hash, hashErr := authService.HashPassword(password)
			if hashErr != nil {
				return hashErr
			}
			_, execErr := store.db.Exec(ctx, `UPDATE users SET password_hash=$1, must_change_password=true, failed_login_count=0, locked_until=NULL, updated_at=NOW() WHERE id=$2`, hash, existing.ID)
			return execErr
		}
		if existing.MustChangePassword {
			return nil
		}
		if existing.LastLoginAt == nil && strings.EqualFold(strings.TrimSpace(os.Getenv("LYFLOW_FORCE_FIRST_LOGIN_PASSWORD_CHANGE")), "true") {
			_, execErr := store.db.Exec(ctx, `UPDATE users SET must_change_password=true, updated_at=NOW() WHERE id=$1`, existing.ID)
			return execErr
		}
		return nil
	}
	if !errors.Is(err, ErrUserNotFound) {
		return err
	}

	hash, err := authService.HashPassword(password)
	if err != nil {
		return err
	}

	user := &User{
		Username:           "admin",
		PasswordHash:       hash,
		Role:               RoleAdmin,
		IsActive:           true,
		MustChangePassword: true,
	}

	return store.CreateUser(ctx, user)
}
