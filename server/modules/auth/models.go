package auth

import (
	"time"
)

// UserRole 用户角色
type UserRole string

const (
	RoleAdmin   UserRole = "admin"
	RoleAnalyst UserRole = "analyst"
	RoleViewer  UserRole = "viewer"
)

// User 用户模型
type User struct {
	ID                 int64      `json:"id" db:"id"`
	Username           string     `json:"username" db:"username"`
	PasswordHash       string     `json:"-" db:"password_hash"`
	Role               UserRole   `json:"role" db:"role"`
	IsActive           bool       `json:"is_active" db:"is_active"`
	MustChangePassword bool       `json:"must_change_password" db:"must_change_password"`
	FailedLoginCount   int        `json:"failed_login_count" db:"failed_login_count"`
	LockedUntil        *time.Time `json:"locked_until" db:"locked_until"`
	LastLoginAt        *time.Time `json:"last_login_at" db:"last_login_at"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=6"`
}

// RegisterRequest 注册请求
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=6"`
	Role     string `json:"role"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token               string    `json:"token"`
	ExpiresAt           time.Time `json:"expires_at"`
	NeedsPasswordChange bool      `json:"needs_password_change"`
	User                UserInfo  `json:"user"`
}

// UserInfo 用户信息(不包含敏感信息)
type UserInfo struct {
	ID                  int64    `json:"id"`
	Username            string   `json:"username"`
	Role                UserRole `json:"role"`
	IsActive            bool     `json:"is_active"`
	NeedsPasswordChange bool     `json:"needs_password_change"`
	Locked              bool     `json:"locked"`
}

func (u *User) IsLocked(now time.Time) bool {
	return u != nil && u.LockedUntil != nil && u.LockedUntil.After(now)
}

func (u *User) SafeInfo(now time.Time) UserInfo {
	if u == nil {
		return UserInfo{}
	}
	return UserInfo{
		ID:                  u.ID,
		Username:            u.Username,
		Role:                u.Role,
		IsActive:            u.IsActive,
		NeedsPasswordChange: u.MustChangePassword,
		Locked:              u.IsLocked(now),
	}
}

// Session 会话
type Session struct {
	Token     string    `json:"token"`
	UserID    int64     `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// ProfileResponse 个人资料响应
type ProfileResponse struct {
	ID                  int64      `json:"id"`
	Username            string     `json:"username"`
	Role                UserRole   `json:"role"`
	IsActive            bool       `json:"is_active"`
	NeedsPasswordChange bool       `json:"needs_password_change"`
	LastLoginAt         *time.Time `json:"last_login_at"`
	CreatedAt           time.Time  `json:"created_at"`
}

// AuthError 认证错误
type AuthError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error implements error interface
func (e *AuthError) Error() string {
	return e.Message
}

// Common errors
var (
	ErrInvalidCredentials     = &AuthError{Code: 401, Message: "用户名或密码错误"}
	ErrUserNotFound           = &AuthError{Code: 404, Message: "用户不存在"}
	ErrUserExists             = &AuthError{Code: 409, Message: "用户名已存在"}
	ErrTokenExpired           = &AuthError{Code: 401, Message: "登录已过期"}
	ErrTokenInvalid           = &AuthError{Code: 401, Message: "无效的令牌"}
	ErrPermissionDenied       = &AuthError{Code: 403, Message: "权限不足"}
	ErrAccountLocked          = &AuthError{Code: 423, Message: "账号已锁定"}
	ErrPasswordChangeRequired = &AuthError{Code: 428, Message: "首次登录必须修改密码"}
)
