package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Service 认证服务
type Service struct {
	secretKey   []byte
	tokenExpiry time.Duration
}

// NewService 创建认证服务
func NewService(secretKey string, tokenExpiry time.Duration) *Service {
	return &Service{
		secretKey:   []byte(secretKey),
		tokenExpiry: tokenExpiry,
	}
}

// HashPassword 密码哈希
func (s *Service) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// VerifyPassword 验证密码
func (s *Service) VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateToken 生成Token
func (s *Service) GenerateToken(userID int64) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.tokenExpiry)

	// 生成随机token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(tokenBytes)

	return token, expiresAt, nil
}

// ValidateToken 验证Token格式
func (s *Service) ValidateToken(token string) error {
	if len(token) != 64 {
		return errors.New("invalid token format")
	}
	// 检查是否为有效的hex
	_, err := hex.DecodeString(token)
	return err
}

// GetTokenExpiry 获取Token过期时间
func (s *Service) GetTokenExpiry() time.Duration {
	return s.tokenExpiry
}

// RolePermissions 角色权限映射
var RolePermissions = map[UserRole][]string{
	RoleAdmin: {
		"users:read", "users:write", "users:delete",
		"rules:read", "rules:write",
		"alerts:read", "alerts:write", "alerts:delete",
		"settings:read", "settings:write",
		"reports:read", "reports:write",
	},
	RoleAnalyst: {
		"alerts:read", "alerts:write",
		"rules:read",
		"reports:read",
	},
	RoleViewer: {
		"alerts:read",
		"rules:read",
		"reports:read",
	},
}

// HasPermission 检查角色是否有权限
func HasPermission(role UserRole, permission string) bool {
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}

// ValidateRole 验证角色是否有效
func ValidateRole(role string) bool {
	switch UserRole(role) {
	case RoleAdmin, RoleAnalyst, RoleViewer:
		return true
	default:
		return false
	}
}