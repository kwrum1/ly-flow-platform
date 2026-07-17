package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// contextKey 用户上下文键
type contextKey string

const (
	UserContextKey  contextKey = "user"
	TokenContextKey contextKey = "token"
	RoleContextKey  contextKey = "role"
)

// Middleware JWT中间件
type Middleware struct {
	authService  *Service
	userStore    Store
	sessionStore sessionReader
}

type sessionReader interface {
	GetSessionByToken(context.Context, string) (*Session, error)
}

// NewMiddleware 创建中间件
func NewMiddleware(authService *Service, userStore Store, sessionStore sessionReader) *Middleware {
	return &Middleware{authService: authService, userStore: userStore, sessionStore: sessionStore}
}

// Authenticate 认证中间件
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeAuthError(w, http.StatusUnauthorized, "missing_authorization", "missing authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeAuthError(w, http.StatusUnauthorized, "invalid_authorization", "invalid authorization header")
			return
		}

		token := parts[1]
		if err := m.authService.ValidateToken(token); err != nil {
			writeAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid token")
			return
		}
		if m.sessionStore == nil || m.userStore == nil {
			writeAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid token")
			return
		}

		session, err := m.sessionStore.GetSessionByToken(r.Context(), token)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "token_expired_or_invalid", "token expired or invalid")
			return
		}
		user, err := m.userStore.GetUserByID(r.Context(), session.UserID)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "token_expired_or_invalid", "token expired or invalid")
			return
		}

		ctx := context.WithValue(r.Context(), TokenContextKey, token)
		ctx = context.WithValue(ctx, UserContextKey, user.ID)
		ctx = context.WithValue(ctx, RoleContextKey, user.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole 角色检查中间件
func (m *Middleware) RequireRole(allowedRoles ...UserRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := GetUserIDFromContext(r.Context())
			if userID == 0 {
				writeAuthError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
				return
			}
			role := GetRoleFromContext(r.Context())
			if !roleAllowed(role, allowedRoles) {
				writeAuthError(w, http.StatusForbidden, "forbidden", "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission 权限检查中间件
func (m *Middleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := GetUserIDFromContext(r.Context())
			if userID == 0 {
				writeAuthError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
				return
			}
			if !HasPermission(GetRoleFromContext(r.Context()), permission) {
				writeAuthError(w, http.StatusForbidden, "forbidden", "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func roleAllowed(role UserRole, allowedRoles []UserRole) bool {
	for _, allowed := range allowedRoles {
		if role == allowed {
			return true
		}
	}
	return false
}

func writeAuthError(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": status, "error_code": errorCode, "message": message})
}

// GetTokenFromContext 从Context获取Token
func GetTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(TokenContextKey).(string)
	return token
}

// GetUserIDFromContext 从Context获取用户ID
func GetUserIDFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(UserContextKey).(int64)
	return id
}

// GetRoleFromContext 从Context获取角色
func GetRoleFromContext(ctx context.Context) UserRole {
	role, _ := ctx.Value(RoleContextKey).(UserRole)
	return role
}

// CORSMiddleware CORS中间件
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware 简易限流中间件
func RateLimitMiddleware(next http.Handler, maxRequests int, window time.Duration) http.Handler {
	return next
}
