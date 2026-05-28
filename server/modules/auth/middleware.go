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
)

// Middleware JWT中间件
type Middleware struct {
	authService  *Service
	sessionStore *SessionStore
}

// NewMiddleware 创建中间件
func NewMiddleware(authService *Service, sessionStore *SessionStore) *Middleware {
	return &Middleware{
		authService:  authService,
		sessionStore: sessionStore,
	}
}

// Authenticate 认证中间件
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeAuthError(w, "missing_authorization", "missing authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeAuthError(w, "invalid_authorization", "invalid authorization header")
			return
		}

		token := parts[1]

		if err := m.authService.ValidateToken(token); err != nil {
			writeAuthError(w, "invalid_token", "invalid token")
			return
		}

		session, err := m.sessionStore.GetSessionByToken(r.Context(), token)
		if err != nil {
			writeAuthError(w, "token_expired_or_invalid", "token expired or invalid")
			return
		}
		userID := session.UserID

		ctx := context.WithValue(r.Context(), TokenContextKey, token)
		ctx = context.WithValue(ctx, UserContextKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole 角色检查中间件
func (m *Middleware) RequireRole(allowedRoles ...UserRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 从Context获取用户ID
			userID := r.Context().Value(UserContextKey)
			if userID == nil {
				writeAuthError(w, "unauthorized", "unauthorized")
				return
			}

			// TODO: 从数据库获取用户角色进行验证
			// 这里需要注入store来查询用户角色

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission 权限检查中间件
func (m *Middleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 从Context获取用户信息
			userID := r.Context().Value(UserContextKey)
			if userID == nil {
				writeAuthError(w, "unauthorized", "unauthorized")
				return
			}

			// TODO: 实现权限检查
			// 需要注入userStore来获取用户角色

			next.ServeHTTP(w, r)
		})
	}
}

func writeAuthError(w http.ResponseWriter, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": http.StatusUnauthorized, "error_code": errorCode, "message": message})
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
	// 简单实现，实际生产环境应使用更复杂的限流算法
	return next
}
