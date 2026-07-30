package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Handler API处理器
type Handler struct {
	authService  *Service
	userStore    *PostgresStore
	sessionStore *SessionStore
	db           *pgxpool.Pool
}

// NewHandler 创建处理器
func NewHandler(authService *Service, userStore *PostgresStore, sessionStore *SessionStore, db *pgxpool.Pool) *Handler {
	return &Handler{
		authService:  authService,
		userStore:    userStore,
		sessionStore: sessionStore,
		db:           db,
	}
}

// Response 标准响应
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Success 返回成功响应
func (h *Handler) Success(w http.ResponseWriter, status int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Code:    0,
		Message: message,
		Data:    data,
	})
}

// Error 返回错误响应
func (h *Handler) Error(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Code:    status,
		Message: message,
	})
}

func validatePasswordPolicy(password string) string {
	if len([]rune(password)) < 8 {
		return "new password must be at least 8 characters"
	}
	return ""
}

// Register 处理注册请求
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 参数验证
	if len(req.Username) < 3 || len(req.Username) > 50 {
		h.Error(w, http.StatusBadRequest, "username must be 3-50 characters")
		return
	}
	if message := validatePasswordPolicy(req.Password); message != "" {
		h.Error(w, http.StatusBadRequest, message)
		return
	}

	role, err := NormalizeRegistrationRole(req.Role)
	if err != nil {
		h.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	// 哈希密码
	hash, err := h.authService.HashPassword(req.Password)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// 创建用户
	user := &User{
		Username:     req.Username,
		PasswordHash: hash,
		Role:         role,
		IsActive:     true,
	}

	if err := h.userStore.CreateUser(r.Context(), user); err != nil {
		if err == ErrUserExists {
			h.Error(w, http.StatusConflict, "username already exists")
			return
		}
		h.Error(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	h.Success(w, http.StatusCreated, "user created", map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
	})
}

// Login 处理登录请求
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	log.Printf("[Auth] Login attempt: username=%s", req.Username)

	// 获取用户
	user, err := h.userStore.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		log.Printf("[Auth] GetUserByUsername error: %v", err)
		if err == ErrUserNotFound {
			h.Error(w, http.StatusUnauthorized, "invalid username or password")
			return
		}
		h.Error(w, http.StatusInternalServerError, "login failed")
		return
	}

	log.Printf("[Auth] User found: id=%d, username=%s", user.ID, user.Username)

	// 检查用户是否激活
	if !user.IsActive {
		h.Error(w, http.StatusForbidden, "account is disabled")
		return
	}
	if user.IsLocked(time.Now()) {
		h.Error(w, http.StatusLocked, ErrAccountLocked.Message)
		return
	}

	// 验证密码
	if !h.authService.VerifyPassword(req.Password, user.PasswordHash) {
		if err := h.userStore.RecordFailedLogin(r.Context(), user.ID, 10, 30*time.Minute); err != nil {
			log.Printf("[Auth] RecordFailedLogin error: %v", err)
		}
		h.Error(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	// 生成Token
	token, expiresAt, err := h.authService.GenerateToken(user.ID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// 保存会话
	if err := h.sessionStore.CreateSession(r.Context(), token, user.ID, expiresAt); err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	// 更新最后登录时间
	h.userStore.UpdateLastLogin(r.Context(), user.ID)
	h.userStore.ResetLoginFailures(r.Context(), user.ID)

	h.Success(w, http.StatusOK, "login success", LoginResponse{
		Token:               token,
		ExpiresAt:           expiresAt,
		NeedsPasswordChange: user.MustChangePassword,
		User:                user.SafeInfo(time.Now()),
	})
}

// Logout 处理登出请求
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// 从Context获取Token
	token := GetTokenFromContext(r.Context())
	if token != "" {
		h.sessionStore.DeleteSession(r.Context(), token)
	}

	h.Success(w, http.StatusOK, "logout success", nil)
}

// Profile 处理获取个人资料请求
func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID := GetUserIDFromContext(r.Context())
	if userID == 0 {
		h.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.userStore.GetUserByID(r.Context(), userID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	h.Success(w, http.StatusOK, "success", ProfileResponse{
		ID:                  user.ID,
		Username:            user.Username,
		Role:                user.Role,
		IsActive:            user.IsActive,
		NeedsPasswordChange: user.MustChangePassword,
		LastLoginAt:         user.LastLoginAt,
		CreatedAt:           user.CreatedAt,
	})
}

// ChangePassword 处理修改密码请求
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID := GetUserIDFromContext(r.Context())
	if userID == 0 {
		h.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if message := validatePasswordPolicy(req.NewPassword); message != "" {
		h.Error(w, http.StatusBadRequest, message)
		return
	}

	user, err := h.userStore.GetUserByID(r.Context(), userID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	// 验证旧密码
	if !h.authService.VerifyPassword(req.OldPassword, user.PasswordHash) {
		h.Error(w, http.StatusUnauthorized, "incorrect old password")
		return
	}

	// 更新密码
	hash, err := h.authService.HashPassword(req.NewPassword)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	if err := h.userStore.MarkPasswordChanged(r.Context(), userID, hash); err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	// 删除所有会话
	h.sessionStore.DeleteUserSessions(r.Context(), userID)

	h.Success(w, http.StatusOK, "password changed", nil)
}

// ListUsers 处理列出用户请求(仅管理员)
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	rows, err := h.db.Query(r.Context(),
		"SELECT id, username, role, is_active, must_change_password, last_login_at, created_at FROM users ORDER BY id LIMIT $1 OFFSET $2",
		limit, offset)
	if err != nil {
		log.Printf("[ListUsers] query error: %v", err)
		h.Error(w, http.StatusInternalServerError, "failed to query users")
		return
	}
	defer rows.Close()

	users := []map[string]interface{}{}
	count := 0
	for rows.Next() {
		count++
		var id int64
		var username string
		var role string
		var isActive bool
		var mustChangePassword bool
		var lastLogin *time.Time
		var createdAt time.Time

		if err := rows.Scan(&id, &username, &role, &isActive, &mustChangePassword, &lastLogin, &createdAt); err != nil {
			continue
		}
		user := map[string]interface{}{
			"id":                   id,
			"username":             username,
			"role":                 role,
			"is_active":            isActive,
			"must_change_password": mustChangePassword,
			"created_at":           createdAt,
		}
		if lastLogin != nil {
			user["last_login_at"] = *lastLogin
		}
		users = append(users, user)
	}

	h.Success(w, http.StatusOK, "success", users)
}

// DeleteUser 删除用户
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID := GetUserIDFromContext(r.Context())
	if userID == 0 {
		h.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := r.URL.Path
	var targetID int64
	if _, err := fmt.Sscanf(path, "/api/v1/auth/users/%d", &targetID); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid user id")
		return
	}

	if targetID == userID {
		h.Error(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}

	result, err := h.db.Exec(r.Context(), "DELETE FROM users WHERE id = $1", targetID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to delete user")
		return
	}

	if result.RowsAffected() == 0 {
		h.Error(w, http.StatusNotFound, "user not found")
		return
	}

	h.sessionStore.DeleteUserSessions(r.Context(), targetID)
	h.Success(w, http.StatusOK, "user deleted", nil)
}

// UpdateUser 更新用户
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		h.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID := GetUserIDFromContext(r.Context())
	if userID == 0 {
		h.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := r.URL.Path
	var targetID int64
	if _, err := fmt.Sscanf(path, "/api/v1/auth/users/%d", &targetID); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req struct {
		Role     string `json:"role"`
		IsActive *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Role != "" && !ValidateRole(req.Role) {
		h.Error(w, http.StatusBadRequest, "invalid role")
		return
	}

	if req.IsActive != nil && targetID == userID && !*req.IsActive {
		h.Error(w, http.StatusBadRequest, "cannot disable yourself")
		return
	}

	if req.Role != "" {
		_, err := h.db.Exec(r.Context(), "UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2", req.Role, targetID)
		if err != nil {
			h.Error(w, http.StatusInternalServerError, "failed to update user")
			return
		}
	}

	if req.IsActive != nil {
		_, err := h.db.Exec(r.Context(), "UPDATE users SET is_active = $1, updated_at = NOW() WHERE id = $2", *req.IsActive, targetID)
		if err != nil {
			h.Error(w, http.StatusInternalServerError, "failed to update user")
			return
		}
	}

	h.Success(w, http.StatusOK, "user updated", nil)
}

// ChangeUserPassword 管理员修改用户密码
func (h *Handler) ChangeUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		h.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID := GetUserIDFromContext(r.Context())
	if userID == 0 {
		h.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		UserID      int64  `json:"user_id"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == 0 {
		h.Error(w, http.StatusBadRequest, "user_id is required")
		return
	}

	if message := validatePasswordPolicy(req.NewPassword); message != "" {
		h.Error(w, http.StatusBadRequest, message)
		return
	}

	hash, err := h.authService.HashPassword(req.NewPassword)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	_, err = h.db.Exec(r.Context(), "UPDATE users SET password_hash = $1, must_change_password = true, updated_at = NOW() WHERE id = $2", hash, req.UserID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	h.sessionStore.DeleteUserSessions(r.Context(), req.UserID)
	h.Success(w, http.StatusOK, "password changed", nil)
}
