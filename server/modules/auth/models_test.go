package auth

import (
	"testing"
	"time"
)

func TestUserLockState(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	future := now.Add(time.Minute)
	past := now.Add(-time.Minute)

	if !(&User{LockedUntil: &future}).IsLocked(now) {
		t.Fatal("future locked_until should lock the user")
	}
	if (&User{LockedUntil: &past}).IsLocked(now) {
		t.Fatal("past locked_until should not lock the user")
	}
	if (&User{}).IsLocked(now) {
		t.Fatal("nil locked_until should not lock the user")
	}
}

func TestSafeInfoExposesPasswordChangeAndLockState(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	lockedUntil := now.Add(30 * time.Minute)
	user := &User{
		ID: 7,
		Username: "admin",
		Role: RoleAdmin,
		IsActive: true,
		MustChangePassword: true,
		LockedUntil: &lockedUntil,
	}

	info := user.SafeInfo(now)
	if info.ID != 7 || info.Username != "admin" || info.Role != RoleAdmin || !info.IsActive {
		t.Fatalf("unexpected safe user info: %#v", info)
	}
	if !info.NeedsPasswordChange {
		t.Fatal("safe info should expose password-change requirement")
	}
	if !info.Locked {
		t.Fatal("safe info should expose lock state")
	}
}
