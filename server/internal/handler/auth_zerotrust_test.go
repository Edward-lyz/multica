package handler

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestJoinZeroTrustDefaultWorkspace(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}

	ctx := context.Background()
	const slug = "handler-tests-zero-trust-team"
	_, _ = testPool.Exec(ctx, `DELETE FROM workspace WHERE slug = $1`, slug)
	_, _ = testPool.Exec(ctx, `UPDATE "user" SET onboarded_at = NULL WHERE id = $1`, testUserID)
	var workspaceID pgtype.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO workspace (name, slug, issue_prefix)
		VALUES ('Zero Trust Team', $1, 'ZTT')
		RETURNING id
	`, slug).Scan(&workspaceID); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM workspace WHERE slug = $1`, slug)
		_, _ = testPool.Exec(context.Background(), `UPDATE "user" SET onboarded_at = NULL WHERE id = $1`, testUserID)
	})

	previousConfig := testHandler.cfg
	testHandler.cfg.ZeroTrustDefaultWorkspaceSlug = slug
	t.Cleanup(func() { testHandler.cfg = previousConfig })

	user, err := testHandler.Queries.GetUser(ctx, parseUUID(testUserID))
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	joined, err := testHandler.joinZeroTrustDefaultWorkspace(ctx, user)
	if err != nil {
		t.Fatalf("join default workspace: %v", err)
	}
	if !joined.OnboardedAt.Valid {
		t.Fatal("zero-trust user was not marked onboarded")
	}

	// Repeated login must not create another membership.
	if _, err := testHandler.joinZeroTrustDefaultWorkspace(ctx, joined); err != nil {
		t.Fatalf("repeat join: %v", err)
	}
	var count int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM member
		WHERE workspace_id = $1 AND user_id = $2 AND role = 'member'
	`, workspaceID, testUserID).Scan(&count); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if count != 1 {
		t.Fatalf("membership count = %d, want 1", count)
	}
}

func signZeroTrustTestToken(t *testing.T, secret string, claims zeroTrustClaims, method jwt.SigningMethod) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func TestVerifyZeroTrustToken(t *testing.T) {
	now := time.Now()
	claims := zeroTrustClaims{
		Username: "zhangsan",
		Name:     "张三",
		Email:    "zhangsan@baidu.com",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}
	token := signZeroTrustTestToken(t, "domain-secret", claims, jwt.SigningMethodHS256)

	got, err := verifyZeroTrustToken(token, "domain-secret")
	if err != nil {
		t.Fatalf("verify valid token: %v", err)
	}
	if got.Username != claims.Username || got.Email != claims.Email || got.Name != claims.Name {
		t.Fatalf("unexpected claims: %+v", got)
	}
}

func TestVerifyZeroTrustTokenRejectsInvalidIdentity(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		claims zeroTrustClaims
		secret string
	}{
		{
			name: "expired",
			claims: zeroTrustClaims{Username: "zhangsan", RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(now.Add(-2 * time.Minute)), ExpiresAt: jwt.NewNumericDate(now.Add(-time.Minute)),
			}},
			secret: "domain-secret",
		},
		{
			name: "missing username",
			claims: zeroTrustClaims{RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			}},
			secret: "domain-secret",
		},
		{
			name: "missing issued at",
			claims: zeroTrustClaims{Username: "zhangsan", RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			}},
			secret: "domain-secret",
		},
		{
			name: "wrong secret",
			claims: zeroTrustClaims{Username: "zhangsan", RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			}},
			secret: "other-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signZeroTrustTestToken(t, "domain-secret", tt.claims, jwt.SigningMethodHS256)
			if _, err := verifyZeroTrustToken(token, tt.secret); err == nil {
				t.Fatal("expected verification to fail")
			}
		})
	}
}
