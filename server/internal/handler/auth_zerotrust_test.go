package handler

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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
