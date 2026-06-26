package apply

import (
	"ALLinSSL/backend/public"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

// generateTestPEMKey 生成一个临时的 EC 私钥 PEM（仅用于测试）
func generateTestPEMKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("生成测试密钥失败:", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("序列化测试密钥失败:", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// TestV4RegistrationCompat 验证 v4 格式账号（{"body":{...},"uri":"..."}）
// 能被兼容层正确解析为 v5 的 acme.ExtendedAccount。
// 使用合成数据，不包含任何真实账号凭据。
func TestV4RegistrationCompat(t *testing.T) {
	logFile, _ := os.CreateTemp("", "compat_test_*.log")
	defer os.Remove(logFile.Name())
	logger, _ := public.NewLogger(logFile.Name())
	defer logger.Close()

	testKey := generateTestPEMKey(t)

	cases := []struct {
		email       string
		ca          string
		reg         string
		expectURI   string
		expectValid bool
	}{
		{
			// 标准 v4 格式：body + uri 两个字段
			email: "test@example.com",
			ca:    "Let's Encrypt",
			reg:   `{"body":{"status":"valid","contact":["mailto:test@example.com"]},"uri":"https://acme-v02.api.letsencrypt.org/acme/acct/123456"}`,
			expectURI:   "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
			expectValid: true,
		},
		{
			// v4 格式：body 字段 status 为 valid，uri 指向其他 CA
			email: "test@example.com",
			ca:    "litessl",
			reg:   `{"body":{"status":"valid","contact":["mailto:test@example.com"]},"uri":"https://acme.litessl.com/acme/v2/acct/testacct"}`,
			expectURI:   "https://acme.litessl.com/acme/v2/acct/testacct",
			expectValid: true,
		},
		{
			// v5 格式（直接 ExtendedAccount JSON）：确保新格式也能正常解析
			email: "test@example.com",
			ca:    "zerossl",
			reg:   `{"status":"valid","contact":["mailto:test@example.com"],"accountURL":"https://acme.zerossl.com/v2/DV90/account/testacct"}`,
			expectURI:   "https://acme.zerossl.com/v2/DV90/account/testacct",
			expectValid: true,
		},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s", tc.ca, tc.email), func(t *testing.T) {
			row := map[string]any{
				"email":       tc.email,
				"type":        tc.ca,
				"reg":         tc.reg,
				"private_key": testKey,
			}

			user := GetAcmeUser(tc.email, logger, row)

			if !tc.expectValid {
				if user.Registration != nil {
					t.Errorf("期望 Registration 为 nil，但得到 %v", user.Registration.Location)
				}
				return
			}

			if user.Registration == nil {
				t.Fatalf("Registration 为 nil：兼容层未能解析 reg 字段")
			}
			if user.Registration.Location != tc.expectURI {
				t.Errorf("Location 不匹配\n  期望: %s\n  实际: %s", tc.expectURI, user.Registration.Location)
			}
			if user.GetPrivateKey() == nil {
				t.Fatalf("PrivateKey 为 nil：私钥解析失败")
			}

			t.Logf("✓ Location  = %s", user.Registration.Location)
			t.Logf("✓ Status    = %s", user.Registration.Status)
			t.Logf("✓ PrivateKey 类型 = %T", user.GetPrivateKey())
		})
	}
}
