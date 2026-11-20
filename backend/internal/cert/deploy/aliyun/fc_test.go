package aliyun

import (
	"ALLinSSL/backend/public"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"testing"
	"time"
)

func TestFCEndpoint(t *testing.T) {
	cases := map[string]string{
		"cn-beijing":   "fcv3.cn-beijing.aliyuncs.com",
		"cn-shanghai":  "fcv3.cn-shanghai.aliyuncs.com",
		"me-central-1": "me-central-1.fc.aliyuncs.com",
	}
	for region, want := range cases {
		got, err := fcEndpoint(region)
		if err != nil || got != want {
			t.Errorf("fcEndpoint(%q) = %q, %v; want %q", region, got, err, want)
		}
	}
	for _, bad := range []string{"", "cn-beijing.evil.com", "CN-BEIJING", "cn beijing", "a/b"} {
		if _, err := fcEndpoint(bad); err == nil {
			t.Errorf("fcEndpoint(%q) should fail", bad)
		}
	}
}

// GetCustomDomain 返回结构的示例（数据为虚构）。
const sampleCustomDomain = `{
  "domainName": "fc.example.com",
  "accountId": "1234567890",
  "protocol": "HTTPS",
  "certConfig": {"certName": "old", "privateKey": null, "certificate": "OLD"},
  "tlsConfig": {"minVersion": "TLSv1.2", "maxVersion": "TLSv1.3", "cipherSuites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]},
  "apiVersion": "2023-03-30",
  "routeConfig": {"routes": [{"path": "/v1/*", "accountId": null, "functionName": "demo-func", "qualifier": "LATEST", "methods": null, "rewriteConfig": null}]},
  "createdTime": "2026-01-01T00:00:00Z",
  "lastModifiedTime": "2026-01-01T00:00:00Z",
  "subdomainCount": null,
  "wafConfig": {"enableWAF": false},
  "authConfig": {"authType": "anonymous", "authInfo": null},
  "corsConfig": {"maxAge": 600}
}`

func TestBuildFCUpdateBody(t *testing.T) {
	raw, err := json.Marshal(buildFCUpdateBody("new-name", "CERT", "KEY"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"certConfig":{"certName":"new-name","certificate":"CERT","privateKey":"KEY"}}`
	if string(raw) != want {
		t.Errorf("body mismatch\n got: %s\nwant: %s", raw, want)
	}
}

func TestChangedFCKeys(t *testing.T) {
	before, err := decodeJSONObject(sampleCustomDomain)
	if err != nil {
		t.Fatal(err)
	}
	// 更新后：证书和时间变了，未设置的字段从 null 变成空数组/缺省，都不算变化。
	after, err := decodeJSONObject(`{
  "protocol": "HTTPS",
  "certConfig": {"certName": "new", "certificate": "NEW"},
  "tlsConfig": {"minVersion": "TLSv1.2", "maxVersion": "TLSv1.3", "cipherSuites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]},
  "routeConfig": {"routes": [{"path": "/v1/*", "functionName": "demo-func", "qualifier": "LATEST", "methods": []}]},
  "lastModifiedTime": "2026-01-02T00:00:00Z",
  "wafConfig": {"enableWAF": false},
  "authConfig": {"authType": "anonymous"},
  "corsConfig": {"maxAge": 600}
}`)
	if err != nil {
		t.Fatal(err)
	}
	if changed := changedFCKeys(before, after); len(changed) != 0 {
		t.Errorf("unexpected changes: %v", changed)
	}
	after["routeConfig"] = map[string]any{"routes": []any{}}
	after["tlsConfig"] = nil
	if changed := changedFCKeys(before, after); !reflect.DeepEqual(changed, []string{"routeConfig", "tlsConfig"}) {
		t.Errorf("changes = %v, want [routeConfig tlsConfig]", changed)
	}
}

func TestFCProtocolHasHTTPS(t *testing.T) {
	for protocol, want := range map[string]bool{"HTTPS": true, "HTTP,HTTPS": true, "HTTP": false, "": false} {
		if got := fcProtocolHasHTTPS(map[string]any{"protocol": protocol}); got != want {
			t.Errorf("protocol %q: got %v want %v", protocol, got, want)
		}
	}
}

func newTestCertPEM(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "fc.example.com"},
		NotBefore:    notAfter.AddDate(0, -3, 0),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestFCCertNameAndLeafMatch(t *testing.T) {
	certPEM := newTestCertPEM(t, time.Date(2027, 2, 16, 23, 59, 59, 0, time.UTC))
	leaf, err := parseLeafCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if name := fcCertName(leaf); !regexp.MustCompile(`^allinssl-20270216-[0-9a-f]{8}$`).MatchString(name) {
		t.Errorf("unexpected cert name %q", name)
	}
	if _, err := parseLeafCert("not a pem"); err == nil {
		t.Error("parseLeafCert should fail on garbage")
	}

	other := newTestCertPEM(t, time.Date(2027, 2, 16, 23, 59, 59, 0, time.UTC))
	for name, tc := range map[string]struct {
		info        map[string]any
		match, isOK bool
	}{
		"same leaf":      {map[string]any{"certConfig": map[string]any{"certificate": certPEM}}, true, true},
		"other leaf":     {map[string]any{"certConfig": map[string]any{"certificate": other}}, false, true},
		"garbage":        {map[string]any{"certConfig": map[string]any{"certificate": "x"}}, false, true},
		"no certificate": {map[string]any{"certConfig": map[string]any{"certName": "n"}}, false, false},
		"null config":    {map[string]any{"certConfig": nil}, false, false},
		"missing config": {map[string]any{}, false, false},
	} {
		match, ok := fcDomainHasLeaf(tc.info, leaf)
		if match != tc.match || ok != tc.isOK {
			t.Errorf("%s: got (%v, %v) want (%v, %v)", name, match, ok, tc.match, tc.isOK)
		}
	}
}

// TestDeployCertToFCDomainLive 真实调用函数计算接口，只在设置了下面的环境变量时运行：
// FC_TEST_AK、FC_TEST_SK、FC_TEST_REGION、FC_TEST_DOMAIN、FC_TEST_CERT_FILE、FC_TEST_KEY_FILE。
func TestDeployCertToFCDomainLive(t *testing.T) {
	env := map[string]string{}
	for _, k := range []string{"FC_TEST_AK", "FC_TEST_SK", "FC_TEST_REGION", "FC_TEST_DOMAIN", "FC_TEST_CERT_FILE", "FC_TEST_KEY_FILE"} {
		env[k] = os.Getenv(k)
		if env[k] == "" {
			t.Skip("FC_TEST_* not set")
		}
	}
	certPEM, err := os.ReadFile(env["FC_TEST_CERT_FILE"])
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(env["FC_TEST_KEY_FILE"])
	if err != nil {
		t.Fatal(err)
	}
	logger, err := public.NewLogger(t.TempDir() + "/test.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	client, err := CreateFCClient(env["FC_TEST_AK"], env["FC_TEST_SK"], env["FC_TEST_REGION"])
	if err != nil {
		t.Fatal(err)
	}
	if err := DeployCertToFCDomain(client, env["FC_TEST_DOMAIN"], string(certPEM), string(keyPEM), logger); err != nil {
		t.Fatal(err)
	}
}
