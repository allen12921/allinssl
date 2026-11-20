package aliyun

import (
	"ALLinSSL/backend/internal/access"
	"ALLinSSL/backend/public"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"
)

// 函数计算 3.0 自定义域名的证书只能以 PEM 形式写在 certConfig 里（不能引用证书服务里的证书），
// 所以续签后要调用 UpdateCustomDomain 把新证书写进去。
//
// UpdateCustomDomain 会保留请求里省略的字段：阿里云官方 Terraform provider（fcv3 custom_domain）
// 更新时也只发送变化的字段。所以这里只发送 certConfig，不做读改写，避免覆盖并发修改的路由、TLS 等配置。
// 更新前后仍会对比这些配置，出现变化就报错，防止接口行为变化后悄悄改掉配置。
//
// 接口直接用 darabonba-openapi 的通用调用（项目已有依赖），按原始 JSON 读取结果。

const fcAPIVersion = "2023-03-30"

// fcCheckedKeys 是自定义域名里除 certConfig 以外的可写配置，更新后必须保持不变。
var fcCheckedKeys = []string{"authConfig", "corsConfig", "protocol", "routeConfig", "tlsConfig", "wafConfig"}

// fcSpecialEndpoints 是不符合 fcv3.<region>.aliyuncs.com 规则的地域接入点
// （来自 api.aliyun.com 上 FC 2023-03-30 的接入点元数据）。
var fcSpecialEndpoints = map[string]string{
	"me-central-1":          "me-central-1.fc.aliyuncs.com",
	"cn-shanghai-finance-1": "cn-shanghai-finance-1.fc.aliyuncs.com",
	"cn-heyuan-acdr-1":      "cn-heyuan-acdr-1.fc.aliyuncs.com",
	"cn-hangzhou-finance":   "cn-hangzhou-finance.fc.aliyuncs.com",
}

var fcRegionPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

func fcEndpoint(region string) (string, error) {
	if !fcRegionPattern.MatchString(region) {
		return "", fmt.Errorf("区域格式错误: %q（示例：cn-beijing）", region)
	}
	if ep, ok := fcSpecialEndpoints[region]; ok {
		return ep, nil
	}
	return "fcv3." + region + ".aliyuncs.com", nil
}

func CreateFCClient(accessKey, accessSecret, region string) (*openapi.Client, error) {
	endpoint, err := fcEndpoint(region)
	if err != nil {
		return nil, err
	}
	return openapi.NewClient(&openapi.Config{
		AccessKeyId:     tea.String(accessKey),
		AccessKeySecret: tea.String(accessSecret),
		RegionId:        tea.String(region),
		Endpoint:        tea.String(endpoint),
	})
}

func callFCCustomDomain(client *openapi.Client, action, method, domain string, body []byte) (map[string]any, error) {
	params := &openapi.Params{
		Action:      tea.String(action),
		Version:     tea.String(fcAPIVersion),
		Protocol:    tea.String("HTTPS"),
		Pathname:    tea.String("/" + fcAPIVersion + "/custom-domains/" + url.PathEscape(domain)),
		Method:      tea.String(method),
		AuthType:    tea.String("AK"),
		Style:       tea.String("ROA"),
		ReqBodyType: tea.String("json"),
		BodyType:    tea.String("string"),
	}
	req := &openapi.OpenApiRequest{}
	if body != nil {
		// Stringify 对字符串原样透传，请求体由这里自己序列化。
		req.Body = string(body)
	}
	resp, err := client.CallApi(params, req, &dara.RuntimeOptions{})
	if err != nil {
		return nil, err
	}
	raw, ok := resp["body"].(string)
	if !ok {
		return nil, fmt.Errorf("%s 返回内容格式错误", action)
	}
	return decodeJSONObject(raw)
}

func decodeJSONObject(raw string) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("解析返回内容失败: %w", err)
	}
	if out == nil {
		return nil, fmt.Errorf("返回内容为空")
	}
	return out, nil
}

// normalizeForCompare 去掉 null、空数组、空对象，只用于更新前后的对比，
// 避免接口把未设置的字段在 null 和空值之间来回表示造成误报。
func normalizeForCompare(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			n := normalizeForCompare(val)
			if n == nil {
				continue
			}
			out[k] = n
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []any:
		if len(t) == 0 {
			return nil
		}
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalizeForCompare(val)
		}
		return out
	default:
		return v
	}
}

func fcProtocolHasHTTPS(current map[string]any) bool {
	protocol, _ := current["protocol"].(string)
	for _, p := range strings.Split(protocol, ",") {
		if strings.EqualFold(strings.TrimSpace(p), "HTTPS") {
			return true
		}
	}
	return false
}

// buildFCUpdateBody 构造 UpdateCustomDomain 的请求体，只包含 certConfig。
func buildFCUpdateBody(certName, certPEM, keyPEM string) map[string]any {
	return map[string]any{
		"certConfig": map[string]any{
			"certName":    certName,
			"certificate": certPEM,
			"privateKey":  keyPEM,
		},
	}
}

// changedFCKeys 返回更新前后发生变化的配置项名称。
func changedFCKeys(before, after map[string]any) []string {
	var changed []string
	for _, k := range fcCheckedKeys {
		if !reflect.DeepEqual(normalizeForCompare(before[k]), normalizeForCompare(after[k])) {
			changed = append(changed, k)
		}
	}
	return changed
}

// fcDomainHasLeaf 判断自定义域名信息里的证书是否就是 leaf；返回内容里没有证书时 ok=false。
func fcDomainHasLeaf(domainInfo map[string]any, leaf *x509.Certificate) (match, ok bool) {
	certCfg, _ := domainInfo["certConfig"].(map[string]any)
	got, _ := certCfg["certificate"].(string)
	if strings.TrimSpace(got) == "" {
		return false, false
	}
	gotLeaf, err := parseLeafCert(got)
	if err != nil {
		return false, true
	}
	return bytes.Equal(gotLeaf.Raw, leaf.Raw), true
}

func parseLeafCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("无法解析证书 PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// fcCertName 生成证书名：allinssl-<到期日>-<叶子证书 sha256 前 8 位>，便于在控制台辨认。
func fcCertName(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.Raw)
	return fmt.Sprintf("allinssl-%s-%s", leaf.NotAfter.UTC().Format("20060102"), hex.EncodeToString(sum[:])[:8])
}

// DeployCertToFCDomain 把证书写到一个函数计算 3.0 自定义域名上，其余配置保持不变。
func DeployCertToFCDomain(client *openapi.Client, domain, certPEM, keyPEM string, logger *public.Logger) error {
	leaf, err := parseLeafCert(certPEM)
	if err != nil {
		return err
	}
	before, err := callFCCustomDomain(client, "GetCustomDomain", "GET", domain, nil)
	if err != nil {
		return fmt.Errorf("获取自定义域名 %s 失败: %w", domain, err)
	}
	if !fcProtocolHasHTTPS(before) {
		return fmt.Errorf("自定义域名 %s 未开启 HTTPS（protocol=%v），请先在函数计算控制台开启", domain, before["protocol"])
	}

	body, err := json.Marshal(buildFCUpdateBody(fcCertName(leaf), certPEM, keyPEM))
	if err != nil {
		return fmt.Errorf("构造请求失败: %w", err)
	}
	after, err := callFCCustomDomain(client, "UpdateCustomDomain", "PUT", domain, body)
	if err != nil {
		return fmt.Errorf("更新自定义域名 %s 的证书失败: %w", domain, err)
	}

	match, ok := fcDomainHasLeaf(after, leaf)
	if !ok {
		// 更新结果里没有证书内容时，重新读取一次再确认。
		if after, err = callFCCustomDomain(client, "GetCustomDomain", "GET", domain, nil); err != nil {
			return fmt.Errorf("自定义域名 %s 已提交更新，但读取结果失败，无法确认证书: %w", domain, err)
		}
		match, ok = fcDomainHasLeaf(after, leaf)
	}
	if !ok || !match {
		return fmt.Errorf("自定义域名 %s 更新后的证书与要部署的证书不一致", domain)
	}
	// 只报告变化的配置项名称，不输出配置内容（authConfig 等可能含认证信息）。
	if changed := changedFCKeys(before, after); len(changed) > 0 {
		return fmt.Errorf("自定义域名 %s 的证书已更新，但这些配置与更新前不一致，请到函数计算控制台核对: %s", domain, strings.Join(changed, ", "))
	}
	logger.Info(fmt.Sprintf("自定义域名 %s 证书已更新：%s，到期 %s", domain, fcCertName(leaf), leaf.NotAfter.UTC().Format("2006-01-02")))
	return nil
}

// DeployAliyunFC 部署到阿里云函数计算 3.0 自定义域名。参数：region（如 cn-beijing）、domain（多个用逗号分隔）。
func DeployAliyunFC(cfg map[string]any, logger *public.Logger) error {
	cert, ok := cfg["certificate"].(map[string]any)
	if !ok {
		return fmt.Errorf("证书不存在")
	}
	certPEM, ok := cert["cert"].(string)
	if !ok || strings.TrimSpace(certPEM) == "" {
		return fmt.Errorf("证书内容不存在或格式错误")
	}
	keyPEM, ok := cert["key"].(string)
	if !ok || strings.TrimSpace(keyPEM) == "" {
		return fmt.Errorf("私钥内容不存在或格式错误")
	}
	var providerID string
	switch v := cfg["provider_id"].(type) {
	case float64:
		providerID = strconv.Itoa(int(v))
	case string:
		providerID = v
	default:
		return fmt.Errorf("参数错误：provider_id")
	}
	region, _ := cfg["region"].(string)
	region = strings.TrimSpace(region)
	if region == "" {
		return fmt.Errorf("区域不能为空")
	}
	domainStr, _ := cfg["domain"].(string)
	var domains []string
	for _, d := range strings.Split(domainStr, ",") {
		if d = strings.TrimSpace(d); d != "" {
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		return fmt.Errorf("域名不存在或格式错误")
	}

	providerData, err := access.GetAccess(providerID)
	if err != nil {
		return err
	}
	providerConfigStr, ok := providerData["config"].(string)
	if !ok {
		return fmt.Errorf("api配置错误")
	}
	var providerConfig map[string]string
	if err = json.Unmarshal([]byte(providerConfigStr), &providerConfig); err != nil {
		return err
	}
	client, err := CreateFCClient(providerConfig["access_key_id"], providerConfig["access_key_secret"], region)
	if err != nil {
		return fmt.Errorf("创建函数计算客户端失败: %w", err)
	}
	for _, d := range domains {
		logger.Info("正在部署函数计算自定义域名: " + d)
		if err = DeployCertToFCDomain(client, d, certPEM, keyPEM, logger); err != nil {
			return err
		}
	}
	return nil
}
