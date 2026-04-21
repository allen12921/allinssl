package aliyun

import (
	"ALLinSSL/backend/internal/access"
	aliCas "ALLinSSL/backend/internal/cert/deploy/client/aliyun"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dcdn "github.com/alibabacloud-go/dcdn-20180115/v3/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"strconv"
)

func CreateDcdnClient(accessKey, accessSecret string) (*dcdn.Client, error) {
	config := &openapi.Config{
		AccessKeyId:     tea.String(accessKey),
		AccessKeySecret: tea.String(accessSecret),
		RegionId:        tea.String("cn-hangzhou"),
	}
	return dcdn.NewClient(config)
}

func DeployCertToDcdn(client *dcdn.Client, domain string, certId *int64) error {
	request := &dcdn.SetDcdnDomainSSLCertificateRequest{
		DomainName:  tea.String(domain),
		SSLProtocol: tea.String("on"),
		CertType:    tea.String("cas"),
		CertId:      certId,
	}

	runtime := &util.RuntimeOptions{}

	_, err := client.SetDcdnDomainSSLCertificateWithOptions(request, runtime)
	return err
}

func DeployAliyunDcdn(cfg map[string]any) error {
	cert, ok := cfg["certificate"].(map[string]any)
	if !ok {
		return fmt.Errorf("证书不存在")
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
	//
	providerData, err := access.GetAccess(providerID)
	if err != nil {
		return err
	}
	providerConfigStr, ok := providerData["config"].(string)
	if !ok {
		return fmt.Errorf("api配置错误")
	}
	// 解析 JSON 配置
	var providerConfig map[string]string
	err = json.Unmarshal([]byte(providerConfigStr), &providerConfig)
	if err != nil {
		return err
	}
	client, err := CreateDcdnClient(providerConfig["access_key_id"], providerConfig["access_key_secret"])
	if err != nil {
		return fmt.Errorf("创建 DCDN 客户端失败: %w", err)
	}
	certPEM, ok := cert["cert"].(string)
	if !ok {
		return fmt.Errorf("证书内容不存在或格式错误")
	}
	privkeyPEM, ok := cert["key"].(string)
	if !ok {
		return fmt.Errorf("私钥内容不存在或格式错误")
	}
	domain, ok := cfg["domain"].(string)
	if !ok {
		return fmt.Errorf("域名不存在或格式错误")
	}
	casClient, err := aliCas.ClientAliCas(providerConfig["access_key_id"], providerConfig["access_key_secret"])
	if err != nil {
		return fmt.Errorf("创建 CAS 客户端失败: %w", err)
	}
	certId, err := casClient.UploadCert(fmt.Sprintf("allinssl_%d", time.Now().UnixMilli()), certPEM, privkeyPEM)
	if err != nil {
		return fmt.Errorf("上传证书到 CAS 失败: %w", err)
	}

	deployed := 0
	for _, d := range strings.Split(domain, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if err = DeployCertToDcdn(client, d, certId); err != nil {
			return fmt.Errorf("部署证书到 DCDN 失败: %w", err)
		}
		deployed++
	}
	if deployed == 0 {
		return fmt.Errorf("域名不存在或格式错误")
	}
	return nil
}
