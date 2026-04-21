package cdn

import (
	"fmt"
	"strings"
	"time"

	"ALLinSSL/plugins/alicloud/cas"
	aliyuncdn "github.com/alibabacloud-go/cdn-20180510/v6/client"
	aliyunopenapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/tea"
)

func createClient(accessKey, accessSecret string) (*aliyuncdn.Client, error) {
	config := &aliyunopenapi.Config{
		AccessKeyId:     tea.String(accessKey),
		AccessKeySecret: tea.String(accessSecret),
		Endpoint:        tea.String("cdn.aliyuncs.com"),
	}
	client, err := aliyuncdn.NewClient(config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func Deploy(cfg map[string]any) error {
	certPEM, ok := cfg["cert"].(string)
	if !ok || certPEM == "" {
		return fmt.Errorf("证书错误：cert")
	}
	keyPEM, ok := cfg["key"].(string)
	if !ok || keyPEM == "" {
		return fmt.Errorf("证书错误：key")
	}
	accessKey, ok := cfg["access_key_id"].(string)
	if !ok || accessKey == "" {
		return fmt.Errorf("参数错误：access_key_id")
	}
	accessSecret, ok := cfg["access_key_secret"].(string)
	if !ok || accessSecret == "" {
		return fmt.Errorf("参数错误：access_key_secret")
	}
	domain, ok := cfg["domain"].(string)
	if !ok || domain == "" {
		return fmt.Errorf("参数错误：domain")
	}
	client, err := createClient(accessKey, accessSecret)
	if err != nil {
		return err
	}
	casClient, err := cas.CreateClient(accessKey, accessSecret, "cas.aliyuncs.com")
	if err != nil {
		return err
	}
	certId, err := cas.UploadAndGetId(casClient, strings.TrimSpace(certPEM), strings.TrimSpace(keyPEM), fmt.Sprintf("allinssl_%d", time.Now().UnixMilli()))
	if err != nil {
		return err
	}
	deployed := 0
	for _, d := range strings.Split(domain, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		req := &aliyuncdn.SetCdnDomainSSLCertificateRequest{
			DomainName:  tea.String(d),
			SSLProtocol: tea.String("on"),
			CertType:    tea.String("cas"),
			CertId:      certId,
		}
		if _, err = client.SetCdnDomainSSLCertificate(req); err != nil {
			return err
		}
		deployed++
	}
	if deployed == 0 {
		return fmt.Errorf("参数错误：domain")
	}
	return nil
}
