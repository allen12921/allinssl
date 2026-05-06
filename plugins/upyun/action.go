package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

const (
	signinURL      = "https://console.upyun.com/accounts/signin/"
	uploadCertURL  = "https://console.upyun.com/api/https/certificate/"
	listCertURL    = "https://console.upyun.com/api/https/certificate/manager/"
	certListURL    = "https://console.upyun.com/api/https/certificate/list/"
	migrateCertURL = "https://console.upyun.com/api/https/migrate/domain"
)

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type apiResp struct {
	Status  int             `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func newHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}
}

func login(client *http.Client, username, password string) error {
	body, _ := json.Marshal(loginReq{Username: username, Password: password})
	req, err := http.NewRequest("POST", signinURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("创建登录请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("登录请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		var ar apiResp
		_ = json.Unmarshal(respBody, &ar)
		if ar.Message != "" {
			return fmt.Errorf("登录失败 (HTTP %d): %s", resp.StatusCode, ar.Message)
		}
		return fmt.Errorf("登录失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var ar apiResp
	if err := json.Unmarshal(respBody, &ar); err == nil {
		if ar.Status != 0 && ar.Status != 200 {
			return fmt.Errorf("登录失败: %s", ar.Message)
		}
	}
	return nil
}

func uploadCert(client *http.Client, cert, key string) (map[string]interface{}, error) {
	payload := map[string]string{
		"certificate": cert,
		"private_key": key,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", uploadCertURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建上传请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("上传证书请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		result = map[string]interface{}{"raw": string(respBody)}
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		msg := ""
		if ar, ok := result["message"]; ok {
			msg = fmt.Sprintf("%v", ar)
		}
		if msg != "" {
			return result, fmt.Errorf("上传证书失败 (HTTP %d): %s", resp.StatusCode, msg)
		}
		return result, fmt.Errorf("上传证书失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	if statusVal, ok := result["status"]; ok {
		switch s := statusVal.(type) {
		case float64:
			if s != 0 && s != 200 && s != 201 {
				msg, _ := result["message"].(string)
				return result, fmt.Errorf("上传证书失败 (status=%.0f): %s", s, msg)
			}
		}
	}

	return result, nil
}

func extractCertID(uploadResult map[string]interface{}) string {
	if data, ok := uploadResult["data"].(map[string]interface{}); ok {
		if res, ok := data["result"].(map[string]interface{}); ok {
			if id, ok := res["certificate_id"].(string); ok {
				return id
			}
		}
	}
	return ""
}

// getDomainsByCert queries which CDN domains are currently using the given certificate.
// Returns the list of domain names from data.domains[].name.
func getDomainsByCert(client *http.Client, certID string) ([]string, error) {
	req, err := http.NewRequest("GET", listCertURL+"?certificate_id="+certID, nil)
	if err != nil {
		return nil, fmt.Errorf("创建查询域名请求失败: %v", err)
	}
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询域名请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("解析域名响应失败: %v", err)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	domainsRaw, ok := data["domains"].([]interface{})
	if !ok {
		return nil, nil
	}

	var domains []string
	for _, d := range domainsRaw {
		if dm, ok := d.(map[string]interface{}); ok {
			if name, ok := dm["name"].(string); ok && name != "" {
				domains = append(domains, name)
			}
		}
	}
	return domains, nil
}

type certListItem struct {
	ID           string
	CommonName   string
	ValidityEnd  int64 // milliseconds
	ConfigDomain int
}

// listAllCerts returns all certificates in the account by paginating through the list API.
func listAllCerts(client *http.Client) ([]certListItem, error) {
	var all []certListItem
	since := ""
	const pageSize = 100

	for {
		url := fmt.Sprintf("%s?limit=%d", certListURL, pageSize)
		if since != "" {
			url = fmt.Sprintf("%s?since=%s&limit=%d", certListURL, since, pageSize)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("创建证书列表请求失败: %v", err)
		}
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("获取证书列表失败: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("解析证书列表响应失败: %v", err)
		}

		data, _ := parsed["data"].(map[string]interface{})
		result, _ := data["result"].(map[string]interface{})

		pageCount := 0
		for certID, v := range result {
			if certID == "default" {
				continue
			}
			info, ok := v.(map[string]interface{})
			if !ok {
				continue
			}
			validity, ok := info["validity"].(map[string]interface{})
			if !ok {
				continue // skip if expiry metadata is missing
			}
			endMs, ok := validity["end"].(float64)
			if !ok || endMs == 0 {
				continue // skip if expiry cannot be determined
			}
			cd, ok := info["config_domain"].(float64)
			if !ok {
				continue // skip if domain binding count is missing
			}
			cn, _ := info["commonName"].(string)
			all = append(all, certListItem{
				ID:           certID,
				CommonName:   cn,
				ValidityEnd:  int64(endMs),
				ConfigDomain: int(cd),
			})
			pageCount++
		}

		pager, _ := data["pager"].(map[string]interface{})
		nextSince, _ := pager["since"].(float64)
		if pageCount < pageSize || nextSince == 0 {
			break
		}
		since = fmt.Sprintf("%.0f", nextSince)
	}
	return all, nil
}

// deleteExpiredUnbound deletes all expired certs with no configured domains,
// skipping skipID (the cert just uploaded).
func deleteExpiredUnbound(client *http.Client, skipID string) ([]string, error) {
	certs, err := listAllCerts(client)
	if err != nil {
		return nil, err
	}

	nowMs := time.Now().UnixMilli()
	var deleted []string
	for _, c := range certs {
		if c.ID == skipID {
			continue
		}
		if c.ValidityEnd > nowMs || c.ConfigDomain > 0 {
			continue
		}
		if err := deleteCert(client, c.ID); err != nil {
			return deleted, fmt.Errorf("删除证书 %s (%s) 失败: %v", c.ID, c.CommonName, err)
		}
		deleted = append(deleted, fmt.Sprintf("%s (%s)", c.ID, c.CommonName))
	}
	return deleted, nil
}

func deleteCert(client *http.Client, certID string) error {
	req, err := http.NewRequest("DELETE", uploadCertURL+"?certificate_id="+certID, nil)
	if err != nil {
		return fmt.Errorf("创建删除请求失败: %v", err)
	}
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("删除证书请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	_ = json.Unmarshal(respBody, &result)

	if code := apiErrorCode(result); code != "" {
		return fmt.Errorf("删除证书失败 (error_code=%s): %s", code, apiErrorMsg(result))
	}
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("删除证书失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// migrateDomainCert migrates an existing certificate on a domain to the new one.
// Returns (alreadyBound=true, nil) when error_code is "23601" (domain already uses this cert).
func migrateDomainCert(client *http.Client, certID, domain string) (alreadyBound bool, err error) {
	payload := map[string]string{
		"crt_id":      certID,
		"domain_name": domain,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", migrateCertURL, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("创建迁移请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("迁移证书请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	_ = json.Unmarshal(respBody, &result)

	if code := apiErrorCode(result); code != "" {
		if code == "23601" {
			return true, nil // domain already bound to this certificate
		}
		return false, fmt.Errorf("迁移证书失败 (error_code=%s): %s", code, apiErrorMsg(result))
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return false, fmt.Errorf("迁移证书失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	return false, nil
}

func apiErrorCode(result map[string]interface{}) string {
	if data, ok := result["data"].(map[string]interface{}); ok {
		if code, ok := data["error_code"]; ok {
			return fmt.Sprintf("%v", code)
		}
	}
	if code, ok := result["error_code"]; ok {
		return fmt.Sprintf("%v", code)
	}
	return ""
}

func apiErrorMsg(result map[string]interface{}) string {
	if data, ok := result["data"].(map[string]interface{}); ok {
		if msg, ok := data["message"].(string); ok && msg != "" {
			return msg
		}
	}
	if msg, ok := result["message"].(string); ok {
		return msg
	}
	return ""
}

func Upload(cfg map[string]any) (*Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	username, ok := cfg["username"].(string)
	if !ok || username == "" {
		return nil, fmt.Errorf("username is required")
	}
	password, ok := cfg["password"].(string)
	if !ok || password == "" {
		return nil, fmt.Errorf("password is required")
	}
	cert, ok := cfg["cert"].(string)
	if !ok || cert == "" {
		return nil, fmt.Errorf("cert is required")
	}
	key, ok := cfg["key"].(string)
	if !ok || key == "" {
		return nil, fmt.Errorf("key is required")
	}

	client := newHTTPClient()

	if err := login(client, username, password); err != nil {
		return nil, err
	}

	uploadResult, err := uploadCert(client, cert, key)
	if err != nil {
		return nil, err
	}

	certID := extractCertID(uploadResult)
	if certID == "" {
		return nil, fmt.Errorf("上传成功但未获取到证书ID，请检查又拍云响应")
	}

	domains, err := getDomainsByCert(client, certID)
	if err != nil {
		return nil, fmt.Errorf("查询匹配域名失败: %v", err)
	}

	var migrated, alreadyBound []string
	for _, d := range domains {
		bound, err := migrateDomainCert(client, certID, d)
		if err != nil {
			return nil, fmt.Errorf("域名 %s 迁移证书失败: %v", d, err)
		}
		if bound {
			alreadyBound = append(alreadyBound, d)
		} else {
			migrated = append(migrated, d)
		}
	}

	parts := []string{}
	if len(migrated) > 0 {
		parts = append(parts, fmt.Sprintf("已迁移域名: %v", migrated))
	}
	if len(alreadyBound) > 0 {
		parts = append(parts, fmt.Sprintf("已绑定该证书无需迁移: %v", alreadyBound))
	}
	msg := "证书已成功上传到又拍云证书库"
	if len(parts) > 0 {
		msg = strings.Join(parts, "; ")
	}

	result := map[string]interface{}{
		"certificate_id": certID,
		"domains":        migrated,
	}
	if len(alreadyBound) > 0 {
		result["already_bound"] = alreadyBound
	}

	deleted, cleanupErr := deleteExpiredUnbound(client, certID)
	if cleanupErr != nil {
		result["cleanup_warning"] = cleanupErr.Error()
	}
	if len(deleted) > 0 {
		result["deleted_certs"] = deleted
	}

	return &Response{
		Status:  "success",
		Message: msg,
		Result:  result,
	}, nil
}
