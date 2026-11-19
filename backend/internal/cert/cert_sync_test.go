package cert

import (
	"encoding/json"
	"strings"
	"testing"
)

const newSha = "newsha256"

// 工作流：start -> upload(sha 引用) -> branch[ upload(数字 id 引用), upload(其他证书) ]
const syncWorkflow = `{"id":"start","type":"start","name":"开始","config":{"exec_type":"auto","big":12345678901234567890},"childNode":{"id":"u1","type":"upload","name":"上传","config":{"cert_id":"newsha256","domains":"a.com","use_local_cert":true,"end_day":30},"childNode":{"id":"b","type":"branch","conditionNodes":[{"id":"c1","type":"condition","childNode":{"id":"u2","type":"upload","config":{"cert_id":7,"domains":"a.com","use_local_cert":true,"end_day":30}}},{"id":"c2","type":"condition","childNode":{"id":"u3","type":"upload","config":{"cert_id":"othersha","domains":"x.com"}}}]}}}`

func findNode(t *testing.T, content, id string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(content))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	var found map[string]any
	var walk func(v any)
	walk = func(v any) {
		switch val := v.(type) {
		case map[string]any:
			if val["id"] == id {
				found = val
			}
			for _, c := range val {
				walk(c)
			}
		case []any:
			for _, c := range val {
				walk(c)
			}
		}
	}
	walk(root)
	if found == nil {
		t.Fatalf("node %s not found", id)
	}
	return found
}

func TestSyncUploadNodeDomains(t *testing.T) {
	out, changed, err := syncUploadNodeDomains(syncWorkflow, []string{newSha, "7"}, "a.com,b.com")
	if err != nil || !changed {
		t.Fatalf("expected change, got changed=%v err=%v", changed, err)
	}
	for _, id := range []string{"u1", "u2"} {
		cfg := findNode(t, out, id)["config"].(map[string]any)
		if cfg["domains"] != "a.com,b.com" {
			t.Errorf("%s domains = %v, want a.com,b.com", id, cfg["domains"])
		}
	}
	if cfg := findNode(t, out, "u3")["config"].(map[string]any); cfg["domains"] != "x.com" {
		t.Errorf("unrelated upload node changed: %v", cfg["domains"])
	}
	// 大整数保持原样
	if !strings.Contains(out, "12345678901234567890") {
		t.Errorf("number not preserved: %s", out)
	}
}

func TestSyncUploadNodeDomainsNoChange(t *testing.T) {
	out, changed, err := syncUploadNodeDomains(syncWorkflow, []string{newSha, "7"}, "a.com")
	if err != nil || changed || out != syncWorkflow {
		t.Fatalf("expected untouched content, changed=%v err=%v", changed, err)
	}
	out, changed, err = syncUploadNodeDomains(syncWorkflow, []string{"nomatch"}, "z.com")
	if err != nil || changed || out != syncWorkflow {
		t.Fatalf("expected untouched content for unrelated cert, changed=%v err=%v", changed, err)
	}
	if _, changed, err = syncUploadNodeDomains("not json", []string{newSha}, "a.com"); err == nil || changed {
		t.Fatalf("expected error for invalid json")
	}
	// 合法对象后还有多余内容：视为不合法，原样返回
	trailing := syncWorkflow + ` {"x":1}`
	if out, changed, err = syncUploadNodeDomains(trailing, []string{newSha, "7"}, "a.com,b.com"); err == nil || changed || out != trailing {
		t.Fatalf("trailing data must be treated as invalid, changed=%v err=%v", changed, err)
	}
	// 新证书没有任何域名时保留原 domains
	out, changed, err = syncUploadNodeDomains(syncWorkflow, []string{newSha, "7"}, "")
	if err != nil || changed || out != syncWorkflow {
		t.Fatalf("empty new domains must not clear node domains, changed=%v err=%v", changed, err)
	}
}

func TestSyncUploadNodeDomainsOrderOnly(t *testing.T) {
	wf := `{"id":"u","type":"upload","config":{"cert_id":"newsha256","domains":"b.com,a.com"}}`
	out, changed, err := syncUploadNodeDomains(wf, []string{newSha}, "a.com,b.com")
	if err != nil || changed || out != wf {
		t.Fatalf("same domain set in different order should not rewrite, changed=%v err=%v", changed, err)
	}
}

func TestSyncUploadNodeDomainsCaseChange(t *testing.T) {
	// 运行时按原字符串精确匹配，只改大小写也必须同步。
	wf := `{"id":"u","type":"upload","config":{"cert_id":"newsha256","domains":"A.com"}}`
	out, changed, err := syncUploadNodeDomains(wf, []string{newSha}, "a.com")
	if err != nil || !changed {
		t.Fatalf("case change should rewrite, changed=%v err=%v", changed, err)
	}
	if cfg := findNode(t, out, "u")["config"].(map[string]any); cfg["domains"] != "a.com" {
		t.Errorf("domains = %v", cfg["domains"])
	}
}

func TestSyncUploadNodeDomainsFloatID(t *testing.T) {
	wf := `{"id":"u","type":"upload","config":{"cert_id":7.0,"domains":"a.com"}}`
	out, changed, err := syncUploadNodeDomains(wf, []string{newSha, "7"}, "a.com,b.com")
	if err != nil || !changed {
		t.Fatalf("integral float id should match, changed=%v err=%v", changed, err)
	}
	if cfg := findNode(t, out, "u")["config"].(map[string]any); cfg["domains"] != "a.com,b.com" {
		t.Errorf("domains = %v", cfg["domains"])
	}
}

func TestSyncUploadNodeDomainsSkipsPluginConfig(t *testing.T) {
	// 插件节点 config 里恰好有形似上传节点的数据，不是可执行节点，不能改。
	wf := `{"id":"p","type":"plugin.demo","config":{"payload":{"id":"fake","type":"upload","config":{"cert_id":"newsha256","domains":"a.com"}}}}`
	out, changed, err := syncUploadNodeDomains(wf, []string{newSha}, "a.com,b.com")
	if err != nil || changed || out != wf {
		t.Fatalf("plugin config must not be rewritten, changed=%v err=%v out=%s", changed, err, out)
	}
}
