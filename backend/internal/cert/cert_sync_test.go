package cert

import (
	"ALLinSSL/backend/public"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

const newSha = "newsha256"

// refs 模拟 certRefMatcher.match：只认给定的 cert_id 文本
func refs(ids ...string) func(string) bool {
	return func(id string) bool {
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	}
}

// syncDomains 以「只改域名」的证书变更调用 syncUploadNodes
func syncDomains(content string, isRef func(string) bool, domains string) (string, bool, error) {
	return syncUploadNodes(content, certChange{domains: domains, usable: domains != "", isRef: isRef})
}

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

// execDomains 按执行器的解码方式取指定节点的 domains
func execDomains(t *testing.T, content, id string) string {
	t.Helper()
	root, err := decodeExecTree(content)
	if err != nil {
		t.Fatalf("executor cannot decode: %v", err)
	}
	var got string
	var walk func(n *ExecNode)
	walk = func(n *ExecNode) {
		if n == nil {
			return
		}
		if n.Id == id {
			got, _ = n.Config["domains"].(string)
		}
		walk(n.ChildNode)
		for _, c := range n.ConditionNodes {
			walk(c)
		}
	}
	walk(root)
	return got
}

func TestSyncUploadNodeDomains(t *testing.T) {
	out, changed, err := syncDomains(syncWorkflow, refs(newSha, "7"), "a.com,b.com")
	if err != nil || !changed {
		t.Fatalf("expected change, got changed=%v err=%v", changed, err)
	}
	for _, id := range []string{"u1", "u2"} {
		if d := execDomains(t, out, id); d != "a.com,b.com" {
			t.Errorf("%s domains = %v, want a.com,b.com", id, d)
		}
	}
	if d := execDomains(t, out, "u3"); d != "x.com" {
		t.Errorf("unrelated upload node changed: %v", d)
	}
	// 大整数保持原样
	if !strings.Contains(out, "12345678901234567890") {
		t.Errorf("number not preserved: %s", out)
	}
}

func TestSyncUploadNodeDomainsNoChange(t *testing.T) {
	out, changed, err := syncDomains(syncWorkflow, refs(newSha, "7"), "a.com")
	if err != nil || changed || out != syncWorkflow {
		t.Fatalf("expected untouched content, changed=%v err=%v", changed, err)
	}
	out, changed, err = syncDomains(syncWorkflow, refs("nomatch"), "z.com")
	if err != nil || changed || out != syncWorkflow {
		t.Fatalf("expected untouched content for unrelated cert, changed=%v err=%v", changed, err)
	}
	// 执行器无法解码的内容（含末尾多余数据）：不处理节点，rewriteWorkflowContent 退回原来的纯文本替换
	for _, bad := range []string{"not json", syncWorkflow + ` {"x":1}`} {
		if out, changed, err := syncDomains(bad, refs(newSha), "a.com,b.com"); !errors.Is(err, errNotExecutable) || changed || out != bad {
			t.Fatalf("undecodable content must be reported as not executable, changed=%v err=%v", changed, err)
		}
		ch := certChange{oldSha: "oldsha", newSha: newSha, domains: "a.com", usable: true, isRef: refs(newSha)}
		if out, err := rewriteWorkflowContent(bad+" oldsha", ch); err != nil || out != bad+" "+newSha {
			t.Fatalf("undecodable content should fall back to text replacement: %q err=%v", out, err)
		}
	}
	// 新证书没有任何域名：有开启本地匹配的引用节点时拒绝，否则保持不变
	if out, changed, err := syncDomains(syncWorkflow, refs(newSha, "7"), ""); !errors.Is(err, errDomainsUnusableForLocalMatch) || changed || out != syncWorkflow {
		t.Fatalf("domainless cert used by local matching must be rejected, changed=%v err=%v", changed, err)
	}
	// 未开启本地匹配：允许，并清空旧域名，避免以后开启时沿用
	noLocal := `{"id":"u","type":"upload","config":{"cert_id":"newsha256","domains":"a.com","use_local_cert":false}}`
	if out, changed, err := syncDomains(noLocal, refs(newSha), ""); err != nil || !changed || execDomains(t, out, "u") != "" {
		t.Fatalf("domainless cert without local matching should clear stale domains, changed=%v err=%v out=%s", changed, err, out)
	}
}

func TestSyncUploadNodeDomainsOrderOnly(t *testing.T) {
	wf := `{"id":"u","type":"upload","config":{"cert_id":"newsha256","domains":"b.com,a.com"}}`
	out, changed, err := syncDomains(wf, refs(newSha), "a.com,b.com")
	if err != nil || changed || out != wf {
		t.Fatalf("same domain set in different order should not rewrite, changed=%v err=%v", changed, err)
	}
}

func TestSyncUploadNodeDomainsCaseChange(t *testing.T) {
	// 运行时按原字符串精确匹配，只改大小写也必须同步。
	wf := `{"id":"u","type":"upload","config":{"cert_id":"newsha256","domains":"A.com"}}`
	out, changed, err := syncDomains(wf, refs(newSha), "a.com")
	if err != nil || !changed || execDomains(t, out, "u") != "a.com" {
		t.Fatalf("case change should rewrite, changed=%v err=%v out=%s", changed, err, out)
	}
}

func TestSyncUploadNodeDomainsNumericID(t *testing.T) {
	// 执行器把数字 cert_id 转成 strconv.Itoa(int(v))，7.0 也是 "7"
	wf := `{"id":"u","type":"upload","config":{"cert_id":7.0,"domains":"a.com"}}`
	out, changed, err := syncDomains(wf, refs("7"), "a.com,b.com")
	if err != nil || !changed || execDomains(t, out, "u") != "a.com,b.com" {
		t.Fatalf("numeric id should match, changed=%v err=%v", changed, err)
	}
}

func TestSyncUploadNodeDomainsSkipsPluginConfig(t *testing.T) {
	// 插件节点 config 里恰好有形似上传节点的数据，不是可执行节点，不能改。
	wf := `{"id":"p","type":"plugin.demo","config":{"payload":{"id":"fake","type":"upload","config":{"cert_id":"newsha256","domains":"a.com"}}}}`
	out, changed, err := syncDomains(wf, refs(newSha), "a.com,b.com")
	if err != nil || changed || out != wf {
		t.Fatalf("plugin config must not be rewritten, changed=%v err=%v out=%s", changed, err, out)
	}
}

func TestSyncUploadNodeDomainsCaseInsensitiveKeys(t *testing.T) {
	// encoding/json 解码 WorkflowNode 时字段名不区分大小写，执行器会把它当上传节点执行
	wf := `{"id":"s","type":"start","ChildNode":{"Id":"u","Type":"upload","Config":{"cert_id":"007","domains":"a.com"}}}`
	out, changed, err := syncDomains(wf, refs(newSha, "007"), "a.com,b.com")
	if err != nil || !changed || execDomains(t, out, "u") != "a.com,b.com" {
		t.Fatalf("expected change, changed=%v err=%v out=%s", changed, err, out)
	}
}

func TestSyncUploadNodeDomainsRejectsUnsafeRewrites(t *testing.T) {
	for name, wf := range map[string]string{
		// 执行器取最后出现的 Type（upload）；重写后键顺序变化会让它变成 plugin.demo
		"大小写重复的 type": `{"id":"s","type":"start","childNode":{"id":"u","type":"plugin.demo","Type":"upload","config":{"cert_id":"7","domains":"a.com"}}}`,
		// 执行器把两个 childNode 合并成一个上传节点；分开看都不完整，改不到
		"拆开的 childNode": `{"id":"s","type":"start","childNode":{"id":"u","type":"upload"},"ChildNode":{"config":{"cert_id":"7","domains":"a.com"}}}`,
		// 执行器合并两个 config；按 map 重写会丢掉第一个 config 的字段
		"重复的 config": `{"id":"u","type":"upload","config":{"use_local_cert":true,"end_day":30},"config":{"cert_id":"7","domains":"a.com"}}`,
		// 大小写不同的 id：执行器取最后的 live，重写后会变成 old
		"大小写重复的 id": `{"id":"old","Id":"live","type":"upload","config":{"cert_id":"7","domains":"a.com"}}`,
	} {
		out, changed, err := syncDomains(wf, refs("7"), "a.com,b.com")
		if !errors.Is(err, errUnsafeRewrite) || changed || out != wf {
			t.Errorf("%s: expected errUnsafeRewrite, changed=%v err=%v out=%s", name, changed, err, out)
		}
	}
	// 有歧义但与该证书无关、不需要改动时不报错
	wf := `{"id":"s","type":"start","childNode":{"id":"u","type":"plugin.demo","Type":"upload","config":{"cert_id":"7","domains":"a.com"}}}`
	if _, changed, err := syncDomains(wf, refs("other"), "a.com,b.com"); err != nil || changed {
		t.Fatalf("unrelated workflow should be left alone, changed=%v err=%v", changed, err)
	}
}

func TestCertRefMatcherUsesSQLiteSemantics(t *testing.T) {
	t.Chdir(t.TempDir())
	db, err := sql.Open("sqlite", "ref.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE cert (id INTEGER PRIMARY KEY, sha256 TEXT); INSERT INTO cert VALUES (7,'abc'),(8,'abc'),(9007199254740992,'big')`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	m := newCertRefMatcher(ctx, conn, 7, "abc")
	// "abc" 在 id 7、8 两行重复：按 sha256 直接匹配，不依赖 SQLite 返回哪一行
	for _, v := range []string{"7", "007", " 7", "7 ", "+7", "7.0", "7e0", "abc"} {
		if !m.match(v) {
			t.Errorf("%q should match cert 7", v)
		}
	}
	for _, v := range []string{"0x7", "7.5", "\u00a07", "07a", "8", "big", ""} {
		if m.match(v) {
			t.Errorf("%q should not match cert 7", v)
		}
	}
	if m.err != nil {
		t.Fatalf("unexpected error: %v", m.err)
	}
	if !newCertRefMatcher(ctx, conn, 9007199254740992, "big2").match("9007199254740992.0") {
		t.Error("decimal text of a large id should match like SQLite does")
	}
	// 查询出错时记录错误
	if _, err = db.Exec(`DROP TABLE cert`); err != nil {
		t.Fatal(err)
	}
	broken := newCertRefMatcher(ctx, conn, 7, "abc")
	if broken.match("7") || broken.err == nil {
		t.Fatal("lookup errors must be recorded, not treated as a non-match")
	}
}

func TestRewriteWorkflowContentEscapedOldSha(t *testing.T) {
	// cert_id 用 JSON 转义写旧 sha（\u0064 = d）：执行器解码后指向旧 sha，文本替换匹配不到
	wf := `{"id":"u","type":"upload","config":{"cert_id":"\u0064old","domains":"a.com","use_local_cert":true,"end_day":30}}`
	ch := certChange{oldSha: "dold", newSha: newSha, domains: "a.com,b.com", usable: true, isRef: refs(newSha)}
	out, err := rewriteWorkflowContent(wf, ch)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeExecTree(out)
	if err != nil {
		t.Fatal(err)
	}
	if root.Config["cert_id"] != newSha || root.Config["domains"] != "a.com,b.com" {
		t.Fatalf("escaped old sha not migrated: %v", root.Config)
	}

	// 旧 sha 以数字开头且该数字被转义（\u0031），新 sha 以字母开头：原文替换会把 \u0031 改成 \u003a（":"）
	wf2 := `{"id":"u","type":"upload","config":{"cert_id":"\u00311abc","domains":"a.com","use_local_cert":true,"end_day":30}}`
	ch2 := certChange{oldSha: "11abc", newSha: "adef", domains: "a.com", usable: true, isRef: refs("adef")}
	out2, err := rewriteWorkflowContent(wf2, ch2)
	if err != nil {
		t.Fatal(err)
	}
	if root2, err := decodeExecTree(out2); err != nil || root2.Config["cert_id"] != "adef" {
		t.Fatalf("escaped digit-leading sha not migrated correctly: %s (%v)", out2, err)
	}
}

func TestRewriteWorkflowContentReplacesShaEverywhere(t *testing.T) {
	// 与原来的全文替换一致：sha 出现在其他节点、键名里也一起替换
	wf := `{"id":"s","type":"start","config":{"note":"uses oldsha","map":{"oldsha":1}},"childNode":{"id":"u","type":"upload","config":{"cert_id":"oldsha","domains":"a.com"}}}`
	ch := certChange{oldSha: "oldsha", newSha: newSha, domains: "a.com", usable: true, isRef: refs(newSha)}
	out, err := rewriteWorkflowContent(wf, ch)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "oldsha") || !strings.Contains(out, `"note":"uses newsha256"`) || !strings.Contains(out, `"newsha256":1`) {
		t.Fatalf("sha not replaced everywhere: %s", out)
	}
}

func TestRewriteWorkflowContentShaOnlyLeavesNodesAlone(t *testing.T) {
	// 执行器把节点当插件（最后的 type 生效），只需替换 sha：不能因为前面的 "Type":"upload" 去改它的 domains
	wf := `{"id":"p","Type":"upload","type":"plugin.demo","config":{"cert_id":"oldsha","domains":"a.com"}}`
	ch := certChange{oldSha: "oldsha", newSha: newSha, domains: "a.com,b.com", usable: true, isRef: refs(newSha)}
	out, err := rewriteWorkflowContent(wf, ch)
	if err != nil {
		t.Fatalf("sha-only rewrite should succeed: %v", err)
	}
	root, err := decodeExecTree(out)
	if err != nil || root.Type != "plugin.demo" || root.Config["cert_id"] != newSha || root.Config["domains"] != "a.com" {
		t.Fatalf("unexpected result: %s (%v)", out, err)
	}
}

func TestRewriteWorkflowContentShaOnlyKeepsKeyOrder(t *testing.T) {
	// "type":"plugin.demo" 在前、"Type":"upload" 在后：执行器按上传节点执行。只换 sha（域名不变）时
	// 原文替换保留键顺序，不能因为重新编码排序键而被拒绝。
	wf := `{"id":"u","type":"plugin.demo","Type":"upload","config":{"cert_id":"oldsha","domains":"a.com"}}`
	ch := certChange{oldSha: "oldsha", newSha: newSha, domains: "a.com", usable: true, isRef: refs(newSha)}
	out, err := rewriteWorkflowContent(wf, ch)
	if err != nil {
		t.Fatalf("sha-only renewal should succeed: %v", err)
	}
	if out != strings.ReplaceAll(wf, "oldsha", newSha) {
		t.Fatalf("expected in-place text replacement, got %s", out)
	}
}

func TestHexCharEscapeRe(t *testing.T) {
	for _, v := range []string{`\u0030`, `\u0039`, `\u0041`, `\u0046`, `\u0061`, `\u0066`, `x\u0064old`} {
		if !hexCharEscapeRe.MatchString(v) {
			t.Errorf("%s should match", v)
		}
	}
	for _, v := range []string{`\u0026`, `\u003a`, `\u0047`, `\u0067`, `\u4e2d`, `plain`} {
		if hexCharEscapeRe.MatchString(v) {
			t.Errorf("%s should not match", v)
		}
	}
}

func TestRewriteWorkflowContentRejectsKeyCollision(t *testing.T) {
	// 同一对象里同时有以旧、新 sha 为键的两项：替换后会合并丢数据，必须拒绝
	wf := `{"id":"s","type":"start","config":{"oldsha":1,"newsha256":2},"childNode":{"id":"u","type":"upload","config":{"cert_id":"oldsha","domains":"a.com"}}}`
	ch := certChange{oldSha: "oldsha", newSha: newSha, domains: "a.com", usable: true, isRef: refs(newSha)}
	if out, err := rewriteWorkflowContent(wf, ch); !errors.Is(err, errUnsafeRewrite) || out != wf {
		t.Fatalf("key collision must be rejected, err=%v out=%s", err, out)
	}
}

func TestNewCertChangeCommaInIdentifier(t *testing.T) {
	// CN 本身是 "a.invalid,b.invalid"：逗号连接存储会被误拆成两个域名，不能作为本地匹配条件
	ch := newCertChange("old", newSha, []string{"a.invalid,b.invalid", "a.invalid"}, refs("7"))
	if ch.usable {
		t.Fatal("identifiers containing commas must not be usable for local matching")
	}
	wf := `{"id":"u","type":"upload","config":{"cert_id":7,"domains":"a.invalid,b.invalid","use_local_cert":true,"end_day":30}}`
	if _, changed, err := syncUploadNodes(wf, ch); !errors.Is(err, errDomainsUnusableForLocalMatch) || changed {
		t.Fatalf("expected errDomainsUnusableForLocalMatch, changed=%v err=%v", changed, err)
	}
	if ok := newCertChange("old", newSha, []string{"a.invalid", "b.invalid"}, refs("7")); !ok.usable || ok.domains != "a.invalid,b.invalid" {
		t.Fatalf("normal identifiers should be usable: %+v", ok)
	}
}

func makeTestCert(t *testing.T, key *ecdsa.PrivateKey, serial int64, cn string, dns []string) string {
	t.Helper()
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: dns, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestUpdateCertSyncsWorkflowsAtomically(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("data", 0755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "data/data.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE cert (id INTEGER PRIMARY KEY, sha256 TEXT, cert TEXT, key TEXT, domains TEXT, end_time TEXT, source TEXT, issuer TEXT, issuer_cert TEXT DEFAULT '', history_id TEXT, workflow_id TEXT, create_time TEXT, update_time TEXT, start_time TEXT, end_day TEXT);
		CREATE TABLE workflow (id INTEGER PRIMARY KEY, name TEXT, content TEXT)`); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	certA := makeTestCert(t, key, 1, "a.invalid", []string{"a.invalid"})
	certAB := makeTestCert(t, key, 2, "a.invalid", []string{"a.invalid", "b.invalid"})
	certC := makeTestCert(t, key, 3, "c.invalid", []string{"c.invalid"})
	certNone := makeTestCert(t, key, 4, "", nil)
	shaA, _ := public.GetSHA256(certA)
	shaAB, _ := public.GetSHA256(certAB)
	if _, err = db.Exec(`INSERT INTO cert (id,sha256,cert,key,domains,source) VALUES (7,?,?,?,?, 'upload')`, shaA, certA, keyPEM, "a.invalid"); err != nil {
		t.Fatal(err)
	}
	// 另一行已经存了 certAB（sha256 不唯一）：编辑后两行 sha 相同，引用仍要同步
	if _, err = db.Exec(`INSERT INTO cert (id,sha256,cert,key,domains,source) VALUES (3,?,?,?,?, 'upload')`, shaAB, certAB, keyPEM, "a.invalid,b.invalid"); err != nil {
		t.Fatal(err)
	}
	workflows := map[int]string{
		1: `{"id":"s","type":"start","childNode":{"id":"u","type":"upload","config":{"cert_id":"` + shaA + `","domains":"a.invalid","use_local_cert":true,"end_day":30}}}`,
		2: `{"id":"s","type":"start","ChildNode":{"Id":"u","Type":"upload","Config":{"cert_id":"007","domains":"a.invalid","use_local_cert":true,"end_day":30}}}`,
		3: `{"id":"s","type":"start","childNode":{"id":"u","type":"upload","config":{"cert_id":"0x7","domains":"a.invalid"}}}`,
	}
	for id, c := range workflows {
		if _, err = db.Exec(`INSERT INTO workflow (id,name,content) VALUES (?,?,?)`, id, fmt.Sprintf("wf%d", id), c); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func() (string, map[int]string) {
		var cert string
		if err := db.QueryRow(`SELECT sha256 || '|' || domains FROM cert WHERE id=7`).Scan(&cert); err != nil {
			t.Fatal(err)
		}
		ws := map[int]string{}
		rows, err := db.Query(`SELECT id, content FROM workflow`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id int
			var c string
			rows.Scan(&id, &c)
			ws[id] = c
		}
		return cert, ws
	}

	// 1. a -> a,b：证书更新，sha 引用与 "007" + 大写字段的引用都同步，"0x7" 不动
	if _, _, uncovered, err := UpdateCert("7", certAB, keyPEM, false); err != nil || len(uncovered) > 0 {
		t.Fatalf("update failed: uncovered=%v err=%v", uncovered, err)
	}
	certRow, ws := snapshot()
	if !strings.HasPrefix(certRow, shaAB+"|") || !sameDomainSet(strings.SplitN(certRow, "|", 2)[1], "a.invalid,b.invalid") {
		t.Fatalf("cert row not updated: %s", certRow)
	}
	for _, id := range []int{1, 2} {
		if !strings.Contains(ws[id], `"domains":"a.invalid,b.invalid"`) && !strings.Contains(ws[id], `"domains":"b.invalid,a.invalid"`) {
			t.Errorf("workflow %d domains not synced: %s", id, ws[id])
		}
	}
	if !strings.Contains(ws[1], shaAB) || strings.Contains(ws[1], shaA) {
		t.Errorf("workflow 1 sha not replaced: %s", ws[1])
	}
	if ws[3] != workflows[3] {
		t.Errorf("workflow 3 must not change: %s", ws[3])
	}

	// 2. 没有任何域名的证书：引用它的节点开启了本地匹配，拒绝且不做任何修改
	if _, _, _, err := UpdateCert("7", certNone, keyPEM, true); err == nil {
		t.Fatal("domainless certificate used by local matching must be rejected")
	}
	if certRow2, ws2 := snapshot(); certRow2 != certRow || ws2[1] != ws[1] || ws2[2] != ws[2] {
		t.Fatal("rejected update must not change anything")
	}

	// 3. 域名未覆盖且未确认：返回 uncovered，不做任何修改
	if _, newSha, uncovered, err := UpdateCert("7", certC, keyPEM, false); err != nil || len(uncovered) == 0 || newSha != "" {
		t.Fatalf("expected confirmation, uncovered=%v err=%v", uncovered, err)
	}
	if certRow3, ws3 := snapshot(); certRow3 != certRow || ws3[1] != ws[1] || ws3[2] != ws[2] {
		t.Fatal("unconfirmed update must not change anything")
	}

	// 2b. 没有工作流做本地匹配的证书可以换成无域名证书（如客户端证书）
	if _, err = db.Exec(`INSERT INTO cert (id,sha256,cert,key,domains,source) VALUES (9,'sha9',?,?,'c.invalid','upload')`, certC, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := UpdateCert("9", certNone, keyPEM, true); err != nil {
		t.Fatalf("domainless certificate without local matching should be allowed: %v", err)
	}
	var dom9 string
	if err := db.QueryRow(`SELECT domains FROM cert WHERE id=9`).Scan(&dom9); err != nil || dom9 != "" {
		t.Fatalf("cert 9 domains = %q, err=%v", dom9, err)
	}
	if _, ws2b := snapshot(); ws2b[1] != ws[1] || ws2b[2] != ws[2] {
		t.Fatal("unrelated workflows must not change")
	}

	// 3b. CN 带逗号的证书：引用它的节点开启了本地匹配，拒绝且不做任何修改
	certComma := makeTestCert(t, key, 5, "a.invalid,b.invalid", []string{"a.invalid"})
	if _, _, _, err := UpdateCert("7", certComma, keyPEM, true); err == nil {
		t.Fatal("certificate with a comma in an identifier must be rejected when local matching uses it")
	}
	if certRow3b, ws3b := snapshot(); certRow3b != certRow || ws3b[1] != ws[1] || ws3b[2] != ws[2] {
		t.Fatal("rejected comma update must not change anything")
	}

	// 3c. 上传与编辑规则一致：标识带逗号的证书上传同样被拒绝
	if _, err := UploadCert(keyPEM, makeTestCert(t, key, 10, "x.invalid,y.invalid", []string{"x.invalid"})); err == nil {
		t.Fatal("uploading a certificate with a comma in an identifier must be rejected")
	}
	var n10 int
	if err := db.QueryRow(`SELECT count(*) FROM cert WHERE domains LIKE '%y.invalid%'`).Scan(&n10); err != nil || n10 != 0 {
		t.Fatalf("rejected upload must not be stored: %d %v", n10, err)
	}
	// 规则上线前已入库的同一张证书重新上传，也不能走去重分支绕过校验
	legacy := makeTestCert(t, key, 12, "p.invalid,q.invalid", []string{"p.invalid"})
	legacySha, _ := public.GetSHA256(legacy)
	if _, err = db.Exec(`INSERT INTO cert (id,sha256,cert,key,domains,source) VALUES (12,?,?,?,'p.invalid,q.invalid,p.invalid','upload')`, legacySha, legacy, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := UploadCert(keyPEM, legacy); err == nil {
		t.Fatal("re-uploading a legacy comma-identifier certificate must be rejected")
	}

	// 4. 只有空 DNS SAN 的证书同样视为没有域名
	if certBlank, err := x509CertWithBlankSAN(t, key); err != nil {
		t.Logf("skip blank-SAN case: %v", err)
	} else {
		if _, _, _, err := UpdateCert("7", certBlank, keyPEM, true); err == nil {
			t.Fatal("certificate with only a blank SAN must be rejected")
		}
		if certRow4, _ := snapshot(); certRow4 != certRow {
			t.Fatal("rejected blank-SAN update must not change the certificate")
		}
	}

	// 5. 引用该证书的节点字段有歧义：整个编辑报错回滚
	if _, err = db.Exec(`INSERT INTO workflow (id,name,content) VALUES (4,'wf4',?)`, `{"id":"s","type":"start","childNode":{"id":"u","type":"plugin.demo","Type":"upload","config":{"cert_id":"7","domains":"a.invalid,b.invalid"}}}`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := UpdateCert("7", certA, keyPEM, true); err == nil {
		t.Fatal("ambiguous referencing workflow must fail the update")
	}
	if certRow5, ws5 := snapshot(); certRow5 != certRow || ws5[1] != ws[1] || ws5[2] != ws[2] {
		t.Fatal("failed update must roll back certificate and workflows")
	}
	if _, err = db.Exec(`UPDATE workflow SET content=? WHERE id=4`, `{"id":"s","type":"start","childNode":{"id":"u","type":"upload"},"ChildNode":{"config":{"cert_id":"7","domains":"a.invalid,b.invalid"}}}`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := UpdateCert("7", certA, keyPEM, true); err == nil {
		t.Fatal("split childNode referencing the cert must fail the update")
	}
	if certRow5b, ws5b := snapshot(); certRow5b != certRow || ws5b[1] != ws[1] || ws5b[2] != ws[2] {
		t.Fatal("failed update must roll back certificate and workflows")
	}
	if _, err = db.Exec(`DELETE FROM workflow WHERE id=4`); err != nil {
		t.Fatal(err)
	}

	// 6. 某个工作流写入失败：证书和已写的工作流都回滚
	if _, err = db.Exec(`CREATE TRIGGER fail_wf2 BEFORE UPDATE ON workflow WHEN NEW.id=2 BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := UpdateCert("7", certA, keyPEM, true); err == nil {
		t.Fatal("workflow write failure must fail the update")
	}
	if certRow6, ws6 := snapshot(); certRow6 != certRow || ws6[1] != ws[1] || ws6[2] != ws[2] {
		t.Fatal("workflow write failure must roll back certificate and workflow 1")
	}
	if _, err = db.Exec(`DROP TRIGGER fail_wf2`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := UpdateCert("7", certA, keyPEM, true); err != nil {
		t.Fatalf("update should succeed after the failure is gone: %v", err)
	}
	if certRow7, ws7 := snapshot(); !strings.HasPrefix(certRow7, shaA+"|") || !strings.Contains(ws7[1], shaA) || !strings.Contains(ws7[2], `"domains":"a.invalid"`) {
		t.Fatalf("retry did not apply: %s / %s / %s", certRow7, ws7[1], ws7[2])
	}
}

// x509CertWithBlankSAN 生成没有 CN、只有一个空 DNS SAN 的证书；当前 Go 版本不允许生成时返回错误。
func x509CertWithBlankSAN(t *testing.T, key *ecdsa.PrivateKey) (string, error) {
	t.Helper()
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(99), DNSNames: []string{""}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	if c, err := x509.ParseCertificate(der); err != nil || len(c.DNSNames) != 1 || c.DNSNames[0] != "" {
		return "", fmt.Errorf("blank SAN not preserved: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
