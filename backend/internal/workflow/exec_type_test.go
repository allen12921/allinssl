package workflow

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

// UpdExecType 读改写整份 content：在另一个写事务提交前必须等待，提交后基于最新内容修改，不能覆盖那次写入。
func TestUpdExecTypeDoesNotOverwriteConcurrentWrite(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("data", 0755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "data/data.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE workflow (id INTEGER PRIMARY KEY, name TEXT, content TEXT, exec_type TEXT, update_time TEXT)`); err != nil {
		t.Fatal(err)
	}
	const before = `{"id":"s","type":"start","config":{"exec_type":"manual"},"childNode":{"id":"u","type":"upload","config":{"cert_id":"7","domains":"a.invalid"}}}`
	const synced = `{"id":"s","type":"start","config":{"exec_type":"manual"},"childNode":{"id":"u","type":"upload","config":{"cert_id":"7","domains":"a.invalid,b.invalid"}}}`
	if _, err = db.Exec(`INSERT INTO workflow (id,name,content,exec_type) VALUES (1,'wf',?,'manual')`, before); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// 模拟编辑证书：持有写锁
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- UpdExecType("1", "auto") }()
	select {
	case err := <-done:
		t.Fatalf("UpdExecType should wait for the write lock, returned %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err = conn.ExecContext(ctx, `UPDATE workflow SET content=? WHERE id=1`, synced); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("UpdExecType did not finish")
	}

	var content, execType string
	if err = db.QueryRow(`SELECT content, exec_type FROM workflow WHERE id=1`).Scan(&content, &execType); err != nil {
		t.Fatal(err)
	}
	if execType != "auto" || !strings.Contains(content, `"exec_type":"auto"`) {
		t.Fatalf("exec_type not updated: %s / %s", execType, content)
	}
	if !strings.Contains(content, `"domains":"a.invalid,b.invalid"`) {
		t.Fatalf("concurrent write was overwritten: %s", content)
	}
}
