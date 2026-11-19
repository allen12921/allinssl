package cert_test

import (
	"ALLinSSL/backend/internal/cert"
	"ALLinSSL/backend/internal/workflow"
	"reflect"
	"testing"
)

// cert.ExecNode 用于按执行器的方式解码工作流，必须与 workflow.WorkflowNode 的 JSON 结构完全一致。
func TestExecNodeMatchesWorkflowNode(t *testing.T) {
	// 两边对应的命名类型
	pairs := map[reflect.Type]reflect.Type{
		reflect.TypeOf(cert.ExecNode{}):       reflect.TypeOf(workflow.WorkflowNode{}),
		reflect.TypeOf(cert.ExecNodeParams{}): reflect.TypeOf(workflow.WorkflowNodeParams{}),
	}
	visited := map[reflect.Type]bool{} // 结构体是递归的（ChildNode *ExecNode），每个命名类型只展开一次
	var same func(a, b reflect.Type, path string)
	same = func(a, b reflect.Type, path string) {
		if want, ok := pairs[a]; ok {
			if b != want {
				t.Errorf("%s: %s should correspond to %s, got %s", path, a, want, b)
				return
			}
			if visited[a] {
				return
			}
			visited[a] = true
			if a.NumField() != b.NumField() {
				t.Errorf("%s: %s has %d fields, %s has %d", path, a, a.NumField(), b, b.NumField())
				return
			}
			for i := 0; i < a.NumField(); i++ {
				fa, fb := a.Field(i), b.Field(i)
				p := path + "." + fa.Name
				if fa.Name != fb.Name || fa.Tag.Get("json") != fb.Tag.Get("json") {
					t.Errorf("%s: field %s `%s` vs %s `%s`", p, fa.Name, fa.Tag, fb.Name, fb.Tag)
					continue
				}
				same(fa.Type, fb.Type, p)
			}
			return
		}
		if a.Kind() != b.Kind() {
			t.Errorf("%s: kind %s vs %s", path, a.Kind(), b.Kind())
			return
		}
		switch a.Kind() {
		case reflect.Ptr, reflect.Slice:
			same(a.Elem(), b.Elem(), path+"[]")
		case reflect.Map:
			same(a.Key(), b.Key(), path+"[key]")
			same(a.Elem(), b.Elem(), path+"[val]")
		default:
			if a != b {
				t.Errorf("%s: type %s vs %s", path, a, b)
			}
		}
	}
	same(reflect.TypeOf(cert.ExecNode{}), reflect.TypeOf(workflow.WorkflowNode{}), "ExecNode")
}
