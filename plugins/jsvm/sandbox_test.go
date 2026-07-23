package jsvm

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/tests"
)

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// newSandboxApp registers a sandboxed jsvm plugin over a single hook file and
// returns the (already-bootstrapped) test app.
func newSandboxApp(t *testing.T, hookSrc string) *tests.TestApp {
	t.Helper()
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Cleanup)

	hooksDir := filepath.Join(t.TempDir(), "pb_hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, "main.pb.js"), []byte(hookSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	MustRegister(app, Config{HooksDir: hooksDir, Sandboxed: true})
	return app
}

// serveRoute builds the app's serve mux (firing OnServe, which registers hook
// routes) and issues one request against it.
func serveRoute(t *testing.T, app *tests.TestApp, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	mux, err := apis.BuildServeMux(app, apis.ServeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestSandboxProcessEnvEmpty(t *testing.T) {
	t.Setenv("SANDBOX_SECRET", "leak-me")

	hook := `
		routerAdd('GET', '/leak', (e) => {
			return e.json(200, { secret: process.env.SANDBOX_SECRET ?? null, keys: Object.keys(process.env).length })
		})
	`
	app := newSandboxApp(t, hook)
	rec := serveRoute(t, app, "GET", "/leak")
	if rec.Code != 200 {
		t.Fatalf("route status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !contains(body, `"secret":null`) {
		t.Fatalf("expected sandboxed process.env.SANDBOX_SECRET to be null, got %s", body)
	}
	if !contains(body, `"keys":0`) {
		t.Fatalf("expected sandboxed process.env to be empty, got %s", body)
	}
}
