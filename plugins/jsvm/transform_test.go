package jsvm

import (
	"strings"
	"testing"
)

func TestIsTypeScript(t *testing.T) {
	cases := map[string]bool{
		"main.pb.ts":  true,
		"001_init.ts": true,
		"main.pb.js":  false,
		"001_init.js": false,
		"notes.txt":   false,
	}
	for name, want := range cases {
		if got := isTypeScript(name); got != want {
			t.Errorf("isTypeScript(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTransformSource_TranspilesTS(t *testing.T) {
	// Type annotations + enum are TS-only syntax goja cannot parse.
	src := []byte("enum E { A, B }\nconst x: number = E.A\nrouterAdd('GET','/x',()=>{})")
	out, err := transformSource("main.pb.ts", src)
	if err != nil {
		t.Fatalf("transformSource: %v", err)
	}
	js := string(out)
	if strings.Contains(js, ": number") {
		t.Fatalf("type annotation not stripped: %s", js)
	}
	if !strings.Contains(js, "routerAdd") {
		t.Fatalf("expected routerAdd call preserved: %s", js)
	}
}

func TestTransformSource_PassesThroughJS(t *testing.T) {
	src := []byte("const x = 1 // plain js")
	out, err := transformSource("main.pb.js", src)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(src) {
		t.Fatalf(".js must pass through byte-identical; got %q", out)
	}
}

func TestTransformSource_WarningStillTranspiles(t *testing.T) {
	// `typeof x === "strnig"` is a typo esbuild flags as a warning (the string is
	// never a valid typeof result) but does NOT treat as an error. The transform
	// must still succeed and emit runnable JS.
	src := []byte("const x: number = 1\nif (typeof x === \"strnig\") { routerAdd('GET','/x',()=>{}) }")
	out, err := transformSource("warn.pb.ts", src)
	if err != nil {
		t.Fatalf("warning-only input must not fail: %v", err)
	}
	js := string(out)
	if strings.Contains(js, ": number") {
		t.Fatalf("type annotation not stripped: %s", js)
	}
	if !strings.Contains(js, "routerAdd") {
		t.Fatalf("expected routerAdd call preserved: %s", js)
	}
}

func TestTransformSource_SyntaxErrorIsClear(t *testing.T) {
	out, err := transformSource("bad.pb.ts", []byte("const x: = "))
	if err == nil {
		t.Fatalf("expected transpile error, got out=%q", out)
	}
	if !strings.Contains(err.Error(), "bad.pb.ts") {
		t.Fatalf("error should name the file: %v", err)
	}
}
