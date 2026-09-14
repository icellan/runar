package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/icellan/runar/compilers/go/ir"
)

// R-048: /api/compile is a public playground endpoint that runs the full
// compiler pipeline on caller-supplied source. Three properties keep one
// small POST from occupying unbounded server resources:
//
//  1. the request body is capped, and the cap is enforced while reading
//     (not after buffering the whole thing),
//  2. the HTTP server enforces read/write/idle timeouts, so a slowloris
//     client cannot pin a connection forever,
//  3. a compile that overruns a deadline is abandoned with an error status
//     instead of holding the request goroutine indefinitely.
//
// Rate limiting and authentication are deliberately out of scope here --
// this is demo code, and both are product decisions rather than bug fixes.

// countingReader records how many bytes were actually pulled from the
// underlying source, which is how we prove the handler stops reading at the
// cap rather than draining a huge body first.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func TestCompile_OversizeBodyRejectedWithoutFullRead(t *testing.T) {
	origLimit := maxCompileBodyBytes
	origFn := compileSourceFn
	t.Cleanup(func() {
		maxCompileBodyBytes = origLimit
		compileSourceFn = origFn
	})

	maxCompileBodyBytes = 256

	compiled := false
	compileSourceFn = func(src []byte, filename string) (string, string, *ir.ANFProgram, error) {
		compiled = true
		return "", "", nil, nil
	}

	// A body two orders of magnitude over the cap. The real endpoint has no
	// upper bound at all, so this stands in for "attacker sends 500 MB".
	payload := `{"lang":"ts","source":"` + strings.Repeat("a", 64*1024) + `"}`
	body := &countingReader{r: strings.NewReader(payload)}

	req := httptest.NewRequest(http.MethodPost, "/api/compile", body)
	rec := httptest.NewRecorder()
	handleCompile(rec, req)

	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("oversize body: want a 4xx status, got %d (%s)", rec.Code, rec.Body.String())
	}
	if compiled {
		t.Fatal("oversize body: compiler ran on a body that exceeded the cap")
	}
	// MaxBytesReader stops one byte past the limit; allow a little slack for
	// however the JSON decoder chunks its reads, but nothing near the payload.
	if body.n > maxCompileBodyBytes+1024 {
		t.Fatalf("oversize body: handler read %d bytes, want <= %d (cap %d)",
			body.n, maxCompileBodyBytes+1024, maxCompileBodyBytes)
	}
}

func TestServer_EnforcesTimeouts(t *testing.T) {
	srv := newServer("0")

	if srv.ReadTimeout <= 0 {
		t.Errorf("server ReadTimeout is %v, want > 0", srv.ReadTimeout)
	}
	if srv.WriteTimeout <= 0 {
		t.Errorf("server WriteTimeout is %v, want > 0", srv.WriteTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Errorf("server IdleTimeout is %v, want > 0", srv.IdleTimeout)
	}
	if srv.Handler == nil {
		t.Error("server has no handler")
	}
	// The compile deadline must fit inside the write deadline, otherwise the
	// client's connection is torn down before the handler can answer.
	if compileTimeout >= srv.WriteTimeout {
		t.Errorf("compileTimeout %v must be shorter than WriteTimeout %v",
			compileTimeout, srv.WriteTimeout)
	}
}

func TestCompile_AbandonsCompileThatOverrunsDeadline(t *testing.T) {
	origTimeout := compileTimeout
	origFn := compileSourceFn

	release := make(chan struct{})
	stubDone := make(chan struct{})

	// Release the abandoned compile goroutine and wait for it to finish
	// before restoring the injection seams -- otherwise the restore races
	// the goroutine's read of compileSourceFn.
	t.Cleanup(func() {
		close(release)
		<-stubDone
		compileTimeout = origTimeout
		compileSourceFn = origFn
	})

	compileTimeout = 25 * time.Millisecond
	compileSourceFn = func(src []byte, filename string) (string, string, *ir.ANFProgram, error) {
		defer close(stubDone)
		<-release // stands in for a pathological compile that never returns
		return "", "", nil, nil
	}

	payload, _ := json.Marshal(map[string]string{"lang": "ts", "source": "class C {}"})
	req := httptest.NewRequest(http.MethodPost, "/api/compile", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handleCompile(rec, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleCompile did not return: the compile pins the request goroutine forever")
	}

	if rec.Code < 400 {
		t.Fatalf("overrunning compile: want a 4xx/5xx status, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// Guard against the cap or the deadline breaking ordinary use: the reference
// PriceBet source is well under both and must still compile end to end.
//
// (The bundled PriceBet.runar.java is deliberately not used here -- it fails
// typecheck through the Go tier's Java front end at this commit, which is a
// pre-existing defect unrelated to R-048.)
func TestCompile_NormalRequestStillSucceeds(t *testing.T) {
	src, err := os.ReadFile("../ts/PriceBet.runar.ts")
	if err != nil {
		t.Skipf("reference TypeScript source unavailable: %v", err)
	}
	if int64(len(src)) >= maxCompileBodyBytes {
		t.Fatalf("reference source (%d bytes) exceeds the request cap (%d)", len(src), maxCompileBodyBytes)
	}

	payload, _ := json.Marshal(map[string]string{
		"filename": "PriceBet.runar.ts",
		"source":   string(src),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compile", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handleCompile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("normal compile: got %d (%s)", rec.Code, rec.Body.String())
	}
}
