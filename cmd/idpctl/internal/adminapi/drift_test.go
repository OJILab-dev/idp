package adminapi_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGeneratedCodeMatchesSpec regenerates the client from the OpenAPI spec
// and fails when the committed file differs, so a spec change cannot land
// without the Go types that idpctl is built from. It needs the oapi-codegen
// pinned in mise.toml on PATH (mise exec -- go test ./...); a missing
// generator fails instead of skipping, because a skipped drift check is a
// silent pass.
func TestGeneratedCodeMatchesSpec(t *testing.T) {
	generator, err := exec.LookPath("oapi-codegen")
	if err != nil {
		t.Fatalf("oapi-codegen is not on PATH; run the tests through mise exec: %v", err)
	}

	// The generator writes to the output named in its config and ignores -o
	// when a config is given, so the test runs it with a copy that points
	// into a temporary directory.
	dir := t.TempDir()
	out := filepath.Join(dir, "adminapi.gen.go")
	config, err := os.ReadFile("oapi-codegen.yaml")
	if err != nil {
		t.Fatal(err)
	}
	config = bytes.Replace(config, []byte("\noutput: adminapi.gen.go\n"), []byte("\noutput: "+out+"\n"), 1)
	if !bytes.Contains(config, []byte(out)) {
		t.Fatal("oapi-codegen.yaml no longer names adminapi.gen.go as its output")
	}
	configPath := filepath.Join(dir, "oapi-codegen.yaml")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	// go test can replay a cached pass after the spec changes, because the
	// spec lies outside this module; mise run idpctl:check therefore runs
	// the tests with -count=1.
	cmd := exec.Command(generator, "-config", configPath, "../../../../contract/openapi/admin.json")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("oapi-codegen failed: %v\n%s", err, output)
	}

	want, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("adminapi.gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("adminapi.gen.go is stale; run mise run idpctl:generate and commit the result")
	}
}
