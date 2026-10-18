package elkeidrasp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPythonEnv(t *testing.T) {
	env, err := PythonEnv(Config{PythonProbePath: "/opt/elkeid/rasp/python", ConfigPath: "/etc/lyflow/rasp.json", Root: "/opt/elkeid/rasp"})
	if err != nil {
		t.Fatalf("env: %v", err)
	}
	joined := strings.Join(env, " ")
	for _, expected := range []string{"PYTHONPATH=/opt/elkeid/rasp/python", "LYFLOW_RASP_CONFIG=/etc/lyflow/rasp.json", "LYFLOW_RASP_ROOT=/opt/elkeid/rasp", "LYFLOW_RASP_MODE=monitor"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %q in %v", expected, env)
		}
	}
	if _, err := PythonEnv(Config{}); err == nil {
		t.Fatal("expected probe path error")
	}
}

func TestProbe(t *testing.T) {
	dir := t.TempDir()
	if err := Probe(Config{PythonProbePath: dir}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := Probe(Config{PythonProbePath: file}); err == nil {
		t.Fatal("expected directory error")
	}
	if err := Probe(Config{PythonProbePath: filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("expected missing probe error")
	}
}
