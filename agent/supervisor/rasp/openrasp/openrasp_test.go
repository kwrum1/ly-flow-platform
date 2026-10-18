package openrasp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJavaAgentArgs(t *testing.T) {
	args, err := JavaAgentArgs(Config{
		JarPath: "/opt/openrasp/rasp.jar", Root: "/opt/openrasp", ConfigPath: "/etc/openrasp.conf",
	})
	if err != nil {
		t.Fatalf("args: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, expected := range []string{"-javaagent:/opt/openrasp/rasp.jar", "-Dopenrasp.root=/opt/openrasp", "-Dopenrasp.config=/etc/openrasp.conf", "-Dopenrasp.cloud.enable=false"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %q in %v", expected, args)
		}
	}
	if _, err := JavaAgentArgs(Config{}); err == nil {
		t.Fatal("expected jar path error")
	}
}

func TestPHPIni(t *testing.T) {
	ini, err := PHPIni(Config{PHPModulePath: "/opt/openrasp/openrasp.so", Root: "/opt/openrasp"})
	if err != nil {
		t.Fatalf("ini: %v", err)
	}
	for _, expected := range []string{"extension=/opt/openrasp/openrasp.so", "openrasp.root=/opt/openrasp", "openrasp.cloud.enable=0"} {
		if !strings.Contains(ini, expected) {
			t.Fatalf("missing %q in %q", expected, ini)
		}
	}
	if _, err := PHPIni(Config{}); err == nil {
		t.Fatal("expected php module error")
	}
}

func TestProbe(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "rasp.jar")
	if err := os.WriteFile(jar, []byte("jar"), 0o644); err != nil {
		t.Fatalf("write jar: %v", err)
	}
	if err := Probe(Config{JarPath: jar}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := Probe(Config{}); err == nil {
		t.Fatal("expected empty probe error")
	}
	if err := Probe(Config{JarPath: filepath.Join(dir, "missing.jar")}); err == nil {
		t.Fatal("expected missing file error")
	}
}
