package main

import "testing"

func TestGithubMirrorEndpointsOrder(t *testing.T) {
	primary := "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml"
	endpoints := githubMirrorEndpoints(primary)
	if len(endpoints) < 4 {
		t.Fatalf("expected mirror chain, got %v", endpoints)
	}
	if endpoints[0] != primary {
		t.Fatalf("primary must be first: %v", endpoints)
	}
	want := []string{
		"https://cdn.jsdelivr.net/gh/SigmaHQ/sigma@master/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml",
		"https://raw.gitmirror.com/SigmaHQ/sigma/master/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml",
	}
	for _, expected := range want {
		found := false
		for _, endpoint := range endpoints {
			if endpoint == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing mirror %s in %v", expected, endpoints)
		}
	}
	for _, endpoint := range endpoints {
		if endpoint == "" {
			t.Fatalf("empty endpoint in %v", endpoints)
		}
	}
}

func TestGithubMirrorEndpointsSkipsOtherHosts(t *testing.T) {
	primary := "https://rules.emergingthreats.net/open/suricata/emerging-all.rules"
	endpoints := githubMirrorEndpoints(primary)
	if len(endpoints) != 1 || endpoints[0] != primary {
		t.Fatalf("non-GitHub source must stay single: %v", endpoints)
	}
}
