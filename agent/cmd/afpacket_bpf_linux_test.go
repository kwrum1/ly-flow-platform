//go:build linux

package main

import (
	"testing"

	"golang.org/x/net/bpf"
)

func TestCompileLinuxCaptureBPFSupportsStaticAgentFilters(t *testing.T) {
	tests := []struct {
		filter     string
		ipProtocol byte
		want       bool
	}{
		{filter: "tcp", ipProtocol: 6, want: true},
		{filter: "tcp", ipProtocol: 17, want: false},
		{filter: "udp", ipProtocol: 17, want: true},
		{filter: "udp", ipProtocol: 6, want: false},
		{filter: "tcp or udp", ipProtocol: 6, want: true},
		{filter: "udp or tcp", ipProtocol: 17, want: true},
	}
	for _, test := range tests {
		raw, err := compileLinuxCaptureBPF(test.filter, 65536)
		if err != nil {
			t.Fatalf("compileLinuxCaptureBPF(%q): %v", test.filter, err)
		}
		instructions, allDecoded := bpf.Disassemble(raw)
		if !allDecoded {
			t.Fatal("compiled BPF contains an undecodable instruction")
		}
		vm, err := bpf.NewVM(instructions)
		if err != nil {
			t.Fatalf("new BPF VM: %v", err)
		}
		packet := make([]byte, 64)
		packet[12], packet[13] = 0x08, 0x00
		packet[23] = test.ipProtocol
		got, err := vm.Run(packet)
		if err != nil {
			t.Fatalf("run BPF filter %q: %v", test.filter, err)
		}
		if (got != 0) != test.want {
			t.Fatalf("filter=%q protocol=%d accepted=%v, want %v", test.filter, test.ipProtocol, got != 0, test.want)
		}
	}
}

func TestCompileLinuxCaptureBPFRejectsUnknownSyntax(t *testing.T) {
	if _, err := compileLinuxCaptureBPF("host 192.0.2.1", 65536); err == nil {
		t.Fatal("unknown dynamic libpcap syntax was accepted")
	}
}
