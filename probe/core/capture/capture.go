package capture

import (
	"fmt"
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Capture interface for packet capture implementations
type Capture interface {
	Start() error
	Stop() error
	OnPacket(handler func([]byte))
}

// PcapCapture implements Capture using pcap
type PcapCapture struct {
	handle      *pcap.Handle
	iface       string
	bpfFilter   string
	snapLen     int
	promiscuous bool
	running     bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
	handler     func([]byte)
	mu          sync.RWMutex
}

// NewPcapCapture creates a new pcap-based capture
func NewPcapCapture(iface, bpfFilter string, snapLen int, promiscuous bool) (*PcapCapture, error) {
	handle, err := pcap.OpenLive(iface, int32(snapLen), promiscuous, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
	}
	handle.Close()

	return &PcapCapture{
		iface:       iface,
		bpfFilter:   bpfFilter,
		snapLen:     snapLen,
		promiscuous: promiscuous,
		stopCh:      make(chan struct{}),
	}, nil
}

// Start begins packet capture
func (p *PcapCapture) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("capture already running")
	}

	handle, err := pcap.OpenLive(p.iface, int32(p.snapLen), p.promiscuous, pcap.BlockForever)
	if err != nil {
		p.mu.Unlock()
		return fmt.Errorf("failed to open interface: %w", err)
	}
	p.handle = handle

	if p.bpfFilter != "" {
		if err := handle.SetBPFFilter(p.bpfFilter); err != nil {
			handle.Close()
			p.mu.Unlock()
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	p.running = true
	p.mu.Unlock()

	p.wg.Add(1)
	go p.processPackets()

	return nil
}

// Stop stops packet capture
func (p *PcapCapture) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	p.mu.Unlock()

	close(p.stopCh)
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.handle != nil {
		p.handle.Close()
		p.handle = nil
	}
	return nil
}

// OnPacket sets the packet handler callback
func (p *PcapCapture) OnPacket(handler func([]byte)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handler = handler
}

func (p *PcapCapture) processPackets() {
	defer p.wg.Done()

	packetSource := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
	packetSource.NoCopy = true

	for {
		select {
		case <-p.stopCh:
			return
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				continue
			}
			p.mu.RLock()
			handler := p.handler
			p.mu.RUnlock()

			if handler != nil {
				handler(packet.Data())
			}
		}
	}
}

// PFRingCapture implements Capture using PF_RING
type PFRingCapture struct {
	stopCh chan struct{}
}

// NewPFRingCapture creates a new PF_RING capture (when available)
func NewPFRingCapture(iface string) (*PFRingCapture, error) {
	return nil, fmt.Errorf("PF_RING not implemented: requires CGO and PF_RING library")
}

func (p *PFRingCapture) Start() error {
	return fmt.Errorf("PF_RING not implemented")
}

func (p *PFRingCapture) Stop() error {
	return nil
}

func (p *PFRingCapture) OnPacket(handler func([]byte)) {
}

// NewCapture creates an appropriate capture based on availability
func NewCapture(iface, bpfFilter string, snapLen int, promiscuous bool) (Capture, error) {
	pfRing, err := NewPFRingCapture(iface)
	if err == nil {
		log.Println("Using PF_RING for packet capture")
		return pfRing, nil
	}

	log.Println("PF_RING not available, falling back to pcap")
	return NewPcapCapture(iface, bpfFilter, snapLen, promiscuous)
}
