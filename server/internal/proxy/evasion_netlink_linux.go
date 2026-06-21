//go:build linux

package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// ExecuteInNamespace switches execution to a target named namespace, runs a function, and returns to the original namespace.
func ExecuteInNamespace(nsName string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get original netns: %w", err)
	}
	defer origns.Close()

	targetNs, err := netns.GetFromName(nsName)
	if err != nil {
		return fmt.Errorf("failed to get target netns %q: %w", nsName, err)
	}
	defer targetNs.Close()

	if err := netns.Set(targetNs); err != nil {
		return fmt.Errorf("failed to switch to netns %q: %w", nsName, err)
	}
	defer netns.Set(origns)

	return fn()
}

// CreateNamespace creates a named network namespace.
func CreateNamespace(name string) error {
	_, err := netns.NewNamed(name)
	if err != nil {
		return fmt.Errorf("failed to create named namespace %q: %w", name, err)
	}
	return nil
}

// DeleteNamespace deletes a named network namespace.
func DeleteNamespace(name string) error {
	if err := netns.DeleteNamed(name); err != nil {
		return fmt.Errorf("failed to delete named namespace %q: %w", name, err)
	}
	return nil
}

// SetupNamespaceInterface creates a veth pair, assigns host IP, moves the peer into target namespace, and configures peer routing.
func SetupNamespaceInterface(nsName, vethHost, vethPeer, hostCIDR, peerCIDR, gateway string) error {
	// Remove interfaces if they already exist to ensure idempotency
	if oldLink, err := netlink.LinkByName(vethHost); err == nil {
		_ = netlink.LinkDel(oldLink)
	}

	// 1. Create the veth pair
	la := netlink.NewLinkAttrs()
	la.Name = vethHost
	veth := &netlink.Veth{
		LinkAttrs: la,
		PeerName:  vethPeer,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair %q <-> %q: %w", vethHost, vethPeer, err)
	}

	// 2. Configure host side
	hostLink, err := netlink.LinkByName(vethHost)
	if err != nil {
		return fmt.Errorf("failed to get host link %q: %w", vethHost, err)
	}
	hostAddr, err := netlink.ParseAddr(hostCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse host CIDR %q: %w", hostCIDR, err)
	}
	if err := netlink.AddrAdd(hostLink, hostAddr); err != nil {
		return fmt.Errorf("failed to assign IP %q to host link %q: %w", hostCIDR, vethHost, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("failed to bring host link %q up: %w", vethHost, err)
	}

	// 3. Move peer to target namespace
	peerLink, err := netlink.LinkByName(vethPeer)
	if err != nil {
		return fmt.Errorf("failed to get peer link %q: %w", vethPeer, err)
	}
	ns, err := netns.GetFromName(nsName)
	if err != nil {
		return fmt.Errorf("failed to get namespace %q: %w", nsName, err)
	}
	defer ns.Close()
	if err := netlink.LinkSetNsFd(peerLink, int(ns)); err != nil {
		return fmt.Errorf("failed to move peer link %q to namespace %q: %w", vethPeer, nsName, err)
	}

	// 4. Configure peer inside the namespace
	err = ExecuteInNamespace(nsName, func() error {
		link, err := netlink.LinkByName(vethPeer)
		if err != nil {
			return fmt.Errorf("failed to get link %q inside namespace: %w", vethPeer, err)
		}
		peerAddr, err := netlink.ParseAddr(peerCIDR)
		if err != nil {
			return fmt.Errorf("failed to parse peer CIDR %q: %w", peerCIDR, err)
		}
		if err := netlink.AddrAdd(link, peerAddr); err != nil {
			return fmt.Errorf("failed to assign IP %q to peer link inside namespace: %w", peerCIDR, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to bring peer link up inside namespace: %w", err)
		}

		// Enable loopback in namespace
		lo, err := netlink.LinkByName("lo")
		if err == nil {
			_ = netlink.LinkSetUp(lo)
		}

		// Add default routing route if gateway is set
		if gateway != "" {
			gwIP := net.ParseIP(gateway)
			if gwIP == nil {
				return fmt.Errorf("failed to parse gateway IP %q", gateway)
			}
			_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
			route := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       defaultDst,
				Gw:        gwIP,
			}
			if err := netlink.RouteAdd(route); err != nil {
				return fmt.Errorf("failed to add default route inside namespace: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to configure namespace interface: %w", err)
	}

	return nil
}

// runCommand runs a command, optionally inside a specific namespace using ip netns.
func runCommand(nsName string, name string, args ...string) error {
	var cmd *exec.Cmd
	if nsName != "" {
		cmdArgs := append([]string{"netns", "exec", nsName, name}, args...)
		cmd = exec.Command("ip", cmdArgs...)
	} else {
		cmd = exec.Command(name, args...)
	}
	return cmd.Run()
}

// SetupRedirectRules configures nftables or iptables redirect rules in the host or a namespace.
func SetupRedirectRules(nsName string, localPort, redirectPort int) error {
	// Try nftables first
	err := runCommand(nsName, "nft", "--version")
	if err == nil {
		_ = runCommand(nsName, "nft", "add", "table", "ip", "nat")
		_ = runCommand(nsName, "nft", "add", "chain", "ip", "nat", "prerouting", "{ type nat hook prerouting priority dstnat ; }")
		_ = runCommand(nsName, "nft", "add", "chain", "ip", "nat", "output", "{ type nat hook output priority -100 ; }")
		
		err1 := runCommand(nsName, "nft", "add", "rule", "ip", "nat", "prerouting", "tcp", "dport", fmt.Sprintf("%d", localPort), "redirect", "to", fmt.Sprintf("%d", redirectPort))
		err2 := runCommand(nsName, "nft", "add", "rule", "ip", "nat", "output", "tcp", "dport", fmt.Sprintf("%d", localPort), "redirect", "to", fmt.Sprintf("%d", redirectPort))
		if err1 == nil && err2 == nil {
			return nil
		}
	}

	// Fallback to iptables
	err1 := runCommand(nsName, "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", fmt.Sprintf("%d", localPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort))
	err2 := runCommand(nsName, "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-o", "lo", "--dport", fmt.Sprintf("%d", localPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort))
	if err1 != nil || err2 != nil {
		return fmt.Errorf("failed to setup redirect rules using nftables and iptables: %v, %v", err1, err2)
	}

	return nil
}

// ClearRedirectRules removes the configured redirect rules.
func ClearRedirectRules(nsName string, localPort, redirectPort int) error {
	// Clean up nftables if applicable
	err := runCommand(nsName, "nft", "--version")
	if err == nil {
		_ = runCommand(nsName, "nft", "delete", "table", "ip", "nat")
	}

	// Clean up iptables rules
	_ = runCommand(nsName, "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", fmt.Sprintf("%d", localPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort))
	_ = runCommand(nsName, "iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-o", "lo", "--dport", fmt.Sprintf("%d", localPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort))

	return nil
}

// WormholeForwarder proxies connections between a target namespace/address and a target host/proxy dialer.
type WormholeForwarder struct {
	nsName      string
	listenAddr  string
	targetAddr  string
	listener    net.Listener
	conns       map[net.Conn]struct{}
	connsMu     sync.Mutex
	running     bool
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewWormholeForwarder creates a new WormholeForwarder instance.
func NewWormholeForwarder(nsName, listenAddr, targetAddr string) *WormholeForwarder {
	return &WormholeForwarder{
		nsName:     nsName,
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		conns:      make(map[net.Conn]struct{}),
	}
}

// Start launches the forwarder listener loop.
func (w *WormholeForwarder) Start(ctx context.Context) error {
	w.connsMu.Lock()
	if w.running {
		w.connsMu.Unlock()
		return nil
	}

	w.ctx, w.cancel = context.WithCancel(ctx)
	w.running = true
	w.connsMu.Unlock()

	var listener net.Listener
	var err error

	if w.nsName != "" {
		err = ExecuteInNamespace(w.nsName, func() error {
			var err error
			listener, err = net.Listen("tcp", w.listenAddr)
			return err
		})
	} else {
		listener, err = net.Listen("tcp", w.listenAddr)
	}

	if err != nil {
		w.running = false
		return fmt.Errorf("failed to listen on %q: %w", w.listenAddr, err)
	}
	w.listener = listener

	go w.acceptLoop()

	return nil
}

func (w *WormholeForwarder) acceptLoop() {
	defer w.listener.Close()

	for {
		conn, err := w.listener.Accept()
		if err != nil {
			w.connsMu.Lock()
			running := w.running
			w.connsMu.Unlock()
			if !running {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		w.connsMu.Lock()
		w.conns[conn] = struct{}{}
		w.connsMu.Unlock()

		go w.handleConnection(conn)
	}
}

func (w *WormholeForwarder) handleConnection(inConn net.Conn) {
	defer func() {
		inConn.Close()
		w.connsMu.Lock()
		delete(w.conns, inConn)
		w.connsMu.Unlock()
	}()

	outConn, err := net.DialTimeout("tcp", w.targetAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer outConn.Close()

	w.connsMu.Lock()
	w.conns[outConn] = struct{}{}
	w.connsMu.Unlock()
	defer func() {
		w.connsMu.Lock()
		delete(w.conns, outConn)
		w.connsMu.Unlock()
	}()

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(inConn, outConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(outConn, inConn)
		errChan <- err
	}()

	select {
	case <-w.ctx.Done():
	case <-errChan:
	}
}

// Stop closes the listener and aborts all active forwarder proxy connections.
func (w *WormholeForwarder) Stop() error {
	w.connsMu.Lock()
	if !w.running {
		w.connsMu.Unlock()
		return nil
	}
	w.running = false
	if w.cancel != nil {
		w.cancel()
	}
	if w.listener != nil {
		w.listener.Close()
	}
	for conn := range w.conns {
		conn.Close()
	}
	w.conns = make(map[net.Conn]struct{})
	w.connsMu.Unlock()
	return nil
}
