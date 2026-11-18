// Disposable OpenWrt VM-only synthetic AmneziaWG interoperability probe.
// The peer uses the same pinned AmneziaWG implementation as Mihomo and the
// upstream WireGuard userspace netstack; no kernel tunnel is created.
package main

import (
	"bufio"
	"crypto/ecdh"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	awg "github.com/metacubex/amneziawg-go/device"
	"github.com/metacubex/wireguard-go/conn"
	devlog "github.com/metacubex/wireguard-go/device"
	mtun "github.com/metacubex/wireguard-go/tun"
	wtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const payload = "xkeenwrt-awg-echo-v1"

func marked() bool {
	if syscall.Geteuid() != 0 {
		return false
	}
	info, err := os.Lstat("/etc/xkeenwrt-isolation-lab")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return false
	}
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return false
	}
	var version []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		version = append(version, byte(c))
	}
	if string(version) != "6.12.112" {
		return false
	}
	marker, e := os.ReadFile("/etc/xkeenwrt-isolation-lab")
	if e != nil || string(marker) != "xkeenwrt-validator-lab-v1\n" {
		return false
	}
	boot, e := os.ReadFile("/proc/cmdline")
	if e != nil {
		return false
	}
	yes := false
	for _, x := range strings.Fields(string(boot)) {
		if x == "xkeenwrt.isolation_lab=1" {
			yes = true
		}
	}
	if !yes {
		return false
	}
	release, e := os.ReadFile("/etc/openwrt_release")
	if e != nil || !strings.Contains(string(release), "DISTRIB_RELEASE='25.12.6'\n") {
		return false
	}
	entries, e := os.ReadDir("/sys/class/net")
	return e == nil && len(entries) == 1 && entries[0].Name() == "lo"
}
func key(fill byte) (*ecdh.PrivateKey, error) {
	p := make([]byte, 32)
	for i := range p {
		p[i] = fill
	}
	return ecdh.X25519().NewPrivateKey(p)
}

//go:embed imported-proxies.yaml
var importedProxies string

func configuration() error {
	client, e := key(1)
	if e != nil {
		return e
	}
	server, e := key(2)
	if e != nil {
		return e
	}
	// Refuse a stale imported fixture if either synthetic key is changed.
	if !strings.Contains(importedProxies, base64.StdEncoding.EncodeToString(client.Bytes())) ||
		!strings.Contains(importedProxies, base64.StdEncoding.EncodeToString(server.PublicKey().Bytes())) {
		return errors.New("fixture mismatch")
	}
	fmt.Printf("mixed-port: 7890\nbind-address: 127.0.0.1\nallow-lan: false\nmode: rule\nlog-level: error\ndns:\n  enable: false\nproxies:\n%srules:\n  - MATCH,awg-v3\n", importedProxies)
	return nil
}

type adapter struct {
	wtun.Device
	events chan mtun.Event
}

func (a *adapter) Events() <-chan mtun.Event { return a.events }
func wrap(d wtun.Device) *adapter {
	a := &adapter{Device: d, events: make(chan mtun.Event, 8)}
	go func() {
		defer close(a.events)
		for e := range d.Events() {
			a.events <- mtun.Event(e)
		}
	}()
	return a
}
func peer() error {
	server, e := key(2)
	if e != nil {
		return e
	}
	client, e := key(1)
	if e != nil {
		return e
	}
	tun, stack, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.99.0.1")}, nil, 1280)
	if e != nil {
		return e
	}
	logger := &devlog.Logger{Verbosef: func(string, ...interface{}) {}, Errorf: func(string, ...interface{}) {}}
	d := awg.NewDevice(wrap(tun), conn.NewStdNetBind(), logger, 1)
	defer d.Close()
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=51822\njc=4\njmin=40\njmax=70\nheader_protection_key=0000000000000000000000000000000000000000000000000000000000000000\npublic_key=%s\nallowed_ip=10.99.0.2/32\n", hex.EncodeToString(server.Bytes()), hex.EncodeToString(client.PublicKey().Bytes()))
	if e = d.IpcSet(ipc); e != nil {
		return errors.New("ipc setup")
	}
	if e = d.Up(); e != nil {
		return errors.New("peer up")
	}
	listener, e := stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.99.0.1:8080"))
	if e != nil {
		return e
	}
	defer listener.Close()
	fmt.Println("AWG_PEER_READY")
	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptedConn := make(chan accepted, 1)
	go func() { c, err := listener.Accept(); acceptedConn <- accepted{c, err} }()
	var c net.Conn
	select {
	case result := <-acceptedConn:
		if result.err != nil {
			return result.err
		}
		c = result.conn
	case <-time.After(25 * time.Second):
		return errors.New("accept timeout")
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	got, e := bufio.NewReader(c).ReadString('\n')
	if e != nil || got != payload+"\n" {
		return errors.New("payload mismatch")
	}
	if _, e = io.WriteString(c, payload+"\n"); e != nil {
		return e
	}
	ack, e := bufio.NewReader(c).ReadString('\n')
	if e != nil || ack != "ACK\n" {
		return errors.New("ack mismatch")
	}
	info, e := d.IpcGet()
	if e != nil {
		return errors.New("peer status")
	}
	var handshake, rx, tx bool
	for _, line := range strings.Split(info, "\n") {
		switch {
		case strings.HasPrefix(line, "last_handshake_time_sec="):
			handshake = line != "last_handshake_time_sec=0"
		case strings.HasPrefix(line, "rx_bytes="):
			rx = line != "rx_bytes=0"
		case strings.HasPrefix(line, "tx_bytes="):
			tx = line != "tx_bytes=0"
		}
	}
	if !handshake || !rx || !tx {
		return errors.New("missing handshake evidence")
	}
	fmt.Println("AWG_HANDSHAKE_AND_DATA_PASS")
	return nil
}

var clientStage = "DIAL"

func client() error {
	c, e := net.DialTimeout("tcp", "127.0.0.1:7890", 5*time.Second)
	if e != nil {
		switch {
		case errors.Is(e, syscall.ECONNREFUSED):
			clientStage = "DIAL_REFUSED"
		case errors.Is(e, syscall.EACCES):
			clientStage = "DIAL_DENIED"
		case errors.Is(e, syscall.ENETUNREACH):
			clientStage = "DIAL_UNREACHABLE"
		default:
			clientStage = "DIAL_OTHER"
		}
		return e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	clientStage = "GREETING"
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		return e
	}
	reply := make([]byte, 2)
	if _, e = io.ReadFull(c, reply); e != nil || reply[0] != 5 || reply[1] != 0 {
		return errors.New("socks greeting")
	}
	clientStage = "CONNECT"
	if _, e = c.Write([]byte{5, 1, 0, 1, 10, 99, 0, 1, 0x1f, 0x90}); e != nil {
		return e
	}
	header := make([]byte, 4)
	if _, e = io.ReadFull(c, header); e != nil || header[0] != 5 || header[1] != 0 {
		return errors.New("socks connect")
	}
	clientStage = "ADDRESS"
	n := 0
	switch header[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var b [1]byte
		if _, e = io.ReadFull(c, b[:]); e != nil {
			return e
		}
		n = int(b[0])
	default:
		return errors.New("socks address")
	}
	if _, e = io.CopyN(io.Discard, c, int64(n+2)); e != nil {
		return e
	}
	clientStage = "WRITE"
	if _, e = io.WriteString(c, payload+"\n"); e != nil {
		return e
	}
	clientStage = "ECHO"
	got, e := bufio.NewReader(c).ReadString('\n')
	if e != nil || got != payload+"\n" {
		return errors.New("echo mismatch")
	}
	clientStage = "ACK"
	if _, e = io.WriteString(c, "ACK\n"); e != nil {
		return e
	}
	fmt.Println("AWG_DATA_PASS")
	return nil
}
func main() {
	if !marked() {
		fmt.Fprintln(os.Stderr, "AWG_UNAVAILABLE")
		os.Exit(1)
	}
	if len(os.Args) != 2 {
		os.Exit(1)
	}
	var e error
	switch os.Args[1] {
	case "config":
		e = configuration()
	case "peer":
		e = peer()
	case "client":
		e = client()
	default:
		e = errors.New("mode")
	}
	if e != nil {
		if os.Args[1] == "client" {
			fmt.Fprintln(os.Stderr, "AWG_FAILED_"+clientStage)
		} else {
			fmt.Fprintln(os.Stderr, "AWG_FAILED")
		}
		os.Exit(1)
	}
}
