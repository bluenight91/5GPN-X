// client-mtproto.go - TCP ACL front for a loopback mtg (MTProto) instance.
// Private NPN clients only; pairs with host firewall allow rules.
//
// Build: go build -ldflags="-s -w" -o client-mtproto client-mtproto.go
// Run:   ./client-mtproto -l 0.0.0.0:5753 -b 127.0.0.1:15753 -a 172.22.0.0/16
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var (
	listenAddr  = flag.String("l", "0.0.0.0:5753", "public listen address")
	backendAddr = flag.String("b", "127.0.0.1:15753", "loopback mtg address")
	allowCIDR   = flag.String("a", "172.22.0.0/16", "comma-separated allowed client CIDRs")
	quiet       = flag.Bool("q", false, "quiet logging")
)

func main() {
	flag.Parse()
	nets, err := parseCIDRs(*allowCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client-mtproto: bad -a: %v\n", err)
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if !*quiet {
		log.Printf("MTProto ACL front on %s → %s (ACL %s)", *listenAddr, *backendAddr, *allowCIDR)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, nets)
	}
}

func parseCIDRs(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty ACL")
	}
	return out, nil
}

func allowed(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func handle(c net.Conn, nets []*net.IPNet) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil || !allowed(net.ParseIP(host), nets) {
		return
	}
	up, err := net.DialTimeout("tcp", *backendAddr, 8*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(2 * time.Minute))
	// Clear deadlines for long-lived Telegram sessions after connect.
	_ = c.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	errc := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); errc <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); errc <- struct{}{} }()
	<-errc
}
