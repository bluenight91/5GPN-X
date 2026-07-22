// client-socks.go - Lightweight SOCKS5 server with user/pass auth and CIDR ACL.
// Pure Go stdlib. Intended for private NPN clients only (defense in depth
// alongside the host firewall).
//
// Build: go build -ldflags="-s -w" -o client-socks client-socks.go
// Run:   ./client-socks -l 0.0.0.0:38443 -u user -P pass -a 172.22.0.0/16
package main

import (
	"encoding/binary"
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
	listenAddr = flag.String("l", "0.0.0.0:38443", "listen address")
	username   = flag.String("u", "", "SOCKS5 username (required)")
	password   = flag.String("P", "", "SOCKS5 password (required)")
	allowCIDR  = flag.String("a", "172.22.0.0/16", "comma-separated allowed client CIDRs")
	quiet      = flag.Bool("q", false, "quiet logging")
)

func main() {
	flag.Parse()
	if *username == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "client-socks: -u and -P are required")
		os.Exit(2)
	}
	nets, err := parseCIDRs(*allowCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client-socks: bad -a: %v\n", err)
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if !*quiet {
		log.Printf("SOCKS5 listening on %s (ACL %s)", *listenAddr, *allowCIDR)
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
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	raddr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok || !allowed(raddr.IP, nets) {
		if !*quiet {
			log.Printf("deny %v (ACL)", c.RemoteAddr())
		}
		return
	}

	buf := make([]byte, 512)
	n, err := io.ReadAtLeast(c, buf, 2)
	if err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	need := 2 + nmethods
	if n < need {
		more, err := io.ReadFull(c, buf[n:need])
		if err != nil {
			return
		}
		n += more
	}
	methods := buf[2:need]
	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		_, _ = c.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
		return
	}

	// Username/password auth (RFC 1929)
	n, err = io.ReadAtLeast(c, buf, 2)
	if err != nil || buf[0] != 0x01 {
		return
	}
	ulen := int(buf[1])
	need = 2 + ulen + 1
	if n < need {
		if _, err := io.ReadFull(c, buf[n:need]); err != nil {
			return
		}
		n = need
	}
	user := string(buf[2 : 2+ulen])
	plen := int(buf[2+ulen])
	need = 2 + ulen + 1 + plen
	if n < need {
		if _, err := io.ReadFull(c, buf[n:need]); err != nil {
			return
		}
	}
	pass := string(buf[2+ulen+1 : need])
	if user != *username || pass != *password {
		_, _ = c.Write([]byte{0x01, 0x01})
		if !*quiet {
			log.Printf("auth fail from %v", c.RemoteAddr())
		}
		return
	}
	if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
		return
	}

	// CONNECT request
	n, err = io.ReadAtLeast(c, buf, 4)
	if err != nil || buf[0] != 0x05 || buf[1] != 0x01 {
		reply(c, 0x07, nil)
		return
	}
	var host string
	var port uint16
	switch buf[3] {
	case 0x01: // IPv4
		need = 4 + 4 + 2
		if n < need {
			if _, err := io.ReadFull(c, buf[n:need]); err != nil {
				return
			}
		}
		host = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case 0x03: // domain
		if n < 5 {
			if _, err := io.ReadFull(c, buf[n:5]); err != nil {
				return
			}
			n = 5
		}
		dlen := int(buf[4])
		need = 5 + dlen + 2
		if n < need {
			if _, err := io.ReadFull(c, buf[n:need]); err != nil {
				return
			}
		}
		host = string(buf[5 : 5+dlen])
		port = binary.BigEndian.Uint16(buf[5+dlen : 5+dlen+2])
	case 0x04: // IPv6
		need = 4 + 16 + 2
		if n < need {
			if _, err := io.ReadFull(c, buf[n:need]); err != nil {
				return
			}
		}
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
	default:
		reply(c, 0x08, nil)
		return
	}

	_ = c.SetDeadline(time.Time{}) // clear handshake deadline
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	up, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		reply(c, 0x05, nil)
		if !*quiet {
			log.Printf("dial %s fail: %v", target, err)
		}
		return
	}
	defer up.Close()
	reply(c, 0x00, up.LocalAddr())
	if !*quiet {
		log.Printf("%v -> %s", c.RemoteAddr(), target)
	}
	errc := make(chan struct{}, 2)
	go proxyCopy(up, c, errc)
	go proxyCopy(c, up, errc)
	<-errc
}

func proxyCopy(dst, src net.Conn, done chan struct{}) {
	_, _ = io.Copy(dst, src)
	done <- struct{}{}
}

func reply(c net.Conn, rep byte, bind net.Addr) {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	resp := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if ta, ok := bind.(*net.TCPAddr); ok && ta.IP != nil {
		if ip4 := ta.IP.To4(); ip4 != nil {
			copy(resp[4:8], ip4)
			binary.BigEndian.PutUint16(resp[8:10], uint16(ta.Port))
		}
	}
	_, _ = c.Write(resp)
}
