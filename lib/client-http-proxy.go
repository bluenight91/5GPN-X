// client-http-proxy.go - Authenticated HTTP/HTTPS forward proxy with CIDR ACL.
// Pure Go stdlib. Intended for private NPN clients only (defense in depth
// alongside the host firewall).
//
// Build: go build -ldflags="-s -w" -o client-http-proxy client-http-proxy.go
// Run:   ./client-http-proxy -l 0.0.0.0:38444 -u user -P pass -a 172.22.0.0/16
package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func agentDebugLog(hypothesisID, location, message string, data map[string]any) {
	entry := map[string]any{
		"hypothesisId": hypothesisID,
		"location":     location,
		"message":      message,
		"data":         data,
		"timestamp":    time.Now().UnixMilli(),
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return
	}
	file, err := os.OpenFile("/opt/cursor/logs/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write(append(payload, '\n'))
}

var (
	listenAddr = flag.String("l", "0.0.0.0:38444", "listen address")
	username   = flag.String("u", "", "proxy username (required)")
	password   = flag.String("P", "", "proxy password (required)")
	allowCIDR  = flag.String("a", "172.22.0.0/16", "comma-separated allowed client CIDRs")
	quiet      = flag.Bool("q", false, "quiet logging")
)

type proxy struct {
	nets      []*net.IPNet
	user      string
	pass      string
	transport *http.Transport
	dial      func(context.Context, string, string) (net.Conn, error)
}

func main() {
	flag.Parse()
	if *username == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "client-http-proxy: -u and -P are required")
		os.Exit(2)
	}
	nets, err := parseCIDRs(*allowCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client-http-proxy: bad -a: %v\n", err)
		os.Exit(2)
	}
	// #region agent log
	agentDebugLog("A,C,D", "lib/client-http-proxy.go:main", "proxy parsed startup arguments", map[string]any{
		"listenAddr": *listenAddr, "allowCIDR": *allowCIDR, "cidrCount": len(nets),
		"userLength": len(*username), "passLength": len(*password), "euid": os.Geteuid(),
	})
	// #endregion
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	p := &proxy{
		nets: nets,
		user: *username,
		pass: *password,
		transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          128,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
		dial: dialer.DialContext,
	}
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if !*quiet {
		log.Printf("HTTP proxy listening on %s (ACL %s)", *listenAddr, *allowCIDR)
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func parseCIDRs(value string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			return nil, err
		}
		out = append(out, network)
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
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		_ = subtle.ConstantTimeCompare([]byte(left), []byte(left))
		_ = subtle.ConstantTimeCompare([]byte(right), []byte(right))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func proxyBasicAuth(header string) (string, string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Basic") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", "", false
	}
	user, pass, ok := strings.Cut(string(decoded), ":")
	return user, pass, ok
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !allowed(net.ParseIP(host), p.nets) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	user, pass, ok := proxyBasicAuth(r.Header.Get("Proxy-Authorization"))
	if !ok || !constantTimeEqual(user, p.user) || !constantTimeEqual(pass, p.pass) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="5GPN-X private proxy"`)
		w.Header().Set("Connection", "close")
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	p.forward(w, r)
}

func (p *proxy) connect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		http.Error(w, "CONNECT target must include a port", http.StatusBadRequest)
		return
	}
	upstream, err := p.dial(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "tunneling unsupported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	if !*quiet {
		log.Printf("%s CONNECT %s", r.RemoteAddr, target)
	}
	relay(client, buffered.Reader, upstream)
}

func (p *proxy) forward(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || (r.URL.Scheme != "http" && r.URL.Scheme != "https") || r.URL.Host == "" {
		http.Error(w, "absolute http(s) URL required", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	removeHopHeaders(out.Header)
	out.Header.Del("Proxy-Authorization")
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	if !*quiet {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Redacted())
	}
}

func removeHopHeaders(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			header.Del(name)
		}
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func relay(client net.Conn, clientReader *bufio.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}
