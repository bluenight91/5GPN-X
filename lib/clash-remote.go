// clash-remote.go - HTTPS reverse proxy for mihomo Clash API with CIDR ACL
// and a dedicated remote secret. Terminates TLS, validates the remote secret,
// then injects the loopback Clash secret when forwarding to 127.0.0.1:9090.
//
// Third-party panels (Neko Dash / Sphere / Sparxie) connect to:
//   https://<domain>:<port>/   secret = CLASH_REMOTE_SECRET
// Path stays at Clash API root (/configs, /proxies, /traffic, …).
//
// Build: go build -ldflags="-s -w" -o clash-remote clash-remote.go
package main

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	listenAddr   = flag.String("l", "0.0.0.0:9443", "TLS listen address")
	backend      = flag.String("b", "127.0.0.1:9090", "loopback Clash API address")
	remoteSecret = flag.String("s", "", "remote panel secret (required)")
	clashSecret  = flag.String("S", "", "upstream Clash secret (or -f)")
	secretFile   = flag.String("f", "", "file containing upstream Clash secret")
	allowCIDR    = flag.String("a", "172.22.0.0/16", "comma-separated allowed client CIDRs")
	certFile     = flag.String("cert", "/etc/mosdns/certs/fullchain.pem", "TLS certificate")
	keyFile      = flag.String("key", "/etc/mosdns/certs/privkey.pem", "TLS private key")
	quiet        = flag.Bool("q", false, "quiet logging")
)

func main() {
	flag.Parse()
	if *remoteSecret == "" {
		fmt.Fprintln(os.Stderr, "clash-remote: -s (remote secret) is required")
		os.Exit(2)
	}
	upSecret := strings.TrimSpace(*clashSecret)
	if upSecret == "" && *secretFile != "" {
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "clash-remote: read secret file: %v\n", err)
			os.Exit(2)
		}
		upSecret = strings.TrimSpace(string(b))
	}
	if upSecret == "" {
		fmt.Fprintln(os.Stderr, "clash-remote: upstream Clash secret required (-S or -f)")
		os.Exit(2)
	}
	nets, err := parseCIDRs(*allowCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clash-remote: bad -a: %v\n", err)
		os.Exit(2)
	}
	target, err := url.Parse("http://" + *backend)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clash-remote: bad -b: %v\n", err)
		os.Exit(2)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = 50 * time.Millisecond
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
		req.Header.Set("Authorization", "Bearer "+upSecret)
		// Strip client-facing auth so mihomo only sees the injected secret.
		req.Header.Del("X-Forwarded-For")
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		if !*quiet {
			log.Printf("upstream error %s: %v", r.URL.Path, e)
		}
		http.Error(w, `{"message":"mihomo unreachable"}`, http.StatusBadGateway)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !allowed(ip, nets) {
			if !*quiet {
				log.Printf("deny %v (ACL)", r.RemoteAddr)
			}
			http.Error(w, `{"message":"forbidden"}`, http.StatusForbidden)
			return
		}
		if !authOK(r, *remoteSecret) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="clash-remote"`)
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if isWebSocket(r) {
			wsRelay(w, r, *backend, upSecret)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load TLS cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if !*quiet {
		log.Printf("clash-remote HTTPS on %s → %s (ACL %s)", *listenAddr, *backend, *allowCIDR)
	}
	log.Fatal(srv.Serve(tlsLn))
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

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func ctEq(a, b string) bool {
	if len(a) != len(b) {
		_ = subtle.ConstantTimeCompare([]byte(a), []byte(a))
		_ = subtle.ConstantTimeCompare([]byte(b), []byte(b))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func authOK(r *http.Request, want string) bool {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") && ctEq(strings.TrimSpace(h[7:]), want) {
		return true
	}
	// Clash panels often pass token as query for WebSocket.
	if tok := r.URL.Query().Get("token"); tok != "" && ctEq(tok, want) {
		return true
	}
	return false
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func wsRelay(w http.ResponseWriter, r *http.Request, backend, upSecret string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, `{"message":"websocket unsupported"}`, http.StatusInternalServerError)
		return
	}
	client, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	up, err := net.DialTimeout("tcp", backend, 10*time.Second)
	if err != nil {
		_, _ = bufrw.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		_ = bufrw.Flush()
		return
	}
	defer up.Close()

	path := r.URL.RequestURI()
	// Strip client token from query before forwarding; auth is injected via header.
	if u, err := url.Parse(path); err == nil {
		q := u.Query()
		q.Del("token")
		u.RawQuery = q.Encode()
		path = u.RequestURI()
	}
	reqLines := []string{
		fmt.Sprintf("GET %s HTTP/1.1", path),
		"Host: " + backend,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: " + headerOr(r, "Sec-WebSocket-Version", "13"),
		"Sec-WebSocket-Key: " + r.Header.Get("Sec-WebSocket-Key"),
		"Authorization: Bearer " + upSecret,
	}
	if p := r.Header.Get("Sec-WebSocket-Protocol"); p != "" {
		reqLines = append(reqLines, "Sec-WebSocket-Protocol: "+p)
	}
	raw := strings.Join(reqLines, "\r\n") + "\r\n\r\n"
	if _, err := up.Write([]byte(raw)); err != nil {
		return
	}
	upBuf := bufio.NewReader(up)
	resp, err := http.ReadResponse(upBuf, r)
	if err != nil {
		return
	}
	if err := resp.Write(bufrw); err != nil {
		return
	}
	if err := bufrw.Flush(); err != nil {
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return
	}
	errc := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, bufrw)
		errc <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upBuf)
		errc <- struct{}{}
	}()
	<-errc
}

func headerOr(r *http.Request, k, def string) string {
	if v := r.Header.Get(k); v != "" {
		return v
	}
	return def
}
