package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNotifyReady(t *testing.T) {
	socket := t.TempDir() + "/notify.sock"
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", socket)

	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 32)
	n, _, err := listener.ReadFromUnix(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(payload[:n]); got != "READY=1" {
		t.Fatalf("notification = %q, want READY=1", got)
	}
}

func testProxy(t *testing.T, cidrs string) *proxy {
	t.Helper()
	nets, err := parseCIDRs(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return &proxy{
		nets: nets,
		user: "alice",
		pass: "secret",
		transport: &http.Transport{
			Proxy:       nil,
			DialContext: dialer.DialContext,
		},
		dial: dialer.DialContext,
	}
}

func authHeader(user, pass string) string {
	token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return "Basic " + token
}

func TestProxyBasicAuth(t *testing.T) {
	user, pass, ok := proxyBasicAuth(authHeader("alice", "s:ecret"))
	if !ok || user != "alice" || pass != "s:ecret" {
		t.Fatalf("unexpected auth result: %q %q %v", user, pass, ok)
	}
	if _, _, ok := proxyBasicAuth("Bearer token"); ok {
		t.Fatal("accepted non-Basic proxy authorization")
	}
}

func TestForwardRequiresACLAndAuthentication(t *testing.T) {
	p := testProxy(t, "172.22.0.0/16")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ACL response = %d, want 403", rec.Code)
	}

	req.RemoteAddr = "172.22.1.2:1234"
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("auth response = %d, want 407", rec.Code)
	}
	if rec.Header().Get("Proxy-Authenticate") == "" {
		t.Fatal("407 response omitted Proxy-Authenticate")
	}
}

func TestForwardHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Errorf("upstream received Proxy-Authorization: %q", got)
		}
		w.Header().Set("X-Upstream", "ok")
		_, _ = io.WriteString(w, r.Method+" "+r.URL.Path)
	}))
	defer backend.Close()

	p := testProxy(t, "172.22.0.0/16")
	req := httptest.NewRequest(http.MethodGet, backend.URL+"/hello", nil)
	req.RemoteAddr = "172.22.1.2:1234"
	req.Header.Set("Proxy-Authorization", authHeader("alice", "secret"))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("response = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Upstream"); got != "ok" {
		t.Fatalf("X-Upstream = %q", got)
	}
	if got := rec.Body.String(); got != "GET /hello" {
		t.Fatalf("body = %q", got)
	}
}

func TestConnectTunnel(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, acceptErr := echo.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	p := testProxy(t, "127.0.0.0/8")
	server := httptest.NewServer(p)
	defer server.Close()
	proxyAddr := strings.TrimPrefix(server.URL, "http://")
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(conn,
		"CONNECT "+echo.Addr().String()+" HTTP/1.1\r\n"+
			"Host: "+echo.Addr().String()+"\r\n"+
			"Proxy-Authorization: "+authHeader("alice", "secret")+"\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "ping" {
		t.Fatalf("tunnel payload = %q", payload)
	}
}

func TestDialReceivesRequestContext(t *testing.T) {
	p := testProxy(t, "127.0.0.0/8")
	called := false
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		called = ctx != nil && network == "tcp" && address == "example.com:443"
		return nil, context.DeadlineExceeded
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Proxy-Authorization", authHeader("alice", "secret"))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if !called {
		t.Fatal("CONNECT did not use configured context-aware dialer")
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("response = %d, want 502", rec.Code)
	}
}
