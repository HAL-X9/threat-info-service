package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/config"
)

func writeCertificate(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal the key: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	write := func(path, blockType string, data []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data}), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(certFile, "CERTIFICATE", der)
	write(keyFile, "EC PRIVATE KEY", keyDER)

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the certificate: %v", err)
	}

	pool = x509.NewCertPool()
	pool.AddCert(cert)

	return certFile, keyFile, pool
}

func tlsConfig(addr, certFile, keyFile string) config.HTTPServer {
	cfg := httpConfig(addr)
	cfg.TLS = config.TLS{CertFile: certFile, KeyFile: keyFile}

	return cfg
}

func TestServesHTTPSWhenACertificateIsConfigured(t *testing.T) {
	certFile, keyFile, pool := writeCertificate(t)
	addr := freeAddr(t)

	var logs bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- newServerWith(t, tlsConfig(addr, certFile, keyFile), &logs).Run(ctx) }()

	secure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, DisableKeepAlives: true}}
	deadline := time.Now().Add(3 * time.Second)

	for {
		resp, err := secure.Get("https://" + addr)
		if err == nil {
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK || resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
				t.Fatalf("status = %d, tls = %+v, want 200 over TLS 1.2 or later", resp.StatusCode, resp.TLS)
			}

			break
		}

		if time.Now().After(deadline) {
			t.Fatalf("the server did not answer over TLS: %v", err)
		}

		time.Sleep(10 * time.Millisecond)
	}

	plain := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	if resp, err := plain.Get("http://" + addr); err == nil {
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("the TLS port answered a plain HTTP request with 200")
		}
	}

	old := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS11},
		DisableKeepAlives: true,
	}}
	if resp, err := old.Get("https://" + addr); err == nil {
		_ = resp.Body.Close()
		t.Error("the server accepted a TLS 1.1 handshake")
	}

	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run = %v, want nil after a requested shutdown", err)
	}

	if !strings.Contains(logs.String(), `"tls":true`) {
		t.Errorf("the ready message does not report TLS: %s", logs.String())
	}
}

func TestPlainHTTPWhenNoCertificateIsConfigured(t *testing.T) {
	var logs bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := freeAddr(t)
	done := make(chan error, 1)

	go func() { done <- newServer(t, addr, &logs).Run(ctx) }()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	deadline := time.Now().Add(3 * time.Second)

	for {
		if resp, err := client.Get("http://" + addr); err == nil {
			_ = resp.Body.Close()

			break
		}

		if time.Now().After(deadline) {
			t.Fatal("the server did not start")
		}

		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	if !strings.Contains(logs.String(), `"tls":false`) {
		t.Errorf("the ready message does not report that TLS is off: %s", logs.String())
	}
}

func TestNewRejectsAnUnusableCertificate(t *testing.T) {
	certFile, keyFile, _ := writeCertificate(t)
	garbage := filepath.Join(t.TempDir(), "garbage.pem")

	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	tests := map[string][2]string{
		"missing files":       {"/nonexistent/cert.pem", "/nonexistent/key.pem"},
		"garbage certificate": {garbage, keyFile},
		"garbage key":         {certFile, garbage},
	}

	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

			srv, err := New(tlsConfig("127.0.0.1:0", files[0], files[1]), handler, slog.New(slog.NewJSONHandler(io.Discard, nil)))
			if err == nil || srv != nil {
				t.Fatalf("New = %v, %v, want an error and no server", srv, err)
			}
		})
	}
}
