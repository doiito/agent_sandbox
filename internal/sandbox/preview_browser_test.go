package sandbox

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreviewChromiumCookieOriginWebSocketAndRevoke(t *testing.T) {
	probeContext, stopProbe := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopProbe()
	probe := exec.CommandContext(probeContext, "python3", "../../scripts/test-preview-browser.py", "--probe")
	metadata, err := probe.Output()
	if err != nil {
		t.Skip("browser validation requires provisioned Playwright")
	}
	var runtime struct {
		Available bool `json:"available"`
	}
	if json.Unmarshal(metadata, &runtime) != nil || !runtime.Available {
		t.Skip("browser validation requires matching provisioned Chromium")
	}
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			conn, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			accept := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(accept[:]) + "\r\n\r\n")
			if buffered.Flush() != nil {
				return
			}
			for {
				data, err := readBrowserWSMessage(buffered.Reader, conn)
				if err != nil {
					return
				}
				if writePortBytes(conn, testWSFrame(data, false)) != nil {
					return
				}
			}
		}
		if r.URL.Path == "/echo" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"authorization": r.Header.Get("Authorization"), "cookie": r.Header.Get("Cookie")})
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Add("Set-Cookie", "app=alive; Path=/")
		w.Header().Add("Set-Cookie", "wide=invalid; Domain=preview.test; Path=/")
		w.Header().Add("Set-Cookie", previewCookie+"=invalid; Secure; Path=/")
		_, _ = w.Write([]byte("<!doctype html><html><body>preview browser fixture</body></html>"))
	}))
	// The regular Go fixture overrides dialing. A real browser needs its URL
	// port to be the actual disposable listener; no production source changes.
	_, port, _ := net.SplitHostPort(f.front.Listener.Addr().String())
	base, _ := url.Parse("https://preview.test:" + port)
	f.service.base = base
	first := f.create(t, strings.Repeat("1", 24), 60000)
	second := f.create(t, strings.Repeat("2", 24), 60000)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certificate := f.api.tls.Certificates[0]
	previewLeaf, err := x509.ParseCertificate(f.front.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(previewLeaf.RawSubjectPublicKeyInfo)
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"api": f.api.server.URL, "grants": []PreviewGrantInfo{first, second}, "preview_spki": base64.StdEncoding.EncodeToString(pin[:]), "direct_app": fmt.Sprintf("http://127.0.0.1:%d/", f.port),
		"ca":   write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[1]})),
		"cert": write("client.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})),
		"key":  write("client.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}
	data, _ := json.Marshal(config)
	path := write("browser.json", data)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "../../scripts/test-preview-browser.py", path)
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		f.service.mu.Lock()
		for _, g := range f.service.grants {
			t.Log("browser fixture state", g.info.ID, g.authorized, len(g.requests), len(g.connections))
		}
		f.service.mu.Unlock()
		t.Log("guest opens", f.guest.opens.Load())
		t.Fatalf("real browser fixture: %v", err)
	}
	if strings.Count(string(output), "PASS ") != 6 {
		t.Fatal("not all browser checks ran")
	}
}

// Browsers may fragment a single send() across frames and interleave controls.
// This is only the disposable application, never the preview proxy parser.
func readBrowserWSMessage(reader io.Reader, writer io.Writer) ([]byte, error) {
	var message []byte
	started := false
	for {
		var header [2]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return nil, err
		}
		op := header[0] & 15
		final := header[0]&128 != 0
		size := uint64(header[1] & 127)
		if header[0]&0x70 != 0 || header[1]&128 == 0 {
			return nil, fmt.Errorf("invalid browser fixture frame")
		}
		if size == 126 {
			var value [2]byte
			if _, err := io.ReadFull(reader, value[:]); err != nil {
				return nil, err
			}
			size = uint64(binary.BigEndian.Uint16(value[:]))
		} else if size == 127 {
			var value [8]byte
			if _, err := io.ReadFull(reader, value[:]); err != nil {
				return nil, err
			}
			size = binary.BigEndian.Uint64(value[:])
		}
		if size > 1<<20 || uint64(len(message))+size > 1<<20 {
			return nil, fmt.Errorf("fixture message too large")
		}
		var mask [4]byte
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return nil, err
		}
		data := make([]byte, int(size))
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}
		for i := range data {
			data[i] ^= mask[i%4]
		}
		switch op {
		case 8:
			frame := testWSFrame(data, false)
			frame[0] = 0x88
			_ = writePortBytes(writer, frame)
			return nil, io.EOF
		case 9:
			if !final || len(data) > 125 {
				return nil, fmt.Errorf("invalid control frame")
			}
			frame := testWSFrame(data, false)
			frame[0] = 0x8a
			if err := writePortBytes(writer, frame); err != nil {
				return nil, err
			}
			continue
		case 10:
			continue
		case 2:
			if started {
				return nil, fmt.Errorf("unexpected binary frame")
			}
			started = true
		case 0:
			if !started {
				return nil, fmt.Errorf("unexpected continuation")
			}
		default:
			return nil, fmt.Errorf("unexpected fixture opcode")
		}
		message = append(message, data...)
		if final {
			return message, nil
		}
	}
}
