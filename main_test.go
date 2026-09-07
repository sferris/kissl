package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testApp(t *testing.T) (*Store, *httptest.Server) {
	t.Helper()
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(NewApp(s, "admin-secret", false))
	t.Cleanup(ts.Close)
	return s, ts
}

func request(t *testing.T, method, url, token, body string) (*http.Response, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func register(t *testing.T, base, name string) (string, string) {
	t.Helper()
	resp, b := request(t, http.MethodPost, base+"/api/v1/register", "", `{"name":"`+name+`"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status %d: %s", resp.StatusCode, b)
	}
	var v struct {
		ServerID string `json:"server_id"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v.ServerID, v.Token
}

func csrPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node.lab"}, DNSNames: []string{"node.lab", "alias.lab"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.7")}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestOpenSSLConfigIsPublicAndContainsDefaults(t *testing.T) {
	_, ts := testApp(t)
	resp, b := request(t, http.MethodGet, ts.URL+"/api/v1/openssl.cnf", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("OpenSSL config status = %d: %s", resp.StatusCode, b)
	}
	for _, expected := range []string{
		"countryName            = US",
		"stateOrProvinceName    = Colorado",
		"localityName           = Windsor",
		"organizationName       = WTFerris Net",
		"organizationalUnitName = IT Department",
		"POST https://KISSL_HOST/api/v1/register",
		"Authorization: Bearer TOKEN_FROM_REGISTRATION",
	} {
		if !bytes.Contains(b, []byte(expected)) {
			t.Errorf("OpenSSL config missing %q", expected)
		}
	}
	if disposition := resp.Header.Get("Content-Disposition"); !strings.Contains(disposition, "openssl.cnf") {
		t.Errorf("Content-Disposition = %q", disposition)
	}
}

func TestRegistrationDisabledAndTokenHashed(t *testing.T) {
	s, ts := testApp(t)
	id, token := register(t, ts.URL, "node-1")
	resp, _ := request(t, http.MethodGet, ts.URL+"/api/v1/server", token, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled credential status = %d, want 403", resp.StatusCode)
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(token)) {
		t.Fatal("auth file contains plaintext token")
	}
	if err := s.SetCredential(id, true, false); err != nil {
		t.Fatal(err)
	}
	resp, b = request(t, http.MethodGet, ts.URL+"/api/v1/server", token, "")
	if resp.StatusCode != http.StatusOK || !bytes.Contains(b, []byte(id)) {
		t.Fatalf("enabled status = %d: %s", resp.StatusCode, b)
	}
	if err := s.SetCredential(id, false, true); err != nil {
		t.Fatal(err)
	}
	resp, _ = request(t, http.MethodGet, ts.URL+"/api/v1/server", token, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked credential status = %d, want 401", resp.StatusCode)
	}
}

func TestDuplicateServerRegistrationIsRejected(t *testing.T) {
	_, ts := testApp(t)
	register(t, ts.URL, "Web-01")
	resp, b := request(t, http.MethodPost, ts.URL+"/api/v1/register", "", `{"name":" web-01 "}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate registration status = %d, want 409: %s", resp.StatusCode, b)
	}
}

func TestIssuePreservesSANsAndTokenIsScoped(t *testing.T) {
	s, ts := testApp(t)
	ca, err := s.CreateCA("Test Lab", 730, 365)
	if err != nil {
		t.Fatal(err)
	}
	id, token := register(t, ts.URL, "node-1")
	otherID, otherToken := register(t, ts.URL, "node-2")
	if err := s.SetCredential(id, true, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCredential(otherID, true, false); err != nil {
		t.Fatal(err)
	}
	resp, b := request(t, http.MethodPost, ts.URL+"/api/v1/ca/"+ca.ID+"/server/certificate?valid=30", token, csrPEM(t))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("issue status %d: %s", resp.StatusCode, b)
	}
	resp, b = request(t, http.MethodGet, ts.URL+"/api/v1/server/certificate", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download status %d: %s", resp.StatusCode, b)
	}
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 2 || cert.DNSNames[1] != "alias.lab" || !cert.IPAddresses[0].Equal(net.ParseIP("10.0.0.7")) {
		t.Fatalf("SANs not preserved: DNS=%v IP=%v", cert.DNSNames, cert.IPAddresses)
	}
	resp, p7b := request(t, http.MethodGet, ts.URL+"/api/v1/server/certificate?format=p7b", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("P7B download status %d: %s", resp.StatusCode, p7b)
	}
	p7Block, _ := pem.Decode(p7b)
	if p7Block == nil || p7Block.Type != "PKCS7" {
		t.Fatalf("P7B response is not PEM PKCS7")
	}
	var contentInfo pkcs7ContentInfo
	if rest, err := asn1.Unmarshal(p7Block.Bytes, &contentInfo); err != nil || len(rest) != 0 {
		t.Fatalf("decode PKCS7 content info: rest=%d err=%v", len(rest), err)
	}
	var signedData pkcs7SignedData
	if rest, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil || len(rest) != 0 {
		t.Fatalf("decode PKCS7 signed data: rest=%d err=%v", len(rest), err)
	}
	chain, err := x509.ParseCertificates(signedData.Certificates.Bytes)
	if err != nil || len(chain) != 3 {
		t.Fatalf("P7B chain has %d certificates, want 3: %v", len(chain), err)
	}

	resp, _ = request(t, http.MethodGet, ts.URL+"/api/v1/server/certificate", otherToken, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("other server downloaded certificate: status %d", resp.StatusCode)
	}
}

func TestAdminCreatesServerCertificateInOneRequest(t *testing.T) {
	s, ts := testApp(t)
	ca, err := s.CreateCA("Test Lab", 730, 365)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"name":          "web-01",
		"ca_id":         ca.ID,
		"csr_pem":       csrPEM(t),
		"validity_days": 30,
	})
	resp, b := request(t, http.MethodPost, ts.URL+"/admin/server/certificate", "admin-secret", string(payload))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create server certificate status %d: %s", resp.StatusCode, b)
	}
	var result struct {
		Server ServerMeta `json:"server"`
		Token  string     `json:"token"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	if result.Token == "" || result.Server.NotAfter == nil {
		t.Fatalf("missing token or certificate metadata: %+v", result)
	}
	credentials, err := s.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 || credentials[0].Enabled {
		t.Fatalf("credential should exist and be disabled: %+v", credentials)
	}

	payload, _ = json.Marshal(map[string]any{
		"name": "broken", "ca_id": ca.ID, "csr_pem": "invalid", "validity_days": 30,
	})
	resp, _ = request(t, http.MethodPost, ts.URL+"/admin/server/certificate", "admin-secret", string(payload))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid CSR status = %d", resp.StatusCode)
	}
	servers, err := s.ListServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("failed issuance left an orphan server: %+v", servers)
	}
}

func TestInvalidCSRAndAdminProtection(t *testing.T) {
	s, ts := testApp(t)
	ca, err := s.CreateCA("Test Lab", 730, 365)
	if err != nil {
		t.Fatal(err)
	}
	id, token := register(t, ts.URL, "node")
	if err := s.SetCredential(id, true, false); err != nil {
		t.Fatal(err)
	}
	resp, _ := request(t, http.MethodPost, ts.URL+"/api/v1/ca/"+ca.ID+"/server/certificate?valid=30", token, "not a csr")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid CSR status = %d", resp.StatusCode)
	}
	resp, _ = request(t, http.MethodGet, ts.URL+"/admin/state", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated admin status = %d", resp.StatusCode)
	}
	resp, _ = request(t, http.MethodGet, ts.URL+"/admin/state", "admin-secret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin bearer status = %d", resp.StatusCode)
	}
}
