package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, nil
}
func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func pemECKey(k *ecdsa.PrivateKey) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}

func (s *Store) CreateCA(name string, rootDays, issuingDays int) (CAMeta, error) {
	if err := cleanName(name); err != nil {
		return CAMeta{}, err
	}
	if rootDays < 365 || rootDays > 7300 {
		return CAMeta{}, errors.New("root validity must be 365-7300 days")
	}
	if issuingDays < 30 || issuingDays > 3650 || issuingDays >= rootDays {
		return CAMeta{}, errors.New("issuing validity must be 30-3650 days and less than root validity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, e := randomHex(16)
	if e != nil {
		return CAMeta{}, e
	}
	d, _ := s.caDir(id)
	if e = os.Mkdir(d, 0700); e != nil {
		return CAMeta{}, e
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(d)
		}
	}()
	now := time.Now().UTC()
	rootKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return CAMeta{}, e
	}
	rootSerial, e := serial()
	if e != nil {
		return CAMeta{}, e
	}
	root := &x509.Certificate{SerialNumber: rootSerial, Subject: pkix.Name{CommonName: name + " Root CA", Organization: []string{name}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, rootDays), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if e != nil {
		return CAMeta{}, e
	}
	issKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return CAMeta{}, e
	}
	issSerial, e := serial()
	if e != nil {
		return CAMeta{}, e
	}
	iss := &x509.Certificate{SerialNumber: issSerial, Subject: pkix.Name{CommonName: name + " Issuing CA", Organization: []string{name}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, issuingDays), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	issDER, e := x509.CreateCertificate(rand.Reader, iss, root, &issKey.PublicKey, rootKey)
	if e != nil {
		return CAMeta{}, e
	}
	rootKeyPEM, e := pemECKey(rootKey)
	if e != nil {
		return CAMeta{}, e
	}
	issKeyPEM, e := pemECKey(issKey)
	if e != nil {
		return CAMeta{}, e
	}
	m := CAMeta{ID: id, Name: name, CreatedAt: now, RootNotAfter: root.NotAfter, IssuingNotAfter: iss.NotAfter}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{{"root-cert.pem", pemCert(rootDER), 0644}, {"root-key.pem", rootKeyPEM, 0600}, {"issuing-cert.pem", pemCert(issDER), 0644}, {"issuing-key.pem", issKeyPEM, 0600}}
	for _, f := range files {
		if e = atomicWrite(filepath.Join(d, f.name), f.data, f.mode); e != nil {
			return CAMeta{}, e
		}
	}
	if e = atomicJSON(filepath.Join(d, "metadata.json"), m, 0600); e != nil {
		return CAMeta{}, e
	}
	ok = true
	return m, nil
}

func parseCert(path string) (*x509.Certificate, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p, _ := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(p.Bytes)
}
func parseKey(path string) (*ecdsa.PrivateKey, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("invalid key PEM")
	}
	k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, e
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not ECDSA")
	}
	return ec, nil
}
func parseCSR(data []byte) (*x509.CertificateRequest, error) {
	p, rest := pem.Decode(data)
	if p == nil || p.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("expected PEM CERTIFICATE REQUEST")
	}
	if len(rest) > 0 {
		return nil, errors.New("unexpected data after CSR")
	}
	csr, e := x509.ParseCertificateRequest(p.Bytes)
	if e != nil {
		return nil, fmt.Errorf("parse CSR: %w", e)
	}
	if e = csr.CheckSignature(); e != nil {
		return nil, errors.New("invalid CSR signature")
	}
	if csr.Subject.CommonName == "" && len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 && len(csr.URIs) == 0 {
		return nil, errors.New("CSR must contain a common name or SAN")
	}
	return csr, nil
}

func (s *Store) Issue(id, caID string, csrPEM []byte, days int) (ServerMeta, error) {
	if days < 1 || days > 825 {
		return ServerMeta{}, errors.New("validity must be 1-825 days")
	}
	csr, e := parseCSR(csrPEM)
	if e != nil {
		return ServerMeta{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, e := s.getServerLocked(id)
	if e != nil {
		return ServerMeta{}, e
	}
	caDir, e := s.caDir(caID)
	if e != nil {
		return ServerMeta{}, e
	}
	iss, e := parseCert(filepath.Join(caDir, "issuing-cert.pem"))
	if e != nil {
		return ServerMeta{}, e
	}
	key, e := parseKey(filepath.Join(caDir, "issuing-key.pem"))
	if e != nil {
		return ServerMeta{}, e
	}
	now := time.Now().UTC()
	notAfter := now.Add(time.Duration(days) * 24 * time.Hour)
	if notAfter.After(iss.NotAfter) {
		return ServerMeta{}, errors.New("requested validity exceeds issuing CA expiry")
	}
	sn, e := serial()
	if e != nil {
		return ServerMeta{}, e
	}
	tpl := &x509.Certificate{SerialNumber: sn, Subject: csr.Subject, NotBefore: now.Add(-5 * time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses, EmailAddresses: csr.EmailAddresses, URIs: cloneURLs(csr.URIs)}
	der, e := x509.CreateCertificate(rand.Reader, tpl, iss, csr.PublicKey, key)
	if e != nil {
		return ServerMeta{}, e
	}
	d, _ := s.serverDir(id)
	if e = atomicWrite(filepath.Join(d, "csr.pem"), csrPEM, 0600); e != nil {
		return ServerMeta{}, e
	}
	if e = atomicWrite(filepath.Join(d, "cert.pem"), pemCert(der), 0644); e != nil {
		return ServerMeta{}, e
	}
	m.CAID = caID
	m.IssuedAt = &now
	m.NotAfter = &notAfter
	m.SerialNumber = sn.Text(16)
	if e = atomicJSON(filepath.Join(d, "metadata.json"), m, 0600); e != nil {
		return ServerMeta{}, e
	}
	return m, nil
}
func cloneURLs(in []*url.URL) []*url.URL {
	out := make([]*url.URL, len(in))
	for i, u := range in {
		v := *u
		out[i] = &v
	}
	return out
}
func (s *Store) Renew(id string, days int) (ServerMeta, error) {
	m, e := s.GetServer(id)
	if e != nil {
		return ServerMeta{}, e
	}
	if m.CAID == "" {
		return ServerMeta{}, errors.New("no existing certificate")
	}
	d, e := s.serverDir(id)
	if e != nil {
		return ServerMeta{}, e
	}
	csr, e := os.ReadFile(filepath.Join(d, "csr.pem"))
	if e != nil {
		return ServerMeta{}, e
	}
	return s.Issue(id, m.CAID, csr, days)
}
