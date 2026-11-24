package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
func pemKey(k crypto.Signer) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}

type CAOptions struct {
	Purpose            string
	Organization       string
	OrganizationalUnit string
}

func (s *Store) CreateCA(name string, rootDays, issuingDays int) (CAMeta, error) {
	return s.CreateCAWithOptions(name, rootDays, issuingDays, CAOptions{})
}

func (s *Store) CreateCAWithOptions(name string, rootDays, issuingDays int, opts CAOptions) (CAMeta, error) {
	if opts.Purpose != "" && opts.Purpose != "server" && opts.Purpose != "client" {
		return CAMeta{}, errors.New("purpose must be server or client")
	}
	if opts.Purpose == "client" {
		if opts.Organization == "" {
			opts.Organization = "WTFerris Net"
		}
		if opts.OrganizationalUnit == "" {
			opts.OrganizationalUnit = "IT Department"
		}
		if err := cleanName(opts.Organization); err != nil {
			return CAMeta{}, fmt.Errorf("organization: %w", err)
		}
		if err := cleanName(opts.OrganizationalUnit); err != nil {
			return CAMeta{}, fmt.Errorf("organizational unit: %w", err)
		}
	} else if opts.Organization != "" || opts.OrganizationalUnit != "" {
		return CAMeta{}, errors.New("organization and organizational unit require client purpose")
	}
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
	var rootKey crypto.Signer
	if opts.Purpose == "client" {
		rootKey, e = rsa.GenerateKey(rand.Reader, 3072)
	} else {
		rootKey, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if e != nil {
		return CAMeta{}, e
	}
	rootSerial, e := serial()
	if e != nil {
		return CAMeta{}, e
	}
	root := &x509.Certificate{SerialNumber: rootSerial, Subject: pkix.Name{CommonName: name + " Root CA", Organization: []string{name}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, rootDays), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	if opts.Purpose == "client" {
		root.Subject = pkix.Name{CommonName: name, Organization: []string{opts.Organization}, OrganizationalUnit: []string{opts.OrganizationalUnit}}
		root.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		root.SignatureAlgorithm = x509.SHA256WithRSA
	}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if e != nil {
		return CAMeta{}, e
	}
	var issKey crypto.Signer
	if opts.Purpose == "client" {
		issKey, e = rsa.GenerateKey(rand.Reader, 3072)
	} else {
		issKey, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if e != nil {
		return CAMeta{}, e
	}
	issSerial, e := serial()
	if e != nil {
		return CAMeta{}, e
	}
	iss := &x509.Certificate{SerialNumber: issSerial, Subject: pkix.Name{CommonName: name + " Issuing CA", Organization: []string{name}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, issuingDays), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	if opts.Purpose == "client" {
		iss.Subject = pkix.Name{CommonName: name + " Issuing CA", Organization: []string{opts.Organization}, OrganizationalUnit: []string{opts.OrganizationalUnit}}
		iss.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		iss.SignatureAlgorithm = x509.SHA256WithRSA
	}
	issDER, e := x509.CreateCertificate(rand.Reader, iss, root, issKey.Public(), rootKey)
	if e != nil {
		return CAMeta{}, e
	}
	rootKeyPEM, e := pemKey(rootKey)
	if e != nil {
		return CAMeta{}, e
	}
	issKeyPEM, e := pemKey(issKey)
	if e != nil {
		return CAMeta{}, e
	}
	m := CAMeta{ID: id, Name: name, CreatedAt: now, RootNotAfter: root.NotAfter, IssuingNotAfter: iss.NotAfter, Purpose: opts.Purpose}
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
func parseKey(path string) (crypto.Signer, error) {
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
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key cannot sign certificates")
	}
	return signer, nil
}
func parseCSR(data []byte) (*x509.CertificateRequest, error) {
	p, rest := pem.Decode(data)
	if p == nil || (p.Type != "CERTIFICATE REQUEST" && p.Type != "NEW CERTIFICATE REQUEST") {
		return nil, errors.New("expected PEM CERTIFICATE REQUEST or NEW CERTIFICATE REQUEST")
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
	var ca CAMeta
	if e = readJSON(filepath.Join(caDir, "metadata.json"), &ca); e != nil {
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
	if ca.Purpose == "client" {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
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
