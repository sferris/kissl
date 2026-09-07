package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	safeID             = regexp.MustCompile(`^[a-f0-9]{32}$`)
	ErrDuplicateServer = errors.New("a server with this name is already registered")
)

type CAMeta struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	CreatedAt       time.Time `json:"created_at"`
	RootNotAfter    time.Time `json:"root_not_after"`
	IssuingNotAfter time.Time `json:"issuing_not_after"`
}

type ServerMeta struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	CAID         string     `json:"ca_id,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	IssuedAt     *time.Time `json:"issued_at,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	SerialNumber string     `json:"serial_number,omitempty"`
}

type Credential struct {
	ServerID string    `json:"server_id"`
	Hash     string    `json:"token_sha256"`
	Enabled  bool      `json:"enabled"`
	Created  time.Time `json:"created_at"`
}

type AuthFile struct {
	Credentials []Credential `json:"credentials"`
}

type Store struct {
	dir string
	mu  sync.RWMutex
}

func NewStore(dir string) (*Store, error) {
	for _, d := range []string{dir, filepath.Join(dir, "ca"), filepath.Join(dir, "servers")} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, err
		}
	}
	s := &Store{dir: dir}
	if _, err := os.Stat(s.authPath()); errors.Is(err, os.ErrNotExist) {
		if err := atomicJSON(s.authPath(), AuthFile{}, 0600); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func validID(id string) error {
	if !safeID.MatchString(id) {
		return errors.New("invalid id")
	}
	return nil
}
func (s *Store) caDir(id string) (string, error) {
	if err := validID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, "ca", id), nil
}
func (s *Store) serverDir(id string) (string, error) {
	if err := validID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, "servers", id), nil
}
func (s *Store) authPath() string { return filepath.Join(s.dir, "auth.json") }

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
func atomicJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return atomicWrite(path, b, mode)
}
func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (s *Store) ListCAs() ([]CAMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(filepath.Join(s.dir, "ca"))
	if err != nil {
		return nil, err
	}
	out := []CAMeta{}
	for _, e := range entries {
		if !e.IsDir() || validID(e.Name()) != nil {
			continue
		}
		var m CAMeta
		if readJSON(filepath.Join(s.dir, "ca", e.Name(), "metadata.json"), &m) == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *Store) ListServers() ([]ServerMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listServersLocked()
}
func (s *Store) listServersLocked() ([]ServerMeta, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "servers"))
	if err != nil {
		return nil, err
	}
	out := []ServerMeta{}
	for _, e := range entries {
		if !e.IsDir() || validID(e.Name()) != nil {
			continue
		}
		var m ServerMeta
		if readJSON(filepath.Join(s.dir, "servers", e.Name(), "metadata.json"), &m) == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *Store) GetServer(id string) (ServerMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getServerLocked(id)
}
func (s *Store) getServerLocked(id string) (ServerMeta, error) {
	d, e := s.serverDir(id)
	if e != nil {
		return ServerMeta{}, e
	}
	var m ServerMeta
	e = readJSON(filepath.Join(d, "metadata.json"), &m)
	return m, e
}
func (s *Store) GetCA(id string) (CAMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, e := s.caDir(id)
	if e != nil {
		return CAMeta{}, e
	}
	var m CAMeta
	e = readJSON(filepath.Join(d, "metadata.json"), &m)
	return m, e
}
func (s *Store) DeleteCA(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, e := s.caDir(id)
	if e != nil {
		return e
	}
	servers, e := s.listServersLocked()
	if e != nil {
		return e
	}
	for _, v := range servers {
		if v.CAID == id {
			return errors.New("CA has issued server certificates")
		}
	}
	return os.RemoveAll(d)
}
func (s *Store) DeleteServer(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, e := s.serverDir(id)
	if e != nil {
		return e
	}
	if e = os.RemoveAll(d); e != nil {
		return e
	}
	a, e := s.loadAuthLocked()
	if e != nil {
		return e
	}
	kept := a.Credentials[:0]
	for _, c := range a.Credentials {
		if c.ServerID != id {
			kept = append(kept, c)
		}
	}
	a.Credentials = kept
	return atomicJSON(s.authPath(), a, 0600)
}
func (s *Store) RemoveCertificate(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, e := s.serverDir(id)
	if e != nil {
		return e
	}
	m, e := s.getServerLocked(id)
	if e != nil {
		return e
	}
	for _, n := range []string{"cert.pem", "csr.pem"} {
		if e = os.Remove(filepath.Join(d, n)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	m.CAID = ""
	m.IssuedAt = nil
	m.NotAfter = nil
	m.SerialNumber = ""
	return atomicJSON(filepath.Join(d, "metadata.json"), m, 0600)
}

func (s *Store) loadAuthLocked() (AuthFile, error) {
	var a AuthFile
	e := readJSON(s.authPath(), &a)
	return a, e
}
func hashToken(t string) string { h := sha256.Sum256([]byte(t)); return hex.EncodeToString(h[:]) }
func (s *Store) Register(name string) (ServerMeta, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = strings.TrimSpace(name)
	servers, e := s.listServersLocked()
	if e != nil {
		return ServerMeta{}, "", e
	}
	for _, server := range servers {
		if strings.EqualFold(strings.TrimSpace(server.Name), name) {
			return ServerMeta{}, "", ErrDuplicateServer
		}
	}
	id, e := randomHex(16)
	if e != nil {
		return ServerMeta{}, "", e
	}
	token, e := randomHex(32)
	if e != nil {
		return ServerMeta{}, "", e
	}
	now := time.Now().UTC()
	m := ServerMeta{ID: id, Name: name, CreatedAt: now}
	d, _ := s.serverDir(id)
	if e = os.Mkdir(d, 0700); e != nil {
		return ServerMeta{}, "", e
	}
	if e = atomicJSON(filepath.Join(d, "metadata.json"), m, 0600); e != nil {
		os.RemoveAll(d)
		return ServerMeta{}, "", e
	}
	a, e := s.loadAuthLocked()
	if e != nil {
		os.RemoveAll(d)
		return ServerMeta{}, "", e
	}
	a.Credentials = append(a.Credentials, Credential{ServerID: id, Hash: hashToken(token), Created: now})
	if e = atomicJSON(s.authPath(), a, 0600); e != nil {
		os.RemoveAll(d)
		return ServerMeta{}, "", e
	}
	return m, token, nil
}
func (s *Store) Credentials() ([]Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, e := s.loadAuthLocked()
	return a.Credentials, e
}
func (s *Store) SetCredential(id string, enabled bool, revoke bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := validID(id); e != nil {
		return e
	}
	a, e := s.loadAuthLocked()
	if e != nil {
		return e
	}
	found := false
	out := a.Credentials[:0]
	for _, c := range a.Credentials {
		if c.ServerID == id {
			found = true
			if revoke {
				continue
			}
			c.Enabled = enabled
		}
		out = append(out, c)
	}
	if !found {
		return os.ErrNotExist
	}
	a.Credentials = out
	return atomicJSON(s.authPath(), a, 0600)
}
func (s *Store) Authenticate(token string) (Credential, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, e := s.loadAuthLocked()
	if e != nil {
		return Credential{}, false, e
	}
	h := hashToken(token)
	for _, c := range a.Credentials {
		if subtleEqual(c.Hash, h) {
			return c, true, nil
		}
	}
	return Credential{}, false, nil
}
func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := range a {
		x |= a[i] ^ b[i]
	}
	return x == 0
}
func (s *Store) certPath(id string) (string, error) {
	d, e := s.serverDir(id)
	return filepath.Join(d, "cert.pem"), e
}
func (s *Store) readCertificate(id string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, e := s.certPath(id)
	if e != nil {
		return nil, e
	}
	return os.ReadFile(p)
}
func cleanName(name string) error {
	if len(name) < 1 || len(name) > 100 {
		return fmt.Errorf("name must be 1-100 characters")
	}
	for _, r := range name {
		if r < 32 {
			return errors.New("name contains control characters")
		}
	}
	return nil
}
