package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFS embed.FS

type session struct{ expires time.Time }
type App struct {
	store        *Store
	adminToken   string
	secureCookie bool
	sessions     map[string]session
	sessionMu    sync.Mutex
	mux          *http.ServeMux
}

type apiError struct {
	Error string `json:"error"`
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, err any) {
	jsonOut(w, status, apiError{Error: fmt.Sprint(err)})
}
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		fail(w, 400, "invalid JSON: "+err.Error())
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		fail(w, 400, "request must contain one JSON value")
		return false
	}
	return true
}
func NewApp(store *Store, admin string, secure bool) *App {
	a := &App{store: store, adminToken: admin, secureCookie: secure, sessions: map[string]session{}, mux: http.NewServeMux()}
	a.routes()
	return a
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	a.mux.ServeHTTP(w, r)
}
func (a *App) routes() {
	a.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		b, e := webFS.ReadFile("web/index.html")
		if e != nil {
			http.Error(w, "UI unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	a.mux.HandleFunc("GET /app.css", asset("web/app.css", "text/css; charset=utf-8"))
	a.mux.HandleFunc("GET /app.js", asset("web/app.js", "text/javascript; charset=utf-8"))
	a.mux.HandleFunc("POST /admin/login", a.login)
	a.mux.HandleFunc("POST /admin/logout", a.requireAdmin(a.logout))
	a.mux.HandleFunc("GET /admin/state", a.requireAdmin(a.state))
	a.mux.HandleFunc("POST /admin/ca", a.requireAdmin(a.createCA))
	a.mux.HandleFunc("DELETE /admin/ca/{id}", a.requireAdmin(a.deleteCA))
	a.mux.HandleFunc("GET /admin/ca/{id}/{kind}", a.requireAdmin(a.downloadCA))
	a.mux.HandleFunc("POST /admin/server", a.requireAdmin(a.createServer))
	a.mux.HandleFunc("POST /admin/server/certificate", a.requireAdmin(a.createServerCertificate))
	a.mux.HandleFunc("POST /admin/server/{id}/issue", a.requireAdmin(a.adminIssue))
	a.mux.HandleFunc("DELETE /admin/server/{id}/certificate", a.requireAdmin(a.adminDeleteCert))
	a.mux.HandleFunc("GET /admin/server/{id}/certificate", a.requireAdmin(a.adminDownloadCert))
	a.mux.HandleFunc("DELETE /admin/server/{id}", a.requireAdmin(a.deleteServer))
	a.mux.HandleFunc("POST /admin/credential/{id}/{action}", a.requireAdmin(a.credential))
	a.mux.HandleFunc("GET /api/v1/openssl.cnf", a.opensslConfig)
	a.mux.HandleFunc("POST /api/v1/register", a.register)
	a.mux.HandleFunc("GET /api/v1/server", a.requireServer(a.serverStatus))
	a.mux.HandleFunc("POST /api/v1/ca/{caID}/server/certificate", a.requireServer(a.serverIssue))
	a.mux.HandleFunc("POST /api/v1/server/renew", a.requireServer(a.serverRenew))
	a.mux.HandleFunc("GET /api/v1/server/certificate", a.requireServer(a.download))
	a.mux.HandleFunc("DELETE /api/v1/server/certificate", a.requireServer(a.removeCert))
}
func asset(path, typ string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, e := webFS.ReadFile(path)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", typ)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(b)
	}
}
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	return o == "http://"+r.Host || o == "https://"+r.Host
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		fail(w, 403, "cross-origin request denied")
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Token) != len(a.adminToken) || subtle.ConstantTimeCompare([]byte(in.Token), []byte(a.adminToken)) != 1 {
		fail(w, 401, "invalid admin token")
		return
	}
	sid, _ := randomHex(32)
	a.sessionMu.Lock()
	a.sessions[sid] = session{time.Now().Add(12 * time.Hour)}
	a.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "kissl_session", Value: sid, Path: "/", HttpOnly: true, Secure: a.secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	jsonOut(w, 200, map[string]bool{"ok": true})
}
func (a *App) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && !sameOrigin(r) {
			fail(w, 403, "cross-origin request denied")
			return
		}
		authorized := false
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			t := strings.TrimPrefix(h, "Bearer ")
			authorized = len(t) == len(a.adminToken) && subtle.ConstantTimeCompare([]byte(t), []byte(a.adminToken)) == 1
		}
		if !authorized {
			if c, e := r.Cookie("kissl_session"); e == nil {
				a.sessionMu.Lock()
				s, ok := a.sessions[c.Value]
				if ok && time.Now().Before(s.expires) {
					authorized = true
				} else {
					delete(a.sessions, c.Value)
				}
				a.sessionMu.Unlock()
			}
		}
		if !authorized {
			fail(w, 401, "admin authentication required")
			return
		}
		next(w, r)
	}
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("kissl_session"); e == nil {
		a.sessionMu.Lock()
		delete(a.sessions, c.Value)
		a.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "kissl_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secureCookie, SameSite: http.SameSiteStrictMode})
	jsonOut(w, 200, map[string]bool{"ok": true})
}

type stateResponse struct {
	CAs         []CAMeta         `json:"cas"`
	Servers     []ServerMeta     `json:"servers"`
	Credentials []CredentialView `json:"credentials"`
}
type CredentialView struct {
	ServerID string    `json:"server_id"`
	Enabled  bool      `json:"enabled"`
	Created  time.Time `json:"created_at"`
}

func (a *App) state(w http.ResponseWriter, r *http.Request) {
	cas, e := a.store.ListCAs()
	if e != nil {
		fail(w, 500, e)
		return
	}
	servers, e := a.store.ListServers()
	if e != nil {
		fail(w, 500, e)
		return
	}
	cs, e := a.store.Credentials()
	if e != nil {
		fail(w, 500, e)
		return
	}
	views := make([]CredentialView, 0, len(cs))
	for _, c := range cs {
		views = append(views, CredentialView{c.ServerID, c.Enabled, c.Created})
	}
	jsonOut(w, 200, stateResponse{cas, servers, views})
}
func (a *App) createCA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		RootDays    int    `json:"root_days"`
		IssuingDays int    `json:"issuing_days"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	m, e := a.store.CreateCA(strings.TrimSpace(in.Name), in.RootDays, in.IssuingDays)
	if e != nil {
		fail(w, 400, e)
		return
	}
	jsonOut(w, 201, m)
}
func (a *App) deleteCA(w http.ResponseWriter, r *http.Request) {
	if e := a.store.DeleteCA(r.PathValue("id")); e != nil {
		fail(w, 409, e)
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}
func (a *App) downloadCA(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "root" && kind != "issuing" {
		fail(w, 404, "certificate not found")
		return
	}
	d, e := a.store.caDir(r.PathValue("id"))
	if e != nil {
		fail(w, 400, e)
		return
	}
	paths := []string{filepath.Join(d, kind+"-cert.pem")}
	if kind == "issuing" {
		paths = append(paths, filepath.Join(d, "root-cert.pem"))
	}
	serveCertificate(w, r, paths, kind+"-ca.pem", kind+"-ca.p7b")
}
func (a *App) createServer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if e := cleanName(strings.TrimSpace(in.Name)); e != nil {
		fail(w, 400, e)
		return
	}
	m, t, e := a.store.Register(strings.TrimSpace(in.Name))
	if e != nil {
		if errors.Is(e, ErrDuplicateServer) {
			fail(w, http.StatusConflict, e)
		} else {
			fail(w, 500, e)
		}
		return
	}
	jsonOut(w, 201, map[string]any{"server": m, "token": t, "warning": "This token is shown once. Store it securely; enable it before use."})
}

type issueRequest struct {
	CAID string `json:"ca_id"`
	CSR  string `json:"csr_pem"`
	Days int    `json:"validity_days"`
}

func (a *App) createServerCertificate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		issueRequest
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if e := cleanName(in.Name); e != nil {
		fail(w, 400, e)
		return
	}
	server, token, e := a.store.Register(in.Name)
	if e != nil {
		if errors.Is(e, ErrDuplicateServer) {
			fail(w, http.StatusConflict, e)
		} else {
			fail(w, 500, e)
		}
		return
	}
	issued, e := a.store.Issue(server.ID, in.CAID, []byte(in.CSR), in.Days)
	if e != nil {
		if cleanupErr := a.store.DeleteServer(server.ID); cleanupErr != nil {
			log.Printf("clean up server %s after failed issuance: %v", server.ID, cleanupErr)
		}
		fail(w, 400, e)
		return
	}
	jsonOut(w, 201, map[string]any{
		"server":  issued,
		"token":   token,
		"enabled": false,
		"warning": "This token is shown once. Store it securely; enable it before use.",
	})
}

func (a *App) adminIssue(w http.ResponseWriter, r *http.Request) {
	var in issueRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	m, e := a.store.Issue(r.PathValue("id"), in.CAID, []byte(in.CSR), in.Days)
	if e != nil {
		fail(w, 400, e)
		return
	}
	jsonOut(w, 201, m)
}
func (a *App) adminDeleteCert(w http.ResponseWriter, r *http.Request) {
	if e := a.store.RemoveCertificate(r.PathValue("id")); e != nil {
		fail(w, 400, e)
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}
func (a *App) adminDownloadCert(w http.ResponseWriter, r *http.Request) {
	paths, e := a.serverCertificatePaths(r.PathValue("id"))
	if e != nil {
		fail(w, 404, e)
		return
	}
	serveCertificate(w, r, paths, "certificate.pem", "certificate-chain.p7b")
}
func (a *App) deleteServer(w http.ResponseWriter, r *http.Request) {
	if e := a.store.DeleteServer(r.PathValue("id")); e != nil {
		fail(w, 400, e)
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}
func (a *App) credential(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action != "enable" && action != "disable" && action != "revoke" {
		fail(w, 404, "unknown action")
		return
	}
	if e := a.store.SetCredential(r.PathValue("id"), action == "enable", action == "revoke"); e != nil {
		fail(w, 404, e)
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	t := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	return t, t != ""
}
func (a *App) requireServer(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, ok := bearer(r)
		if !ok {
			fail(w, 401, "bearer token required")
			return
		}
		c, ok, e := a.store.Authenticate(t)
		if e != nil {
			fail(w, 500, "authentication unavailable")
			return
		}
		if !ok {
			fail(w, 401, "invalid or revoked token")
			return
		}
		if !c.Enabled {
			fail(w, 403, "credential is disabled")
			return
		}
		next(w, r, c.ServerID)
	}
}
func (a *App) opensslConfig(w http.ResponseWriter, r *http.Request) {
	const config = `# kissl OpenSSL CSR template
#
# 1. Edit commonName and the alt_names entries below for this server.
# 2. Generate a private key (keep server.key private):
#      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server.key
# 3. Generate the CSR to submit to kissl:
#      openssl req -new -key server.key -out server.csr -config openssl.cnf
#
# Register the server. The returned token starts disabled and is shown once:
#   curl -X POST KISSL_BASE_URL/api/v1/register \
#     -H 'Content-Type: application/json' \
#     -d '{"name":"server.example.lab"}'
#
# After an administrator enables the token, submit the CSR as the request body:
#   curl -X POST 'KISSL_BASE_URL/api/v1/ca/CA_ID_FROM_KISSL/server/certificate?valid=90' \
#     -H 'Authorization: Bearer TOKEN_FROM_REGISTRATION' \
#     -H 'Content-Type: application/pkcs10' \
#     --data-binary @server.csr
#
# Download the issued certificate:
#   curl KISSL_BASE_URL/api/v1/server/certificate \
#     -H 'Authorization: Bearer TOKEN_FROM_REGISTRATION' \
#     -o server.crt

[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = distinguished_name
req_extensions     = request_extensions

[ distinguished_name ]
countryName            = US
stateOrProvinceName    = Colorado
localityName           = Windsor
organizationName       = WTFerris Net
organizationalUnitName = IT Department
commonName             = server.example.lab

[ request_extensions ]
basicConstraints = critical, CA:false
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName   = @alt_names

[ alt_names ]
DNS.1 = server.example.lab
# DNS.2 = alias.example.lab
# IP.1  = 192.0.2.10
`
	w.Header().Set("Content-Type", "application/x-openssl-conf; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="openssl.cnf"`)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded == "http" || forwarded == "https" {
		scheme = forwarded
	}
	baseURL := scheme + "://" + r.Host
	_, _ = io.WriteString(w, strings.ReplaceAll(config, "KISSL_BASE_URL", baseURL))
}

func (a *App) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if e := cleanName(in.Name); e != nil {
		fail(w, 400, e)
		return
	}
	m, t, e := a.store.Register(in.Name)
	if e != nil {
		if errors.Is(e, ErrDuplicateServer) {
			fail(w, http.StatusConflict, e)
		} else {
			fail(w, 500, e)
		}
		return
	}
	jsonOut(w, 201, map[string]any{"server_id": m.ID, "token": t, "enabled": false})
}
func (a *App) serverStatus(w http.ResponseWriter, r *http.Request, id string) {
	m, e := a.store.GetServer(id)
	if e != nil {
		fail(w, 404, e)
		return
	}
	jsonOut(w, 200, m)
}
func (a *App) serverIssue(w http.ResponseWriter, r *http.Request, id string) {
	days := 90
	if value := r.URL.Query().Get("valid"); value != "" {
		parsed, e := strconv.Atoi(value)
		if e != nil {
			fail(w, 400, "valid must be a whole number of days")
			return
		}
		days = parsed
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	csr, e := io.ReadAll(r.Body)
	if e != nil {
		fail(w, 400, "unable to read CSR")
		return
	}
	if len(csr) == 0 {
		fail(w, 400, "request body must contain a PEM CSR")
		return
	}
	m, e := a.store.GetServer(id)
	if e != nil {
		fail(w, 404, e)
		return
	}
	if m.CAID != "" {
		fail(w, 409, "certificate already exists; use renewal")
		return
	}
	m, e = a.store.Issue(id, r.PathValue("caID"), csr, days)
	if e != nil {
		fail(w, 400, e)
		return
	}
	jsonOut(w, 201, m)
}
func (a *App) serverRenew(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		Days int `json:"validity_days"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	m, e := a.store.Renew(id, in.Days)
	if e != nil {
		fail(w, 400, e)
		return
	}
	jsonOut(w, 200, m)
}
func (a *App) serverCertificatePaths(id string) ([]string, error) {
	server, e := a.store.GetServer(id)
	if e != nil {
		return nil, e
	}
	if server.CAID == "" {
		return nil, os.ErrNotExist
	}
	serverPath, e := a.store.certPath(id)
	if e != nil {
		return nil, e
	}
	caDir, e := a.store.caDir(server.CAID)
	if e != nil {
		return nil, e
	}
	return []string{
		serverPath,
		filepath.Join(caDir, "issuing-cert.pem"),
		filepath.Join(caDir, "root-cert.pem"),
	}, nil
}
func (a *App) download(w http.ResponseWriter, r *http.Request, id string) {
	paths, e := a.serverCertificatePaths(id)
	if e != nil {
		fail(w, 404, "certificate not found")
		return
	}
	serveCertificate(w, r, paths, "certificate.pem", "certificate-chain.p7b")
}
func (a *App) removeCert(w http.ResponseWriter, r *http.Request, id string) {
	if e := a.store.RemoveCertificate(id); e != nil {
		fail(w, 400, e)
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func main() {
	dir := getenv("KISSL_DATA_DIR", "./data")
	addr := getenv("KISSL_ADDR", ":8080")
	token := os.Getenv("KISSL_ADMIN_TOKEN")
	if token == "" {
		token, _ = randomHex(24)
		log.Printf("KISSL_ADMIN_TOKEN was not set; generated admin token (shown once): %s", token)
	}
	store, e := NewStore(dir)
	if e != nil {
		log.Fatal(e)
	}
	srv := &http.Server{Addr: addr, Handler: NewApp(store, token, os.Getenv("KISSL_COOKIE_SECURE") == "true"), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	log.Printf("kissl listening on %s using data directory %s", addr, dir)
	log.Fatal(srv.ListenAndServe())
}
func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
