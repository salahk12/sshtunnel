package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"sshtunnel-panel/internal/config"
	"sshtunnel-panel/internal/sshx"
	"sshtunnel-panel/internal/store"
	"sshtunnel-panel/internal/tunnel"
)

//go:embed static/*
var staticFS embed.FS

// Server holds web dependencies.
type Server struct {
	cfg   *config.Config
	st    *store.Store
	mgr   *tunnel.Manager
	sess  *sessionStore
	index []byte
}

// New builds the HTTP server handler.
func New(cfg *config.Config, st *store.Store, mgr *tunnel.Manager) (http.Handler, error) {
	s := &Server{cfg: cfg, st: st, mgr: mgr, sess: newSessionStore()}

	raw, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		return nil, err
	}
	// Inject base path so the SPA knows where the API lives.
	s.index = []byte(strings.ReplaceAll(string(raw), "__BASE__", cfg.BasePath))

	mux := http.NewServeMux()
	// API
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/ciphers", s.auth(s.handleCiphers))
	mux.HandleFunc("GET /api/tunnels", s.auth(s.handleList))
	mux.HandleFunc("POST /api/tunnels", s.auth(s.handleCreate))
	mux.HandleFunc("GET /api/tunnels/{id}", s.auth(s.handleGet))
	mux.HandleFunc("PUT /api/tunnels/{id}", s.auth(s.handleUpdate))
	mux.HandleFunc("DELETE /api/tunnels/{id}", s.auth(s.handleDelete))
	mux.HandleFunc("POST /api/tunnels/{id}/action", s.auth(s.handleAction))
	mux.HandleFunc("GET /api/tunnels/{id}/logs", s.auth(s.handleLogs))
	mux.HandleFunc("GET /api/settings", s.auth(s.handleGetSettings))
	mux.HandleFunc("PUT /api/settings", s.auth(s.handleUpdateSettings))

	// Node identity (used by a master to verify reachability + token).
	mux.HandleFunc("GET /api/node/info", s.auth(s.handleNodeInfo))

	// Master (central) endpoints: registry of remote nodes + reverse proxy.
	mux.HandleFunc("GET /api/nodes", s.auth(s.handleNodesList))
	mux.HandleFunc("POST /api/nodes", s.auth(s.handleNodeAdd))
	mux.HandleFunc("DELETE /api/nodes/{id}", s.auth(s.handleNodeDelete))
	mux.HandleFunc("/api/nodes/{id}/proxy/{rest...}", s.auth(s.handleNodeProxy))

	// Static assets + SPA fallback
	sub, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" || p == "index.html" {
			s.serveIndex(w)
			return
		}
		if _, err := fs.Stat(sub, p); err != nil {
			s.serveIndex(w) // SPA fallback
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	return s.withBasePath(mux), nil
}

func (s *Server) serveIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(s.index)
}

// withBasePath strips the configured base path before routing.
func (s *Server) withBasePath(h http.Handler) http.Handler {
	base := s.cfg.BasePath
	if base == "" {
		return h
	}
	outer := http.NewServeMux()
	outer.Handle(base+"/", http.StripPrefix(base, h))
	outer.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, base+"/", http.StatusFound)
	})
	outer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return outer
}

// ---- sessions ----

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]string // token -> username
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]string{}}
}

func (ss *sessionStore) create(username string) string {
	b := make([]byte, 24)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	ss.mu.Lock()
	ss.sessions[tok] = username
	ss.mu.Unlock()
	return tok
}

func (ss *sessionStore) get(tok string) (string, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	u, ok := ss.sessions[tok]
	return u, ok
}

func (ss *sessionStore) delete(tok string) {
	ss.mu.Lock()
	delete(ss.sessions, tok)
	ss.mu.Unlock()
}

const cookieName = "sshtp_session"

func (s *Server) cookiePath() string {
	if s.cfg.BasePath == "" {
		return "/"
	}
	return s.cfg.BasePath + "/"
}

// auth accepts either a valid session cookie (browser) or the node bearer
// token (master->node machine-to-machine calls).
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			if s.cfg.NodeToken != "" && strings.TrimPrefix(h, "Bearer ") == s.cfg.NodeToken {
				next(w, r)
				return
			}
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		if _, ok := s.sess.get(c.Value); !ok {
			writeErr(w, http.StatusUnauthorized, "session expired")
			return
		}
		next(w, r)
	}
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// ---- session / auth handlers ----

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"needs_setup": !s.st.HasUsers(), "authenticated": false, "master_enabled": s.cfg.MasterEnabled}
	if c, err := r.Cookie(cookieName); err == nil {
		if u, ok := s.sess.get(c.Value); ok {
			resp["authenticated"] = true
			resp["username"] = u
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.st.HasUsers() {
		writeErr(w, http.StatusConflict, "already configured")
		return
	}
	var in struct{ Username, Password string }
	if err := decode(r, &in); err != nil || in.Username == "" || len(in.Password) < 6 {
		writeErr(w, http.StatusBadRequest, "username and password (min 6 chars) required")
		return
	}
	if err := s.st.SetUser(in.Username, in.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setSession(w, in.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if !s.st.CheckLogin(in.Username, in.Password) {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.setSession(w, in.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) setSession(w http.ResponseWriter, username string) {
	tok := s.sess.create(username)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    tok,
		Path:     s.cookiePath(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sess.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: s.cookiePath(), MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCiphers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, sshx.SupportedCiphers)
}

// ---- tunnel handlers ----

// tunnelView is the API representation (private key omitted).
type tunnelView struct {
	*store.Tunnel
	PrivateKey string         `json:"private_key,omitempty"` // omit secret
	Status     *tunnel.Status `json:"status,omitempty"`
}

func (s *Server) view(t *store.Tunnel, withStatus bool) tunnelView {
	cp := *t
	cp.PrivateKey = "" // never expose
	v := tunnelView{Tunnel: &cp}
	if withStatus {
		st := s.mgr.Status(t.ID)
		v.Status = &st
	}
	return v
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	ts := s.st.Tunnels()
	out := make([]tunnelView, 0, len(ts))
	for _, t := range ts {
		out = append(out, s.view(t, true))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.st.Tunnel(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, s.view(t, true))
}

// tunnelInput is the create/update payload.
type tunnelInput struct {
	Name                string          `json:"name"`
	RemoteHost          string          `json:"remote_host"`
	RemotePort          int             `json:"remote_port"`
	Username            string          `json:"username"`
	AuthMethod          string          `json:"auth_method"`
	Password            string          `json:"password"`
	PrivateKey          string          `json:"private_key"`
	Cipher              string          `json:"cipher"`
	Workers             int             `json:"workers"`
	Compression         bool            `json:"compression"`
	ServerAliveInterval int             `json:"server_alive_interval"`
	ServerAliveCountMax int             `json:"server_alive_count_max"`
	BufferSize          int             `json:"buffer_size"`
	SocketBuffer        int             `json:"socket_buffer"`
	DisableNoDelay      bool            `json:"disable_nodelay"`
	MSS                 int             `json:"mss"`
	Forwards            []store.Forward `json:"forwards"`
	Enabled             bool            `json:"enabled"`
}

func (in *tunnelInput) normalize() {
	if in.RemotePort == 0 {
		in.RemotePort = 22
	}
	if in.Workers < 1 {
		in.Workers = 1
	}
	if in.Workers > 16 {
		in.Workers = 16
	}
	if in.ServerAliveInterval == 0 {
		in.ServerAliveInterval = 30
	}
	if in.ServerAliveCountMax == 0 {
		in.ServerAliveCountMax = 3
	}
	// Tuning bounds: keep values sane.
	if in.BufferSize < 0 {
		in.BufferSize = 0
	}
	if in.BufferSize > 8192 { // max 8 MB copy buffer
		in.BufferSize = 8192
	}
	if in.SocketBuffer < 0 {
		in.SocketBuffer = 0
	}
	if in.SocketBuffer > 65536 { // max 64 MB socket buffer
		in.SocketBuffer = 65536
	}
	if in.MSS < 0 {
		in.MSS = 0
	}
	if in.MSS > 9000 {
		in.MSS = 9000
	}
	for i := range in.Forwards {
		if in.Forwards[i].ListenAddr == "" {
			in.Forwards[i].ListenAddr = "0.0.0.0"
		}
		if in.Forwards[i].RemoteAddr == "" {
			in.Forwards[i].RemoteAddr = "127.0.0.1"
		}
	}
}

func (in *tunnelInput) validate() error {
	if in.Name == "" || in.RemoteHost == "" || in.Username == "" {
		return fmt.Errorf("name, remote_host and username are required")
	}
	if len(in.Forwards) == 0 {
		return fmt.Errorf("at least one port forward is required")
	}
	for _, f := range in.Forwards {
		if f.ListenPort <= 0 || f.RemotePort <= 0 {
			return fmt.Errorf("invalid port in forwards")
		}
	}
	return nil
}

// resolveAuth fills key material on the tunnel based on the chosen auth method.
// existing is non-nil on update (to reuse stored keys when unchanged).
func (s *Server) resolveAuth(in *tunnelInput, t *store.Tunnel, existing *store.Tunnel) error {
	switch in.AuthMethod {
	case store.AuthPassword:
		if in.Password == "" {
			// On update with no new password, keep existing key auth.
			if existing != nil && existing.PrivateKey != "" {
				t.PrivateKey = existing.PrivateKey
				t.PublicKey = existing.PublicKey
				t.HostKey = existing.HostKey
				t.AuthMethod = store.AuthKey
				return nil
			}
			return fmt.Errorf("password required")
		}
		kp, err := sshx.GenerateKey("sshtunnel-panel-" + t.ID)
		if err != nil {
			return err
		}
		hostKey, err := sshx.InstallKey(in.RemoteHost, in.RemotePort, in.Username, in.Password, kp.AuthorizedLine)
		if err != nil {
			return err
		}
		t.PrivateKey = kp.PrivatePEM
		t.PublicKey = kp.AuthorizedLine
		t.HostKey = hostKey
		t.AuthMethod = store.AuthKey // from now on we use the installed key
	case store.AuthKey:
		pem := in.PrivateKey
		if pem == "" && existing != nil {
			pem = existing.PrivateKey
		}
		if pem == "" {
			return fmt.Errorf("private_key required")
		}
		pub, err := sshx.PublicFromPrivate(pem)
		if err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}
		hostKey, err := sshx.TestConnection(sshx.ClientConfigOptions{
			User: in.Username, PrivatePEM: pem, Cipher: in.Cipher,
		}, in.RemoteHost, in.RemotePort)
		if err != nil {
			return fmt.Errorf("connection test failed: %w", err)
		}
		t.PrivateKey = pem
		t.PublicKey = pub
		t.HostKey = hostKey
		t.AuthMethod = store.AuthKey
	default:
		return fmt.Errorf("auth_method must be 'password' or 'key'")
	}
	return nil
}

func applyInput(t *store.Tunnel, in *tunnelInput) {
	t.Name = in.Name
	t.RemoteHost = in.RemoteHost
	t.RemotePort = in.RemotePort
	t.Username = in.Username
	t.Cipher = in.Cipher
	t.Workers = in.Workers
	t.Compression = in.Compression
	t.ServerAliveInterval = in.ServerAliveInterval
	t.ServerAliveCountMax = in.ServerAliveCountMax
	t.BufferSize = in.BufferSize
	t.SocketBuffer = in.SocketBuffer
	t.DisableNoDelay = in.DisableNoDelay
	t.MSS = in.MSS
	t.Forwards = in.Forwards
	t.Enabled = in.Enabled
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var in tunnelInput
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	in.normalize()
	if err := in.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	t := &store.Tunnel{ID: ""}
	// Pre-assign an id so key comments are stable.
	created, err := s.st.AddTunnel(t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	t = created
	applyInput(t, &in)
	if err := s.resolveAuth(&in, t, nil); err != nil {
		_ = s.st.DeleteTunnel(t.ID) // roll back the placeholder
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.UpdateTunnel(t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.mgr.Apply(t); err != nil {
		writeErr(w, http.StatusInternalServerError, "saved but failed to apply systemd unit: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.view(t, true))
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.st.Tunnel(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var in tunnelInput
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	in.normalize()
	if err := in.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	t := &store.Tunnel{ID: id}
	applyInput(t, &in)
	if err := s.resolveAuth(&in, t, existing); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.UpdateTunnel(t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.mgr.Apply(t); err != nil {
		writeErr(w, http.StatusInternalServerError, "saved but failed to apply: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.view(t, true))
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.st.Tunnel(id); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	_ = s.mgr.Remove(id)
	if err := s.st.DeleteTunnel(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := s.st.Tunnel(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var in struct{ Action string }
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	switch in.Action {
	case "start":
		t.Enabled = true
		_ = s.st.UpdateTunnel(t)
		err = s.mgr.Apply(t)
	case "stop":
		t.Enabled = false
		_ = s.st.UpdateTunnel(t)
		err = s.mgr.Apply(t)
	case "restart":
		err = s.mgr.Restart(id)
	default:
		writeErr(w, http.StatusBadRequest, "unknown action")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	out, _ := s.mgr.Logs(id, 200)
	writeJSON(w, http.StatusOK, map[string]string{"logs": out})
}

// ---- settings ----

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"listen":         s.cfg.Listen,
		"base_path":      s.cfg.BasePath,
		"username":       s.st.AdminUsername(),
		"node_token":     s.cfg.NodeToken,
		"master_enabled": s.cfg.MasterEnabled,
	})
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Listen        string `json:"listen"`
		BasePath      string `json:"base_path"`
		Username      string `json:"username"`
		NewPassword   string `json:"new_password"`
		MasterEnabled *bool  `json:"master_enabled"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if in.NewPassword != "" {
		if len(in.NewPassword) < 6 {
			writeErr(w, http.StatusBadRequest, "password too short")
			return
		}
		u := in.Username
		if u == "" {
			u = s.st.AdminUsername()
		}
		if err := s.st.SetUser(u, in.NewPassword); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if in.Listen != "" {
		s.cfg.Listen = in.Listen
	}
	s.cfg.BasePath = config.NormalizeBasePath(in.BasePath)
	if in.MasterEnabled != nil {
		s.cfg.MasterEnabled = *in.MasterEnabled
		if *in.MasterEnabled {
			s.ensureLocalNode()
		}
	}
	if err := s.cfg.Save(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": true})
}

func (s *Server) ensureLocalNode() { EnsureLocalNode(s.cfg, s.st) }

// EnsureLocalNode registers this server as a node in its own master registry,
// so the central dashboard shows local tunnels uniformly with remote ones.
func EnsureLocalNode(cfg *config.Config, st *store.Store) {
	if st.LocalNode() != nil {
		return
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		host, port = "127.0.0.1", "2095"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	base := fmt.Sprintf("http://%s:%s%s", host, port, cfg.BasePath)
	name, _ := os.Hostname()
	if name == "" {
		name = "local"
	}
	_, _ = st.AddNode(&store.Node{Name: name + " (local)", BaseURL: base, Token: cfg.NodeToken, Local: true})
}
