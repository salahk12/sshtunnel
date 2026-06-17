package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// AuthMethod for connecting to the remote (kharej) server.
const (
	AuthPassword = "password"
	AuthKey      = "key"
)

// Forward describes one local->remote port mapping inside a tunnel.
type Forward struct {
	ListenAddr string `json:"listen_addr"` // e.g. "0.0.0.0"
	ListenPort int    `json:"listen_port"` // e.g. 443
	RemoteAddr string `json:"remote_addr"` // e.g. "127.0.0.1"
	RemotePort int    `json:"remote_port"` // e.g. 443
}

// Tunnel is a managed SSH tunnel configuration.
type Tunnel struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	RemoteHost string    `json:"remote_host"`
	RemotePort int       `json:"remote_port"` // ssh port on kharej, default 22
	Username   string    `json:"username"`
	AuthMethod string    `json:"auth_method"`
	PrivateKey string    `json:"private_key"` // PEM; the key the tunnel authenticates with
	PublicKey  string    `json:"public_key"`  // authorized_keys line
	HostKey    string    `json:"host_key"`    // pinned remote host key (authorized_keys format)

	Cipher              string `json:"cipher"`
	Workers             int    `json:"workers"`
	Compression         bool   `json:"compression"`
	ServerAliveInterval int    `json:"server_alive_interval"`
	ServerAliveCountMax int    `json:"server_alive_count_max"`

	Forwards  []Forward `json:"forwards"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// User of the panel.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// Node is a remote panel (Iran server) managed from this central master.
type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	BaseURL   string    `json:"base_url"` // e.g. http://1.2.3.4:2095/secretpath
	Token     string    `json:"token"`    // node's NodeToken (bearer)
	Local     bool      `json:"local"`    // true for the auto-added self node
	CreatedAt time.Time `json:"created_at"`
}

type data struct {
	Users   []User    `json:"users"`
	Tunnels []*Tunnel `json:"tunnels"`
	Nodes   []*Node   `json:"nodes"`
}

// Store is a mutex-guarded JSON-file database.
type Store struct {
	mu   sync.RWMutex
	path string
	data data
}

// Open loads (or creates) the store at path.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, s.flush()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("parse store: %w", err)
	}
	return s, nil
}

// flush writes the store atomically. Caller must hold the write lock.
func (s *Store) flush() error {
	raw, err := json.MarshalIndent(&s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ---- Users ----

// HasUsers reports whether any user exists (used to gate first-run setup).
func (s *Store) HasUsers() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.Users) > 0
}

// SetUser creates or replaces the single admin user.
func (s *Store) SetUser(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Users = []User{{Username: username, PasswordHash: string(hash)}}
	return s.flush()
}

// CheckLogin validates credentials.
func (s *Store) CheckLogin(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.data.Users {
		if u.Username == username {
			return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
		}
	}
	return false
}

// AdminUsername returns the configured admin username (or "").
func (s *Store) AdminUsername() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.data.Users) > 0 {
		return s.data.Users[0].Username
	}
	return ""
}

// ---- Tunnels ----

var ErrNotFound = errors.New("not found")

// Tunnels returns a copy of all tunnels sorted by creation time.
func (s *Store) Tunnels() []*Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Tunnel, len(s.data.Tunnels))
	for i, t := range s.data.Tunnels {
		cp := *t
		out[i] = &cp
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Tunnel returns a copy of one tunnel by id.
func (s *Store) Tunnel(id string) (*Tunnel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.data.Tunnels {
		if t.ID == id {
			cp := *t
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// AddTunnel inserts a new tunnel, assigning an id and CreatedAt.
func (s *Store) AddTunnel(t *Tunnel) (*Tunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.ID == "" {
		t.ID = newID()
	}
	t.CreatedAt = time.Now()
	cp := *t
	s.data.Tunnels = append(s.data.Tunnels, &cp)
	if err := s.flush(); err != nil {
		return nil, err
	}
	out := cp
	return &out, nil
}

// UpdateTunnel replaces an existing tunnel (matched by ID), preserving CreatedAt.
func (s *Store) UpdateTunnel(t *Tunnel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ex := range s.data.Tunnels {
		if ex.ID == t.ID {
			t.CreatedAt = ex.CreatedAt
			cp := *t
			s.data.Tunnels[i] = &cp
			return s.flush()
		}
	}
	return ErrNotFound
}

// DeleteTunnel removes a tunnel by id.
func (s *Store) DeleteTunnel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.data.Tunnels {
		if t.ID == id {
			s.data.Tunnels = append(s.data.Tunnels[:i], s.data.Tunnels[i+1:]...)
			return s.flush()
		}
	}
	return ErrNotFound
}

// ---- Nodes (master registry) ----

// Nodes returns a copy of all registered nodes sorted by creation time.
func (s *Store) Nodes() []*Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Node, len(s.data.Nodes))
	for i, n := range s.data.Nodes {
		cp := *n
		out[i] = &cp
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Node returns a copy of one node by id.
func (s *Store) Node(id string) (*Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.data.Nodes {
		if n.ID == id {
			cp := *n
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// LocalNode returns the auto-added self node, if any.
func (s *Store) LocalNode() *Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.data.Nodes {
		if n.Local {
			cp := *n
			return &cp
		}
	}
	return nil
}

// AddNode inserts a new node.
func (s *Store) AddNode(n *Node) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.ID == "" {
		n.ID = newID()
	}
	n.CreatedAt = time.Now()
	cp := *n
	s.data.Nodes = append(s.data.Nodes, &cp)
	if err := s.flush(); err != nil {
		return nil, err
	}
	out := cp
	return &out, nil
}

// UpdateNode replaces an existing node (matched by ID), preserving CreatedAt.
func (s *Store) UpdateNode(n *Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ex := range s.data.Nodes {
		if ex.ID == n.ID {
			n.CreatedAt = ex.CreatedAt
			cp := *n
			s.data.Nodes[i] = &cp
			return s.flush()
		}
	}
	return ErrNotFound
}

// DeleteNode removes a node by id.
func (s *Store) DeleteNode(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, n := range s.data.Nodes {
		if n.ID == id {
			s.data.Nodes = append(s.data.Nodes[:i], s.data.Nodes[i+1:]...)
			return s.flush()
		}
	}
	return ErrNotFound
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
