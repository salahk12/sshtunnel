package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"sshtunnel-panel/internal/store"
)

// Version is set from main at startup.
var Version = "dev"

var httpClient = &http.Client{Timeout: 12 * time.Second}

// handleNodeInfo lets a master verify reachability + token of this node.
func (s *Server) handleNodeInfo(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"hostname":  host,
		"version":   Version,
		"base_path": s.cfg.BasePath,
	})
}

// nodeRequest issues an authenticated request to a remote node's API path
// (apiPath must start with "/api/...").
func nodeRequest(ctx context.Context, n *store.Node, method, apiPath string, body io.Reader) (*http.Response, error) {
	url := strings.TrimRight(n.BaseURL, "/") + apiPath
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	req.Header.Set("Content-Type", "application/json")
	return httpClient.Do(req)
}

// remoteTunnel is the subset of a node's tunnel view we aggregate on.
type remoteTunnel struct {
	Status *struct {
		Active string `json:"active"`
		Stat   *struct {
			BytesIn          uint64 `json:"bytes_in"`
			BytesOut         uint64 `json:"bytes_out"`
			ActiveConns      int    `json:"active_conns"`
			ConnectedWorkers int    `json:"connected_workers"`
		} `json:"stat"`
	} `json:"status"`
}

type nodeSummary struct {
	Online        bool   `json:"online"`
	Error         string `json:"error,omitempty"`
	Tunnels       int    `json:"tunnels"`
	ActiveTunnels int    `json:"active_tunnels"`
	BytesIn       uint64 `json:"bytes_in"`
	BytesOut      uint64 `json:"bytes_out"`
	Conns         int    `json:"conns"`
}

type nodeView struct {
	*store.Node
	Token   string      `json:"token,omitempty"` // omit secret in listings
	Summary nodeSummary `json:"summary"`
}

func (s *Server) handleNodesList(w http.ResponseWriter, r *http.Request) {
	nodes := s.st.Nodes()
	out := make([]nodeView, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n *store.Node) {
			defer wg.Done()
			cp := *n
			cp.Token = "" // never expose in list
			out[i] = nodeView{Node: &cp, Summary: s.summarize(n)}
		}(i, n)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) summarize(n *store.Node) nodeSummary {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	resp, err := nodeRequest(ctx, n, "GET", "/api/tunnels", nil)
	if err != nil {
		return nodeSummary{Online: false, Error: "unreachable"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nodeSummary{Online: false, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	var tns []remoteTunnel
	if err := json.NewDecoder(resp.Body).Decode(&tns); err != nil {
		return nodeSummary{Online: false, Error: "bad response"}
	}
	sum := nodeSummary{Online: true, Tunnels: len(tns)}
	for _, t := range tns {
		if t.Status == nil {
			continue
		}
		if t.Status.Active == "active" {
			sum.ActiveTunnels++
		}
		if t.Status.Stat != nil {
			sum.BytesIn += t.Status.Stat.BytesIn
			sum.BytesOut += t.Status.Stat.BytesOut
			sum.Conns += t.Status.Stat.ActiveConns
		}
	}
	return sum
}

func (s *Server) handleNodeAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		BaseURL string `json:"base_url"`
		Token   string `json:"token"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	in.Token = strings.TrimSpace(in.Token)
	if in.Name == "" || in.BaseURL == "" || in.Token == "" {
		writeErr(w, http.StatusBadRequest, "name, base_url and token are required")
		return
	}
	if !strings.HasPrefix(in.BaseURL, "http://") && !strings.HasPrefix(in.BaseURL, "https://") {
		in.BaseURL = "http://" + in.BaseURL
	}
	n := &store.Node{Name: in.Name, BaseURL: in.BaseURL, Token: in.Token}

	// Verify reachability + token before saving.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	resp, err := nodeRequest(ctx, n, "GET", "/api/node/info", nil)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "cannot reach node: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		writeErr(w, http.StatusBadRequest, "token rejected by node")
		return
	}
	if resp.StatusCode != 200 {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("node returned HTTP %d", resp.StatusCode))
		return
	}
	saved, err := s.st.AddNode(n)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	saved.Token = ""
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.st.DeleteNode(id); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleNodeProxy forwards /api/nodes/{id}/proxy/<rest> to the node's
// /api/<rest>, injecting the node's bearer token.
func (s *Server) handleNodeProxy(w http.ResponseWriter, r *http.Request) {
	n, err := s.st.Node(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	apiPath := "/api/" + r.PathValue("rest")
	if r.URL.RawQuery != "" {
		apiPath += "?" + r.URL.RawQuery
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	resp, err := nodeRequest(ctx, n, r.Method, apiPath, r.Body)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "node unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
