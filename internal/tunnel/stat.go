package tunnel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Stat is the live runtime snapshot a runner writes for the panel to read.
type Stat struct {
	TunnelID         string    `json:"tunnel_id"`
	UpdatedAt        time.Time `json:"updated_at"`
	BytesIn          uint64    `json:"bytes_in"`  // remote -> local (download into Iran)
	BytesOut         uint64    `json:"bytes_out"` // local -> remote (upload to kharej)
	ActiveConns      int       `json:"active_conns"`
	ConnectedWorkers int       `json:"connected_workers"`
	TotalWorkers     int       `json:"total_workers"`
	LastError        string    `json:"last_error"`
	StartedAt        time.Time `json:"started_at"`
}

func statPath(runDir, id string) string {
	return filepath.Join(runDir, id+".stat")
}

// WriteStat atomically persists a stat snapshot.
func WriteStat(runDir string, st *Stat) error {
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	st.UpdatedAt = time.Now()
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	p := statPath(runDir, st.TunnelID)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ReadStat loads a stat snapshot; returns nil if none exists yet.
func ReadStat(runDir, id string) *Stat {
	raw, err := os.ReadFile(statPath(runDir, id))
	if err != nil {
		return nil
	}
	var st Stat
	if json.Unmarshal(raw, &st) != nil {
		return nil
	}
	return &st
}

// RemoveStat deletes a tunnel's stat file.
func RemoveStat(runDir, id string) {
	_ = os.Remove(statPath(runDir, id))
}
