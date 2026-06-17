package tunnel

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"sshtunnel-panel/internal/config"
	"sshtunnel-panel/internal/store"
)

const systemdDir = "/etc/systemd/system"

// Manager generates and controls one systemd unit per tunnel.
type Manager struct {
	cfg     *config.Config
	exePath string
}

// NewManager returns a Manager. exePath is the absolute path to this binary,
// embedded into generated units as ExecStart.
func NewManager(cfg *config.Config, exePath string) *Manager {
	return &Manager{cfg: cfg, exePath: exePath}
}

func unitName(id string) string { return "sshtunnel-" + id + ".service" }

func (m *Manager) unitPath(id string) string {
	return filepath.Join(systemdDir, unitName(id))
}

var unitTmpl = template.Must(template.New("unit").Parse(`[Unit]
Description=SSH Tunnel {{.Name}} ({{.ID}})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.Exe}} run-tunnel --id {{.ID}}
Restart=always
RestartSec=3s
Environment=SSHTP_CONFIG_DIR={{.ConfigDir}}
Environment=SSHTP_DATA_DIR={{.DataDir}}
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`))

// WriteUnit (re)generates the systemd unit file for a tunnel.
func (m *Manager) WriteUnit(t *store.Tunnel) error {
	var buf bytes.Buffer
	err := unitTmpl.Execute(&buf, map[string]string{
		"Name":      t.Name,
		"ID":        t.ID,
		"Exe":       m.exePath,
		"ConfigDir": config.Dir(),
		"DataDir":   m.cfg.DataDir,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(m.unitPath(t.ID), buf.Bytes(), 0o644)
}

// Apply writes the unit, reloads systemd, and brings the unit to the desired
// state: enabled+started when t.Enabled, otherwise stopped+disabled.
func (m *Manager) Apply(t *store.Tunnel) error {
	if err := m.WriteUnit(t); err != nil {
		return err
	}
	if err := m.daemonReload(); err != nil {
		return err
	}
	if t.Enabled {
		if err := m.systemctl("enable", unitName(t.ID)); err != nil {
			return err
		}
		return m.systemctl("restart", unitName(t.ID))
	}
	_ = m.systemctl("disable", unitName(t.ID))
	return m.systemctl("stop", unitName(t.ID))
}

// Start/Stop/Restart control an existing unit.
func (m *Manager) Start(id string) error   { return m.systemctl("start", unitName(id)) }
func (m *Manager) Stop(id string) error    { return m.systemctl("stop", unitName(id)) }
func (m *Manager) Restart(id string) error { return m.systemctl("restart", unitName(id)) }

// Remove stops, disables, and deletes the unit and its stat file.
func (m *Manager) Remove(id string) error {
	_ = m.systemctl("stop", unitName(id))
	_ = m.systemctl("disable", unitName(id))
	_ = os.Remove(m.unitPath(id))
	_ = m.daemonReload()
	RemoveStat(m.cfg.RunDir(), id)
	return nil
}

// Status describes the runtime state of a tunnel unit.
type Status struct {
	Active    string `json:"active"`     // active / inactive / failed / activating
	Enabled   bool   `json:"enabled"`    // enabled on boot
	SubState  string `json:"sub_state"`  // running / dead / ...
	Stat      *Stat  `json:"stat"`       // traffic snapshot (may be nil)
}

// Status returns the unit status plus the latest stat snapshot.
func (m *Manager) Status(id string) Status {
	s := Status{}
	s.Active = strings.TrimSpace(m.output("is-active", unitName(id)))
	s.SubState = strings.TrimSpace(m.showProp(id, "SubState"))
	en := strings.TrimSpace(m.output("is-enabled", unitName(id)))
	s.Enabled = en == "enabled"
	s.Stat = ReadStat(m.cfg.RunDir(), id)
	return s
}

// Logs returns the last n journal lines for a tunnel unit.
func (m *Manager) Logs(id string, n int) (string, error) {
	cmd := exec.Command("journalctl", "-u", unitName(id), "-n", fmt.Sprintf("%d", n), "--no-pager", "-o", "short-iso")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (m *Manager) daemonReload() error { return m.systemctl("daemon-reload") }

func (m *Manager) systemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) output(args ...string) string {
	cmd := exec.Command("systemctl", args...)
	out, _ := cmd.CombinedOutput() // is-active returns non-zero when inactive; ignore err
	return string(out)
}

func (m *Manager) showProp(id, prop string) string {
	cmd := exec.Command("systemctl", "show", unitName(id), "-p", prop, "--value")
	out, _ := cmd.CombinedOutput()
	return string(out)
}
