package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh"

	"sshtunnel-panel/internal/config"
	"sshtunnel-panel/internal/sshx"
	"sshtunnel-panel/internal/store"
)

// ReverseManager implements reverse tunnels: the kharej (foreign) server dials
// back into this Iran server with `ssh -R`, so Iran makes no outbound traffic
// during operation. The connector is deployed onto kharej over SSH; Iran only
// runs sshd (with GatewayPorts) and accounts traffic locally via iptables.
type ReverseManager struct {
	cfg *config.Config
}

func NewReverseManager(cfg *config.Config) *ReverseManager { return &ReverseManager{cfg: cfg} }

func revUnitName(id string) string { return "sshtunnel-rev-" + id + ".service" }
func revKeyPath(id string) string  { return "/etc/sshtunnel-reverse/" + id + ".key" }
func revKnownHosts(id string) string {
	return "/etc/sshtunnel-reverse/" + id + ".known_hosts"
}

// Apply performs the full reverse setup: Iran-side authorized_keys + GatewayPorts
// + iptables accounting, then deploys/starts the connector unit on kharej.
func (m *ReverseManager) Apply(t *store.Tunnel) error {
	if err := m.ensureIranAuthorizedKey(t); err != nil {
		return fmt.Errorf("install reverse key on Iran: %w", err)
	}
	if err := ensureGatewayPorts(); err != nil {
		return fmt.Errorf("enable GatewayPorts: %w", err)
	}
	for _, f := range t.Forwards {
		iptEnsure(f.ListenPort)
	}

	client, err := m.dialKharej(t)
	if err != nil {
		return fmt.Errorf("connect to kharej: %w", err)
	}
	defer client.Close()

	if err := sshx.WriteRemoteFile(client, revKeyPath(t.ID), t.ReverseKey, "600"); err != nil {
		return fmt.Errorf("write key on kharej: %w", err)
	}
	unit := m.buildUnit(t)
	if err := sshx.WriteRemoteFile(client, "/etc/systemd/system/"+revUnitName(t.ID), unit, "644"); err != nil {
		return fmt.Errorf("write unit on kharej: %w", err)
	}
	if out, err := sshx.RunCommand(client, "systemctl daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload on kharej: %v: %s", err, out)
	}
	if t.Enabled {
		if out, err := sshx.RunCommand(client, "systemctl enable --now "+revUnitName(t.ID)+" && systemctl restart "+revUnitName(t.ID)); err != nil {
			return fmt.Errorf("start on kharej: %v: %s", err, out)
		}
	} else {
		_, _ = sshx.RunCommand(client, "systemctl disable --now "+revUnitName(t.ID))
	}
	return nil
}

// buildUnit renders the systemd unit that runs on kharej.
func (m *ReverseManager) buildUnit(t *store.Tunnel) string {
	sai := t.ServerAliveInterval
	if sai <= 0 {
		sai = 30
	}
	sacm := t.ServerAliveCountMax
	if sacm <= 0 {
		sacm = 3
	}
	args := []string{
		"/usr/bin/ssh", "-N",
		"-o", "ExitOnForwardFailure=yes",
		"-o", fmt.Sprintf("ServerAliveInterval=%d", sai),
		"-o", fmt.Sprintf("ServerAliveCountMax=%d", sacm),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + revKnownHosts(t.ID),
		"-i", revKeyPath(t.ID),
		"-p", fmt.Sprintf("%d", tIranPort(t)),
	}
	if t.Compression {
		args = append(args, "-C")
	}
	if t.Cipher != "" {
		args = append(args, "-c", t.Cipher)
	}
	for _, f := range t.Forwards {
		args = append(args, "-R", fmt.Sprintf("0.0.0.0:%d:%s:%d", f.ListenPort, f.RemoteAddr, f.RemotePort))
	}
	args = append(args, fmt.Sprintf("%s@%s", tIranUser(t), t.IranHost))

	return fmt.Sprintf(`[Unit]
Description=SSH Reverse Tunnel %s (%s) -> %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
`, t.Name, t.ID, t.IranHost, strings.Join(args, " "))
}

// Remove tears down the kharej unit and Iran-side accounting / key.
func (m *ReverseManager) Remove(t *store.Tunnel) error {
	if client, err := m.dialKharej(t); err == nil {
		_, _ = sshx.RunCommand(client, "systemctl disable --now "+revUnitName(t.ID)+
			"; rm -f /etc/systemd/system/"+revUnitName(t.ID)+" "+revKeyPath(t.ID)+" "+revKnownHosts(t.ID)+
			"; systemctl daemon-reload")
		client.Close()
	}
	for _, f := range t.Forwards {
		iptRemove(f.ListenPort)
	}
	m.removeIranAuthorizedKey(t)
	return nil
}

func (m *ReverseManager) Start(t *store.Tunnel) error   { return m.kharejCtl(t, "enable --now") }
func (m *ReverseManager) Stop(t *store.Tunnel) error    { return m.kharejCtl(t, "disable --now") }
func (m *ReverseManager) Restart(t *store.Tunnel) error { return m.kharejCtl(t, "restart") }

func (m *ReverseManager) kharejCtl(t *store.Tunnel, action string) error {
	client, err := m.dialKharej(t)
	if err != nil {
		return fmt.Errorf("connect to kharej: %w", err)
	}
	defer client.Close()
	if out, err := sshx.RunCommand(client, "systemctl "+action+" "+revUnitName(t.ID)); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// Status reports reverse-tunnel state using only local Iran-side information
// (no outbound): whether the forwarded port is bound, plus iptables byte counts.
func (m *ReverseManager) Status(t *store.Tunnel) Status {
	bound := allPortsBound(t.Forwards)
	var in, out uint64
	for _, f := range t.Forwards {
		i, o := iptRead(f.ListenPort)
		in += i
		out += o
	}
	st := &Stat{
		TunnelID:     t.ID,
		BytesIn:      in,
		BytesOut:     out,
		TotalWorkers: 1,
	}
	active := "inactive"
	if bound {
		active = "active"
		st.ConnectedWorkers = 1
	}
	return Status{Active: active, Enabled: t.Enabled, SubState: "", Stat: st}
}

// Logs fetches the connector journal from kharej (requires Iran->kharej SSH).
func (m *ReverseManager) Logs(t *store.Tunnel, n int) (string, error) {
	client, err := m.dialKharej(t)
	if err != nil {
		return "", err
	}
	defer client.Close()
	return sshx.RunCommand(client, fmt.Sprintf("journalctl -u %s -n %d --no-pager -o short-iso", revUnitName(t.ID), n))
}

func (m *ReverseManager) dialKharej(t *store.Tunnel) (*ssh.Client, error) {
	cfg, err := sshx.BuildClientConfig(sshx.ClientConfigOptions{
		User:       t.Username,
		PrivatePEM: t.PrivateKey,
		Cipher:     t.Cipher,
		HostKey:    t.HostKey,
	})
	if err != nil {
		return nil, err
	}
	return sshx.Dial(t.RemoteHost, t.RemotePort, cfg)
}

// ---- Iran-side helpers ----

func (m *ReverseManager) ensureIranAuthorizedKey(t *store.Tunnel) error {
	pub, err := sshx.PublicFromPrivate(t.ReverseKey)
	if err != nil {
		return err
	}
	path := iranAuthKeysPath(tIranUser(t))
	dir := path[:strings.LastIndex(path, "/")]
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), pub) {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line := pub + " sshtunnel-reverse-" + t.ID + "\n"
	_, err = f.WriteString(line)
	return err
}

func (m *ReverseManager) removeIranAuthorizedKey(t *store.Tunnel) {
	path := iranAuthKeysPath(tIranUser(t))
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var kept []string
	for _, ln := range strings.Split(string(data), "\n") {
		if ln == "" || strings.Contains(ln, "sshtunnel-reverse-"+t.ID) {
			continue
		}
		kept = append(kept, ln)
	}
	_ = os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600)
}

func iranAuthKeysPath(user string) string {
	if user == "" || user == "root" {
		return "/root/.ssh/authorized_keys"
	}
	return "/home/" + user + "/.ssh/authorized_keys"
}

func tIranUser(t *store.Tunnel) string {
	if t.IranUser == "" {
		return "root"
	}
	return t.IranUser
}

func tIranPort(t *store.Tunnel) int {
	if t.IranSSHPort <= 0 {
		return 22
	}
	return t.IranSSHPort
}

// ---- GatewayPorts (so `ssh -R 0.0.0.0:...` can bind publicly on Iran) ----

const gatewayDropIn = "/etc/ssh/sshd_config.d/sshtunnel-gatewayports.conf"

func ensureGatewayPorts() error {
	// Already effective? then nothing to do.
	if gatewayPortsEffective() {
		return nil
	}
	_ = os.WriteFile(gatewayDropIn, []byte("GatewayPorts clientspecified\n"), 0o644)
	reloadSSHD()
	if gatewayPortsEffective() {
		return nil
	}
	// Drop-in not honoured (no Include): append to main config once.
	main := "/etc/ssh/sshd_config"
	data, _ := os.ReadFile(main)
	if !strings.Contains(string(data), "sshtunnel-gatewayports") {
		f, err := os.OpenFile(main, os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			_, _ = f.WriteString("\n# sshtunnel-gatewayports\nGatewayPorts clientspecified\n")
			f.Close()
		}
	}
	reloadSSHD()
	if !gatewayPortsEffective() {
		return fmt.Errorf("could not enable GatewayPorts on sshd")
	}
	return nil
}

func gatewayPortsEffective() bool {
	out, _ := exec.Command("sshd", "-T").CombinedOutput()
	if len(out) == 0 {
		out, _ = exec.Command("/usr/sbin/sshd", "-T").CombinedOutput()
	}
	s := strings.ToLower(string(out))
	return strings.Contains(s, "gatewayports clientspecified") || strings.Contains(s, "gatewayports yes")
}

func reloadSSHD() {
	if err := exec.Command("systemctl", "reload", "ssh").Run(); err != nil {
		_ = exec.Command("systemctl", "reload", "sshd").Run()
	}
}

// ---- port-bound check (proxy for "kharej is connected") ----

func allPortsBound(forwards []store.Forward) bool {
	if len(forwards) == 0 {
		return false
	}
	out, _ := exec.Command("ss", "-ltnH").CombinedOutput()
	listing := string(out)
	for _, f := range forwards {
		if !strings.Contains(listing, fmt.Sprintf(":%d ", f.ListenPort)) {
			return false
		}
	}
	return true
}

// ---- iptables byte accounting per listen port ----

func iptChains(port int) (in, out string) {
	return fmt.Sprintf("SSHTP_%d_IN", port), fmt.Sprintf("SSHTP_%d_OUT", port)
}

func iptEnsure(port int) {
	if _, err := exec.LookPath("iptables"); err != nil {
		return
	}
	cin, cout := iptChains(port)
	run := func(args ...string) { _ = exec.Command("iptables", args...).Run() }
	// IN chain: counts client -> Iran (dport)
	run("-N", cin)
	if exec.Command("iptables", "-C", cin, "-j", "RETURN").Run() != nil {
		run("-A", cin, "-j", "RETURN")
	}
	if exec.Command("iptables", "-C", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", cin).Run() != nil {
		run("-I", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", cin)
	}
	// OUT chain: counts Iran -> client (sport)
	run("-N", cout)
	if exec.Command("iptables", "-C", cout, "-j", "RETURN").Run() != nil {
		run("-A", cout, "-j", "RETURN")
	}
	if exec.Command("iptables", "-C", "OUTPUT", "-p", "tcp", "--sport", fmt.Sprintf("%d", port), "-j", cout).Run() != nil {
		run("-I", "OUTPUT", "-p", "tcp", "--sport", fmt.Sprintf("%d", port), "-j", cout)
	}
}

func iptRead(port int) (in, out uint64) {
	cin, cout := iptChains(port)
	return iptChainBytes(cin), iptChainBytes(cout)
}

func iptChainBytes(chain string) uint64 {
	out, err := exec.Command("iptables", "-nvxL", chain).CombinedOutput()
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(out), "\n") {
		if strings.Contains(ln, "RETURN") {
			fields := strings.Fields(ln)
			if len(fields) >= 2 {
				var b uint64
				fmt.Sscanf(fields[1], "%d", &b)
				return b
			}
		}
	}
	return 0
}

func iptRemove(port int) {
	if _, err := exec.LookPath("iptables"); err != nil {
		return
	}
	cin, cout := iptChains(port)
	p := fmt.Sprintf("%d", port)
	_ = exec.Command("iptables", "-D", "INPUT", "-p", "tcp", "--dport", p, "-j", cin).Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", p, "-j", cout).Run()
	for _, c := range []string{cin, cout} {
		_ = exec.Command("iptables", "-F", c).Run()
		_ = exec.Command("iptables", "-X", c).Run()
	}
}
