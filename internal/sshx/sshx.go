package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// SupportedCiphers maps the panel's friendly cipher choices. The empty value
// means "use the SSH library default set".
var SupportedCiphers = []string{
	"aes128-gcm@openssh.com",
	"aes256-gcm@openssh.com",
	"chacha20-poly1305@openssh.com",
	"aes128-ctr",
	"aes192-ctr",
	"aes256-ctr",
}

// KeyPair holds a generated ed25519 key in OpenSSH-compatible encodings.
type KeyPair struct {
	PrivatePEM     string // PEM, usable by ssh.ParsePrivateKey
	AuthorizedLine string // "ssh-ed25519 AAAA... comment"
}

// GenerateKey creates a new ed25519 key pair.
func GenerateKey(comment string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	authLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		authLine += " " + comment
	}
	return &KeyPair{
		PrivatePEM:     string(pem.EncodeToMemory(block)),
		AuthorizedLine: authLine,
	}, nil
}

// ClientConfigOptions configure a connection to the remote server.
type ClientConfigOptions struct {
	User        string
	Password    string // when using password auth
	PrivatePEM  string // when using key auth
	Cipher      string // optional single cipher; "" => library default
	HostKey     string // pinned authorized_keys line; "" => accept & capture (TOFU)
	Timeout     time.Duration
	OnHostKey   func(line string) // called with captured host key when HostKey == ""
}

// BuildClientConfig assembles an *ssh.ClientConfig from options.
func BuildClientConfig(o ClientConfigOptions) (*ssh.ClientConfig, error) {
	var auths []ssh.AuthMethod
	if o.PrivatePEM != "" {
		signer, err := ssh.ParsePrivateKey([]byte(o.PrivatePEM))
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if o.Password != "" {
		auths = append(auths, ssh.Password(o.Password))
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("no authentication method provided")
	}

	cfg := &ssh.ClientConfig{
		User:    o.User,
		Auth:    auths,
		Timeout: o.Timeout,
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if o.Cipher != "" {
		cfg.Config.Ciphers = []string{o.Cipher}
	}

	if o.HostKey != "" {
		pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(o.HostKey))
		if err != nil {
			return nil, fmt.Errorf("parse pinned host key: %w", err)
		}
		cfg.HostKeyCallback = ssh.FixedHostKey(pinned)
	} else {
		// Trust-on-first-use: accept and report the key so the caller can pin it.
		cfg.HostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if o.OnHostKey != nil {
				o.OnHostKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
			}
			return nil
		}
	}
	return cfg, nil
}

// Dial connects to host:port using the given config.
func Dial(host string, port int, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	return ssh.Dial("tcp", addr, cfg)
}

// SocketControl matches net.Dialer.Control: a hook to tune the raw fd before
// connect (set SO_SNDBUF/SO_RCVBUF, TCP_MAXSEG, TCP_NODELAY, …).
type SocketControl func(network, address string, c syscall.RawConn) error

// DialWithControl dials the SSH transport TCP socket through a custom dialer so
// socket options can be applied to the long-haul (Iran<->kharej) connection,
// then performs the SSH handshake over it.
func DialWithControl(host string, port int, cfg *ssh.ClientConfig, control SocketControl) (*ssh.Client, error) {
	if control == nil {
		return Dial(host, port, cfg)
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: cfg.Timeout, Control: control}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// InstallKey appends the public key to the remote ~/.ssh/authorized_keys,
// mirroring `ssh-copy-id`. It returns the captured host key for pinning.
func InstallKey(host string, port int, user, password, authorizedLine string) (hostKey string, err error) {
	cfg, err := BuildClientConfig(ClientConfigOptions{
		User:      user,
		Password:  password,
		OnHostKey: func(line string) { hostKey = line },
	})
	if err != nil {
		return "", err
	}
	client, err := Dial(host, port, cfg)
	if err != nil {
		return "", fmt.Errorf("connect with password: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	// Safe append: create ~/.ssh, fix perms, avoid duplicate lines.
	cmd := fmt.Sprintf(
		`umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && `+
			`grep -qxF %s ~/.ssh/authorized_keys || echo %s >> ~/.ssh/authorized_keys`,
		shellQuote(authorizedLine), shellQuote(authorizedLine),
	)
	if out, err := sess.CombinedOutput(cmd); err != nil {
		return "", fmt.Errorf("install key: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return hostKey, nil
}

// TestConnection verifies that key auth works and captures the host key if needed.
func TestConnection(o ClientConfigOptions, host string, port int) (hostKey string, err error) {
	captured := o.HostKey
	o.OnHostKey = func(line string) { captured = line }
	cfg, err := BuildClientConfig(o)
	if err != nil {
		return "", err
	}
	client, err := Dial(host, port, cfg)
	if err != nil {
		return "", err
	}
	client.Close()
	return captured, nil
}

// RunCommand runs a command on the remote host and returns combined output.
func RunCommand(c *ssh.Client, cmd string) (string, error) {
	s, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	out, err := s.CombinedOutput(cmd)
	return string(out), err
}

// WriteRemoteFile writes content to a remote path (creating parent dirs) and
// applies the given chmod mode (e.g. "600").
func WriteRemoteFile(c *ssh.Client, path, content, mode string) error {
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	s.Stdin = strings.NewReader(content)
	dir := path[:strings.LastIndex(path, "/")]
	cmd := fmt.Sprintf("mkdir -p %s && cat > %s && chmod %s %s",
		shellQuote(dir), shellQuote(path), mode, shellQuote(path))
	if out, err := combinedRun(s, cmd); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func combinedRun(s *ssh.Session, cmd string) (string, error) {
	out, err := s.Output(cmd)
	return string(out), err
}

// PublicFromPrivate derives the authorized_keys line from a private key PEM.
func PublicFromPrivate(privatePEM string) (string, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privatePEM))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
