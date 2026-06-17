package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sshtunnel-panel/internal/config"
	"sshtunnel-panel/internal/store"
	"sshtunnel-panel/internal/tunnel"
	"sshtunnel-panel/internal/web"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		serve(os.Args[1:])
		return
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "run-tunnel":
		runTunnel(os.Args[2:])
	case "admin":
		admin(os.Args[2:])
	case "node-token":
		nodeToken(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		serve(os.Args[1:])
	}
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.Parse(args)

	cfg, err := config.Load()
	must(err)
	st, err := store.Open(cfg.StorePath())
	must(err)

	exe, err := os.Executable()
	must(err)
	mgr := tunnel.NewManager(cfg, exe)

	if cfg.MasterEnabled {
		web.EnsureLocalNode(cfg, st)
	}

	web.Version = version
	handler, err := web.New(cfg, st, mgr)
	must(err)

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	logURL(cfg)
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Fatal(srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey))
	} else {
		log.Fatal(srv.ListenAndServe())
	}
}

func runTunnel(args []string) {
	fs := flag.NewFlagSet("run-tunnel", flag.ExitOnError)
	id := fs.String("id", "", "tunnel id")
	fs.Parse(args)
	if *id == "" {
		log.Fatal("run-tunnel: --id is required")
	}
	cfg, err := config.Load()
	must(err)
	r, err := tunnel.NewRunner(cfg, *id)
	must(err)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	log.Printf("starting tunnel %s", *id)
	if err := r.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

// admin sets credentials / listen / base path from the CLI (used by install.sh).
func admin(args []string) {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	user := fs.String("username", "", "admin username")
	pass := fs.String("password", "", "admin password (random if empty and creating)")
	listen := fs.String("listen", "", "listen address, e.g. 0.0.0.0:2095")
	basePath := fs.String("path", "", "web base path")
	randomPath := fs.Bool("random-path", false, "generate a random web path")
	master := fs.String("master", "", "set central master mode: 'on' or 'off'")
	showOnly := fs.Bool("show", false, "only print current access info")
	fs.Parse(args)

	cfg, err := config.Load()
	must(err)
	st, err := store.Open(cfg.StorePath())
	must(err)

	if *showOnly {
		logURL(cfg)
		fmt.Printf("Username: %s\n", st.AdminUsername())
		return
	}

	if *listen != "" {
		cfg.Listen = *listen
	}
	switch *master {
	case "on", "true", "1":
		cfg.MasterEnabled = true
	case "off", "false", "0":
		cfg.MasterEnabled = false
	}
	if *randomPath {
		cfg.BasePath = config.NormalizeBasePath(randToken(8))
	} else if *basePath != "" {
		cfg.BasePath = config.NormalizeBasePath(*basePath)
	}
	must(cfg.Save())

	u := *user
	if u == "" {
		u = st.AdminUsername()
	}
	if u == "" {
		u = "admin"
	}
	p := *pass
	if p == "" {
		if st.AdminUsername() == "" {
			p = randToken(8) // first-time random password
		}
	}
	if p != "" {
		must(st.SetUser(u, p))
		fmt.Println("===========================================")
		fmt.Println(" SSH Tunnel Panel credentials")
		fmt.Printf(" Username: %s\n", u)
		fmt.Printf(" Password: %s\n", p)
		fmt.Println("===========================================")
	}
	logURL(cfg)
}

// nodeToken prints (or regenerates) this node's bearer token, used when
// registering the server on a central master panel.
func nodeToken(args []string) {
	fs := flag.NewFlagSet("node-token", flag.ExitOnError)
	regen := fs.Bool("regenerate", false, "generate a new token (invalidates the old one)")
	fs.Parse(args)
	cfg, err := config.Load()
	must(err)
	if *regen {
		cfg.NodeToken = randToken(24)
		must(cfg.Save())
	}
	fmt.Println(cfg.NodeToken)
}

func logURL(cfg *config.Config) {
	scheme := "http"
	if cfg.TLSCert != "" {
		scheme = "https"
	}
	log.Printf("Panel URL: %s://<server-ip>%s -> listen %s, path %q",
		scheme, cfg.BasePath, cfg.Listen, cfg.BasePath)
}

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
