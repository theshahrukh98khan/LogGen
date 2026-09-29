// Command loggen is a log simulation lab: it generates correctly structured
// records for common log sources and ships them to a SIEM over syslog, so
// parsers, decoders and detection rules can be exercised without a real estate.
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/auth"
	"github.com/theshahrukh98khan/LogGen/internal/catalog"
	"github.com/theshahrukh98khan/LogGen/internal/server"
	"github.com/theshahrukh98khan/LogGen/internal/sink"
	"github.com/theshahrukh98khan/LogGen/internal/store"
)

//go:embed all:web
var embeddedWeb embed.FS

// version is stamped at build time with -ldflags "-X main.version=v1.2.3".
// Left unset, it is read back from the build info, so a `go install` still
// reports something useful.
var version = ""

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				return s.Value[:7]
			}
		}
	}
	return "dev"
}

func main() {
	addr := flag.String("addr", "0.0.0.0:8088", "address for the operator console")
	data := flag.String("data", "data", "directory holding profiles.json")
	open := flag.Bool("open", true, "open the console in a browser on start")
	sinkAddr := flag.String("sink", "", "run a syslog receiver on this address instead of the console, e.g. :5514")
	resetAuth := flag.Bool("reset-auth", false, "reset the console sign-in to admin/admin and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("loggen %s  %s/%s  %s\n",
			buildVersion(), runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	log.SetFlags(log.Ltime)
	// Go's log package writes to stderr by default, which means "loggen > file"
	// captures nothing. What this prints is a startup banner and a request log,
	// not errors, so it belongs on stdout where redirecting it works.
	log.SetOutput(os.Stdout)

	// Sink mode turns the same binary into a local collector, so the pipeline
	// can be verified without pointing at a live Wazuh manager.
	if *sinkAddr != "" {
		if err := sink.Run(*sinkAddr); err != nil {
			log.Fatalf("sink: %v", err)
		}
		return
	}

	// Credentials live in their own file, written owner-only.
	creds, err := auth.Open(filepath.Join(*data, "auth.json"))
	if err != nil {
		log.Fatalf("open credentials: %v", err)
	}

	// The way back in from a forgotten password when no mail server is
	// configured. It needs a shell on the host, which is a higher bar than
	// knowing the password, so it is not a way around the sign-in.
	if *resetAuth {
		if err := creds.Reset(); err != nil {
			log.Fatalf("reset credentials: %v", err)
		}
		fmt.Printf("Sign-in reset to %s / %s. Change it after signing in.\n",
			auth.DefaultUser, auth.DefaultPassword)
		return
	}

	st, err := store.Open(filepath.Join(*data, "profiles.json"))
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	webRoot, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		log.Fatalf("mount web assets: %v", err)
	}

	console := server.New(st, webRoot, creds)
	console.Version = buildVersion()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           console.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	local, urls := consoleURLs(*addr)
	log.Printf("LogGen %s", buildVersion())
	log.Printf("%d control(s) registered", catalog.Count())
	if def, err := st.Default(); err == nil {
		log.Printf("default target: %s://%s (%s)", def.Protocol, def.Addr(), def.Name)
	}
	log.Print("LogGen console reachable at:")
	for _, u := range urls {
		log.Printf("    %s", u)
	}
	if creds.Config().Pristine {
		log.Print("sign in with admin / admin, then change it in Administration > Sign-in")
	}
	if isWildcard(*addr) {
		log.Print("console is bound to all interfaces and served over plain HTTP; keep it on the lab network")
	}

	if *open {
		go launchBrowser(local)
	}

	// Serve until interrupted, then let in-flight requests finish. Without this
	// a Ctrl+C during a burst kills the process mid-write, and the operator is
	// left wondering whether the last records went out.
	serveErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		log.Fatalf("serve: %v", err)
	case <-stop:
		log.Print("shutting down")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("some requests were still running at shutdown: %v", err)
	}
}

// isWildcard reports whether the listen address covers every interface.
func isWildcard(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return host == "" || host == "0.0.0.0" || host == "::"
}

// consoleURLs returns the address to open locally plus every URL the console
// can be reached on, so a browser on another machine has something to type.
func consoleURLs(addr string) (local string, all []string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr, []string{"http://" + addr}
	}

	if !isWildcard(addr) {
		u := "http://" + net.JoinHostPort(host, port)
		return u, []string{u}
	}

	local = "http://" + net.JoinHostPort("127.0.0.1", port)
	all = append(all, local+"  (this machine)")

	// A wildcard bind answers on every interface, but most of them are no use
	// to somebody on another host. Machines commonly carry a pile of virtual
	// and disconnected adapters, and listing them all buries the one address
	// the operator actually wants to type.
	ifaces, err := net.Interfaces()
	if err != nil {
		return local, all
	}
	for _, iface := range ifaces {
		// Skip anything that is down or is the loopback device.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			// IPv4 only, and skip 169.254.x.x: a link-local address means the
			// interface never got a lease, so nothing will reach it there.
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			all = append(all, "http://"+net.JoinHostPort(ip.String(), port)+
				"  ("+iface.Name+")")
		}
	}
	return local, all
}

// launchBrowser opens the console. Failure is not fatal: the URL is logged.
func launchBrowser(url string) {
	time.Sleep(300 * time.Millisecond)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("could not open a browser (%v) — visit %s", err, url)
	}
}
