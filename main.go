// Command loggen is a log simulation lab: it generates correctly structured
// records for common log sources and ships them to a SIEM over syslog, so
// parsers, decoders and detection rules can be exercised without a real estate.
package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/catalog"
	"github.com/theshahrukh98khan/LogGen/internal/server"
	"github.com/theshahrukh98khan/LogGen/internal/sink"
	"github.com/theshahrukh98khan/LogGen/internal/store"
)

//go:embed all:web
var embeddedWeb embed.FS

func main() {
	addr := flag.String("addr", "0.0.0.0:8088", "address for the operator console")
	data := flag.String("data", "data", "directory holding profiles.json")
	open := flag.Bool("open", true, "open the console in a browser on start")
	sinkAddr := flag.String("sink", "", "run a syslog receiver on this address instead of the console, e.g. :5514")
	flag.Parse()

	log.SetFlags(log.Ltime)

	// Sink mode turns the same binary into a local collector, so the pipeline
	// can be verified without pointing at a live Wazuh manager.
	if *sinkAddr != "" {
		if err := sink.Run(*sinkAddr); err != nil {
			log.Fatalf("sink: %v", err)
		}
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

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(st, webRoot).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	local, urls := consoleURLs(*addr)
	log.Printf("%d control(s) registered", catalog.Count())
	if def, err := st.Default(); err == nil {
		log.Printf("default target: %s://%s (%s)", def.Protocol, def.Addr(), def.Name)
	}
	log.Print("LogGen console reachable at:")
	for _, u := range urls {
		log.Printf("    %s", u)
	}
	if isWildcard(*addr) {
		log.Print("console is bound to all interfaces and has no authentication — keep it on the lab network")
	}

	if *open {
		go launchBrowser(local)
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
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

	// A wildcard bind answers on every interface, but only the routable
	// addresses are useful to somebody on another host.
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return local, all
	}
	for _, a := range ifaces {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		all = append(all, "http://"+net.JoinHostPort(ipnet.IP.String(), port)+"  (network)")
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
