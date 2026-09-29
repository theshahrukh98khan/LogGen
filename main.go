// Command logsource is a log simulation lab: it generates correctly structured
// records for common log sources and ships them to a SIEM over syslog, so
// parsers, decoders and detection rules can be exercised without a real estate.
package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"socbyte.ai/logsource/internal/catalog"
	"socbyte.ai/logsource/internal/server"
	"socbyte.ai/logsource/internal/sink"
	"socbyte.ai/logsource/internal/store"
)

//go:embed all:web
var embeddedWeb embed.FS

func main() {
	addr := flag.String("addr", "127.0.0.1:8088", "address for the operator console")
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

	url := "http://" + *addr
	log.Printf("LogSource console: %s", url)
	log.Printf("%d control(s) registered", catalog.Count())
	if def, err := st.Default(); err == nil {
		log.Printf("default target: %s://%s (%s)", def.Protocol, def.Addr(), def.Name)
	}

	if *open {
		go launchBrowser(url)
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
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
