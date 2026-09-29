// Package server exposes the HTTP API and serves the operator console.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/catalog"
	"github.com/theshahrukh98khan/LogGen/internal/core"
	"github.com/theshahrukh98khan/LogGen/internal/sender"
	"github.com/theshahrukh98khan/LogGen/internal/store"
)

// maxBurst caps how many records a single request may emit, so a stray zero in
// the UI cannot flood the SIEM.
const maxBurst = 500

// activityCap is the size of the in-memory send history.
const activityCap = 400

// Server wires the store, the catalog and the web console together.
type Server struct {
	// Version is reported by the console's About page. Set by main after New.
	Version string

	st  *store.Store
	web fs.FS

	mu     sync.Mutex
	recent []core.Activity
	seq    uint64
}

// New builds a server. webFS should contain index.html at its root.
func New(st *store.Store, webFS fs.FS) *Server {
	return &Server{st: st, web: webFS}
}

// Handler returns the fully routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("GET /api/controls", s.handleControls)
	mux.HandleFunc("GET /api/activity", s.handleActivity)

	mux.HandleFunc("PUT /api/env", s.handleSetEnv)

	mux.HandleFunc("GET /api/profiles", s.handleListProfiles)
	mux.HandleFunc("POST /api/profiles", s.handleCreateProfile)
	mux.HandleFunc("PUT /api/profiles/{id}", s.handleUpdateProfile)
	mux.HandleFunc("DELETE /api/profiles/{id}", s.handleDeleteProfile)
	mux.HandleFunc("POST /api/profiles/{id}/default", s.handleSetDefault)
	mux.HandleFunc("POST /api/profiles/{id}/test", s.handleTestProfile)

	mux.HandleFunc("GET /api/customs", s.handleListCustoms)
	mux.HandleFunc("POST /api/customs", s.handleCreateCustom)
	mux.HandleFunc("PUT /api/customs/{id}", s.handleUpdateCustom)
	mux.HandleFunc("DELETE /api/customs/{id}", s.handleDeleteCustom)
	mux.HandleFunc("POST /api/preview-custom", s.handlePreviewCustom)
	mux.HandleFunc("GET /api/sources", s.handleSources)
	mux.HandleFunc("GET /api/placeholders", s.handlePlaceholders)

	mux.HandleFunc("POST /api/preview", s.handlePreview)
	mux.HandleFunc("POST /api/send", s.handleSend)

	mux.Handle("/", noStore(http.FileServer(http.FS(s.web))))

	return logRequests(mux)
}

// noStore stops browsers caching the console.
//
// Embedded files carry a zero modification time, so the usual validators are
// useless: after upgrading LogGen a browser will happily keep serving the
// previous build's CSS and JavaScript against the new binary. The console is
// served from localhost and weighs a few kilobytes, so revalidating every time
// costs nothing and removes a confusing class of stale-asset bug.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Read handlers
// ---------------------------------------------------------------------------

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"env":      s.st.Env(),
		"profiles": s.st.Profiles(),
		"controls": s.allControls(),
		"customs":  s.st.Customs(),
		"sources":  s.sources(),
		"version":  s.Version,
		"dataDir":  s.st.Path(),
	})
}

func (s *Server) handleControls(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.allControls())
}

// allControls merges the compiled-in catalog with the operator's own controls.
func (s *Server) allControls() []core.Control {
	built := catalog.Controls()
	customs := s.st.Customs()

	out := make([]core.Control, 0, len(built)+len(customs))
	out = append(out, built...)
	for _, c := range customs {
		out = append(out, c.Control())
	}
	return out
}

// resolve finds a control by ID, looking at the compiled-in catalog first so a
// custom control can never shadow a built-in one.
func (s *Server) resolve(id string) (core.Definition, bool) {
	if def, ok := catalog.Get(id); ok {
		return def, true
	}
	if cc, err := s.st.Custom(id); err == nil {
		return core.Definition{Control: cc.Control(), Build: cc.Build}, true
	}
	return core.Definition{}, false
}

// sources lists every source that has at least one control, so the console can
// offer them and the admin form can add to an existing one.
func (s *Server) sources() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range s.allControls() {
		if !seen[c.Source] {
			seen[c.Source] = true
			out = append(out, c.Source)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.activity())
}

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.st.Profiles())
}

// ---------------------------------------------------------------------------
// Configuration handlers
// ---------------------------------------------------------------------------

func (s *Server) handleSetEnv(w http.ResponseWriter, r *http.Request) {
	var env core.Env
	if !decode(w, r, &env) {
		return
	}
	saved, err := s.st.SetEnv(env)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var p core.Profile
	if !decode(w, r, &p) {
		return
	}
	saved, err := s.st.Create(p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	var p core.Profile
	if !decode(w, r, &p) {
		return
	}
	saved, err := s.st.Update(r.PathValue("id"), p)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.st.Delete(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSetDefault(w http.ResponseWriter, r *http.Request) {
	if err := s.st.SetDefault(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.st.Profiles())
}

// handleTestProfile checks a destination without sending a record.
//
// Resolution is checked before dialling, because a name that does not resolve
// and a port nothing is listening on are different problems with different
// fixes, and telling somebody to check their firewall when DNS is the fault
// sends them the wrong way.
func (s *Server) handleTestProfile(w http.ResponseWriter, r *http.Request) {
	p, err := s.st.Profile(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}

	target := p.Protocol + "://" + p.Addr()
	res := sender.Resolve(p)

	if res.Failed {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       false,
			"stage":    "resolve",
			"target":   target,
			"resolved": res,
			"error": fmt.Sprintf("%q does not resolve. Check the name, or use an IP address.",
				res.Host),
			"detail": res.Message,
		})
		return
	}

	if err := sender.Probe(p); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       false,
			"stage":    "connect",
			"target":   target,
			"resolved": res,
			"reason":   string(sender.Classify(err)),
			"error":    err.Error(),
		})
		return
	}

	note := "Connected."
	if p.Protocol == core.ProtoUDP {
		note = "Socket opened. UDP is connectionless, so this does not prove the SIEM is listening — send a heartbeat and confirm it arrives."
	}
	// With a named destination, say what it resolved to: a stale record or an
	// unexpected address is invisible otherwise.
	if !res.IsIP && len(res.Addrs) > 0 {
		note += " " + res.Host + " resolves to " + strings.Join(res.Addrs, ", ") + "."
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"stage":    "connect",
		"target":   target,
		"resolved": res,
		"note":     note,
	})
}

// ---------------------------------------------------------------------------
// Simulation handlers
// ---------------------------------------------------------------------------

type simRequest struct {
	ControlID string            `json:"controlId"`
	ProfileID string            `json:"profileId"`
	Params    map[string]string `json:"params"`
	Count     int               `json:"count"`
	DelayMS   int               `json:"delayMs"`
}

// handlePreview renders a control without sending it.
func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	var req simRequest
	if !decode(w, r, &req) {
		return
	}
	def, ok := s.resolve(req.ControlID)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown control %q", req.ControlID))
		return
	}
	profile, err := s.st.Resolve(req.ProfileID)
	if err != nil {
		writeStoreErr(w, err)
		return
	}

	now := time.Now()
	payload := def.Build(core.NewCtx(s.st.Env(), req.Params))
	writeJSON(w, http.StatusOK, map[string]any{
		"control": def.Control,
		"target":  profile.Protocol + "://" + profile.Addr(),
		"wire":    sender.Encode(payload, profile, now),
		"body":    payload.Message,
	})
}

// handleSend renders a control and ships it to the target.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	var req simRequest
	if !decode(w, r, &req) {
		return
	}
	def, ok := s.resolve(req.ControlID)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown control %q", req.ControlID))
		return
	}
	profile, err := s.st.Resolve(req.ProfileID)
	if err != nil {
		writeStoreErr(w, err)
		return
	}

	count := req.Count
	if count < 1 {
		count = 1
	}
	if count > maxBurst {
		count = maxBurst
	}

	// A single record is sent inline so the console gets an immediate verdict.
	// Bursts run in the background and surface through the activity feed.
	if count == 1 {
		act := s.emit(def, profile, req.Params)
		status := http.StatusOK
		if !act.OK {
			status = http.StatusBadGateway
		}
		writeJSON(w, status, act)
		return
	}

	go s.burst(def, profile, req.Params, count, req.DelayMS)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"queued":  count,
		"control": def.Name,
		"target":  profile.Protocol + "://" + profile.Addr(),
	})
}

// emit renders and sends one record, recording the outcome.
func (s *Server) emit(def core.Definition, p core.Profile, params map[string]string) core.Activity {
	now := time.Now()
	payload := def.Build(core.NewCtx(s.st.Env(), params))
	wire := sender.Encode(payload, p, now)

	act := core.Activity{
		Time:      now,
		ControlID: def.ID,
		Control:   def.Name,
		Source:    def.Source,
		Profile:   p.Name,
		Target:    p.Protocol + "://" + p.Addr(),
		Wire:      wire,
	}
	n, err := sender.SendOne(p, wire)
	if err != nil {
		act.Error = err.Error()
	} else {
		act.OK = true
		act.Bytes = n
	}
	return s.record(act)
}

// burst reuses one connection for the whole run, which matters for TCP.
func (s *Server) burst(def core.Definition, p core.Profile, params map[string]string, count, delayMS int) {
	conn, err := sender.Open(p)
	if err != nil {
		s.record(core.Activity{
			Time:      time.Now(),
			ControlID: def.ID,
			Control:   def.Name,
			Source:    def.Source,
			Profile:   p.Name,
			Target:    p.Protocol + "://" + p.Addr(),
			Error:     err.Error(),
		})
		return
	}
	defer conn.Close()

	if delayMS < 0 {
		delayMS = 0
	}
	for i := 0; i < count; i++ {
		now := time.Now()
		// Rebuild per iteration so each record gets fresh randomised fields.
		payload := def.Build(core.NewCtx(s.st.Env(), params))
		wire := sender.Encode(payload, p, now)

		act := core.Activity{
			Time:      now,
			ControlID: def.ID,
			Control:   fmt.Sprintf("%s (%d/%d)", def.Name, i+1, count),
			Source:    def.Source,
			Profile:   p.Name,
			Target:    p.Protocol + "://" + p.Addr(),
			Wire:      wire,
		}
		n, werr := conn.Write(wire)
		if werr != nil {
			act.Error = werr.Error()
			s.record(act)
			return // the connection is broken; stop rather than spin
		}
		act.OK = true
		act.Bytes = n
		s.record(act)

		if delayMS > 0 && i < count-1 {
			time.Sleep(time.Duration(delayMS) * time.Millisecond)
		}
	}
}

// ---------------------------------------------------------------------------
// Custom controls
// ---------------------------------------------------------------------------

func (s *Server) handleListCustoms(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.st.Customs())
}

// handlePreviewCustom renders a custom control that has not been saved, so the
// operator can see the real wire format before committing it.
func (s *Server) handlePreviewCustom(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Control   core.CustomControl `json:"control"`
		ProfileID string             `json:"profileId"`
		Params    map[string]string  `json:"params"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Control.Template) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("template is required"))
		return
	}

	profile, err := s.st.Resolve(req.ProfileID)
	if err != nil {
		writeStoreErr(w, err)
		return
	}

	cc := req.Control.Normalize()
	payload := cc.Build(core.NewCtx(s.st.Env(), req.Params))
	writeJSON(w, http.StatusOK, map[string]any{
		"wire": sender.Encode(payload, profile, time.Now()),
		"body": payload.Message,
	})
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.sources())
}

func (s *Server) handlePlaceholders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, core.Placeholders())
}

// builtinIDs is the set of compiled-in control IDs, which custom controls are
// not allowed to reuse.
func builtinIDs() map[string]bool {
	out := map[string]bool{}
	for _, c := range catalog.Controls() {
		out[c.ID] = true
	}
	return out
}

func (s *Server) handleCreateCustom(w http.ResponseWriter, r *http.Request) {
	var cc core.CustomControl
	if !decode(w, r, &cc) {
		return
	}
	if strings.TrimSpace(cc.Template) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("template is required"))
		return
	}
	saved, err := s.st.CreateCustom(cc, builtinIDs())
	if err != nil {
		if errors.Is(err, store.ErrDuplicateID) {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleUpdateCustom(w http.ResponseWriter, r *http.Request) {
	var cc core.CustomControl
	if !decode(w, r, &cc) {
		return
	}
	if strings.TrimSpace(cc.Template) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("template is required"))
		return
	}
	saved, err := s.st.UpdateCustom(r.PathValue("id"), cc)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteCustom(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteCustom(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------
// Activity ring buffer
// ---------------------------------------------------------------------------

// record stamps an entry with the next sequence number, stores it, and returns
// the stored form.
//
// It returns the entry rather than mutating the caller's copy because the
// caller needs the sequence too: a send response that reported seq 0 while the
// feed showed the real number made the two impossible to correlate.
func (s *Server) record(a core.Activity) core.Activity {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	a.Seq = s.seq
	s.recent = append(s.recent, a)
	if len(s.recent) > activityCap {
		s.recent = s.recent[len(s.recent)-activityCap:]
	}
	return a
}

// activity returns the history newest first.
func (s *Server) activity() []core.Activity {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]core.Activity, len(s.recent))
	for i, a := range s.recent {
		out[len(s.recent)-1-i] = a
	}
	return out
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"error": err.Error()})
}

func writeStoreErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeErr(w, http.StatusBadRequest, err)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			log.Printf("%s %s", r.Method, r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}
