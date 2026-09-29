// Package catalog is the registry of simulated controls. Each log source
// (Windows, Linux, Nginx, Apache) lives in its own file and registers its
// controls from an init function, so adding a source never touches this file.
package catalog

import (
	"fmt"
	"sort"

	"socbyte.ai/logsource/internal/core"
)

var (
	defs  = map[string]core.Definition{}
	order []string
)

// Register adds a definition to the catalog. It panics on a duplicate ID
// because that is a programming error, caught the first time the binary runs.
func Register(d core.Definition) {
	if d.ID == "" {
		panic("catalog: definition with empty ID")
	}
	if _, dup := defs[d.ID]; dup {
		panic(fmt.Sprintf("catalog: duplicate control ID %q", d.ID))
	}
	if d.Build == nil {
		panic(fmt.Sprintf("catalog: control %q has no Build function", d.ID))
	}
	defs[d.ID] = d
	order = append(order, d.ID)
}

// Get looks up one definition.
func Get(id string) (core.Definition, bool) {
	d, ok := defs[id]
	return d, ok
}

// Controls returns the metadata for every registered control, sorted by source
// then group then name so the UI renders in a stable order.
func Controls() []core.Control {
	out := make([]core.Control, 0, len(defs))
	for _, id := range order {
		out = append(out, defs[id].Control)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return sourceRank(out[i].Source) < sourceRank(out[j].Source)
		}
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Count reports how many controls are registered.
func Count() int { return len(defs) }

func sourceRank(s string) int {
	switch s {
	case core.SourceWindows:
		return 1
	case core.SourceLinux:
		return 2
	case core.SourceNginx:
		return 3
	case core.SourceApache:
		return 4
	default:
		return 9
	}
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

// A single built-in control so the transport can be exercised end to end before
// any log source is wired up.
func init() {
	Register(core.Definition{
		Control: core.Control{
			ID:       "diag-heartbeat",
			Source:   "diagnostics",
			Group:    "Diagnostics",
			Name:     "Connectivity heartbeat",
			Desc:     "A plain syslog message used to confirm the target SIEM is receiving traffic from this host.",
			Severity: core.SevLabelInfo,
			Params: []core.Param{
				{Key: "note", Label: "Note", Placeholder: "free text carried in the message"},
			},
		},
		Build: func(c *core.Ctx) core.Payload {
			note := c.P("note", "logsource connectivity test")
			return core.Payload{
				Kind:     "diagnostics",
				Tag:      "logsource",
				PID:      c.PID(),
				Host:     c.Env.LinuxHost,
				Facility: core.FacLocal0,
				Severity: core.SevInfo,
				Message:  fmt.Sprintf("heartbeat: %s", note),
			}
		},
	})
}
