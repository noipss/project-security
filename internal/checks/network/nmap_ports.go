package network

import (
	"context"
	"fmt"

	"github.com/defproj/def/internal/core"
	"github.com/defproj/def/internal/engines"
)

// NmapPorts — проверка портов через движок nmap (версии сервисов, полнее нативной).
// Требует установленного nmap; иначе оркестратор пропускает её по NeedsEngine.
type NmapPorts struct {
	Engine engines.Nmap
}

func (NmapPorts) Meta() core.CheckerMeta {
	return core.CheckerMeta{
		ID:            "network.nmap-ports",
		Module:        core.ModNetwork,
		Title:         "Порты и версии сервисов (движок nmap)",
		ActiveNetwork: true,
		NeedsEngine:   "nmap",
	}
}

func (n NmapPorts) Run(ctx context.Context, t core.Target) <-chan core.Finding {
	out := make(chan core.Finding)
	go func() {
		defer close(out)
		ports, err := n.Engine.ScanPorts(ctx, t.Host)
		if err != nil {
			return
		}
		for _, p := range ports {
			title := fmt.Sprintf("Открыт %s/%d — %s", p.Proto, p.Number, p.Service)
			if p.Version != "" {
				title += " (" + p.Version + ")"
			}
			out <- core.Finding{
				Source:   core.ModNetwork,
				RuleID:   "nmap-open-port",
				Title:    title,
				Severity: core.SevInfo,
				Location: core.Location{Host: t.Host, Port: p.Number},
				Evidence: []core.Artifact{{Kind: "banner", Data: p.Service + " " + p.Version}},
				Remediation: core.Remediation{
					Advice: "Проверьте необходимость сервиса и актуальность версии; закройте лишнее файрволом.",
				},
			}
		}
	}()
	return out
}
