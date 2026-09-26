// Package network — сетевые проверки (порты, TLS).
// Все проверки неразрушающие: только установка соединения и чтение, без нагрузок.
package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/defproj/def/internal/core"
)

// commonPorts — типовые порты для нативного connect-скана (безопасный дефолт).
// Полный диапазон и версии сервисов — задача движка nmap.
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
	587, 993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5432, 5601,
	5672, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 11211, 27017,
}

// riskyPorts — порты управляющих/чувствительных сервисов: открытость наружу
// сама по себе повод для внимания.
var riskyPorts = map[int]string{
	23: "Telnet (незашифрованный доступ)", 3389: "RDP", 5900: "VNC",
	3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 11211: "Memcached",
	27017: "MongoDB", 9200: "Elasticsearch", 2049: "NFS", 445: "SMB",
	1433: "MSSQL", 135: "MSRPC",
}

// PortScan — нативный TCP connect-скан по типовым портам.
type PortScan struct {
	Timeout time.Duration
}

func (PortScan) Meta() core.CheckerMeta {
	return core.CheckerMeta{
		ID:            "network.ports",
		Module:        core.ModNetwork,
		Title:         "Открытые TCP-порты (нативный connect-скан)",
		ActiveNetwork: true,
	}
}

func (p PortScan) Run(ctx context.Context, t core.Target) <-chan core.Finding {
	out := make(chan core.Finding)
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	go func() {
		defer close(out)
		for _, port := range commonPorts {
			select {
			case <-ctx.Done():
				return
			default:
			}
			addr := net.JoinHostPort(t.Host, strconv.Itoa(port))
			conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
			if err != nil {
				continue // порт закрыт/фильтруется — не находка
			}
			conn.Close()

			sev := core.SevInfo
			title := fmt.Sprintf("Открыт TCP-порт %d", port)
			advice := "Убедитесь, что порт должен быть доступен из этой сети; иначе закройте файрволом."
			if svc, risky := riskyPorts[port]; risky {
				sev = core.SevMedium
				title = fmt.Sprintf("Открыт чувствительный порт %d — %s", port, svc)
				advice = "Управляющий/сервисный порт не должен быть открыт в недоверенную сеть. Ограничьте доступ файрволом/VPN и включите аутентификацию."
			}
			out <- core.Finding{
				Source:      core.ModNetwork,
				RuleID:      "open-port",
				Title:       title,
				Severity:    sev,
				Location:    core.Location{Host: t.Host, Port: port},
				Evidence:    []core.Artifact{{Kind: "banner", Data: "tcp connect ok"}},
				Remediation: core.Remediation{Advice: advice},
			}
		}
	}()
	return out
}
