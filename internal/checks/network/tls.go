package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/defproj/def/internal/core"
)

// TLSCheck — инспекция TLS на 443: версия протокола, срок сертификата, соответствие имени.
// Неразрушающая: один handshake, без отправки данных.
type TLSCheck struct {
	Port    int
	Timeout time.Duration
}

func (TLSCheck) Meta() core.CheckerMeta {
	return core.CheckerMeta{
		ID:            "network.tls",
		Module:        core.ModNetwork,
		Title:         "Параметры TLS (протокол, сертификат)",
		ActiveNetwork: true,
	}
}

// tlsVersionName переводит код версии в читаемое имя.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func (c TLSCheck) Run(ctx context.Context, t core.Target) <-chan core.Finding {
	out := make(chan core.Finding)
	port := c.Port
	if port == 0 {
		port = 443
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	go func() {
		defer close(out)
		addr := net.JoinHostPort(t.Host, fmt.Sprint(port))
		dialer := &net.Dialer{Timeout: timeout}
		// InsecureSkipVerify: мы сами анализируем цепочку, а не доверяем ей.
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         t.Host,
		})
		if err != nil {
			return // нет TLS на этом порту — не находка на этом шаге
		}
		defer conn.Close()
		st := conn.ConnectionState()
		loc := core.Location{Host: t.Host, Port: port}

		// Устаревшие версии протокола.
		if st.Version < tls.VersionTLS12 {
			out <- core.Finding{
				Source:      core.ModNetwork,
				RuleID:      "tls-old-version",
				Title:       fmt.Sprintf("Устаревшая версия TLS: %s", tlsVersionName(st.Version)),
				Severity:    core.SevHigh,
				Location:    loc,
				Refs:        []string{"CWE-326"},
				Evidence:    []core.Artifact{{Kind: "banner", Data: tlsVersionName(st.Version)}},
				Remediation: core.Remediation{Advice: "Отключите TLS 1.0/1.1, оставьте TLS 1.2+ (лучше 1.3.).", AutoFixable: true},
			}
		}

		// Срок действия сертификата.
		if len(st.PeerCertificates) > 0 {
			leaf := st.PeerCertificates[0]
			now := time.Now()
			switch {
			case now.After(leaf.NotAfter):
				out <- core.Finding{
					Source:   core.ModNetwork,
					RuleID:   "tls-cert-expired",
					Title:    fmt.Sprintf("Сертификат истёк %s", leaf.NotAfter.Format("2006-01-02")),
					Severity: core.SevHigh,
					Location: loc,
					Remediation: core.Remediation{Advice: "Перевыпустите сертификат; настройте автопродление."},
				}
			case now.Add(14 * 24 * time.Hour).After(leaf.NotAfter):
				out <- core.Finding{
					Source:   core.ModNetwork,
					RuleID:   "tls-cert-expiring",
					Title:    fmt.Sprintf("Сертификат истекает скоро: %s", leaf.NotAfter.Format("2006-01-02")),
					Severity: core.SevMedium,
					Location: loc,
					Remediation: core.Remediation{Advice: "Продлите сертификат заранее; включите автопродление."},
				}
			}
			// Соответствие имени хоста.
			if err := leaf.VerifyHostname(t.Host); err != nil {
				out <- core.Finding{
					Source:   core.ModNetwork,
					RuleID:   "tls-cert-hostname",
					Title:    "Сертификат не соответствует имени хоста",
					Severity: core.SevMedium,
					Location: loc,
					Evidence: []core.Artifact{{Kind: "banner", Data: err.Error()}},
					Remediation: core.Remediation{Advice: "Выпустите сертификат с корректным CN/SAN для этого хоста."},
				}
			}
		}
	}()
	return out
}
