// Package web — веб-проверки: пассивный анализ заголовков безопасности
// одного ответа, без разрушающих полезных нагрузок.
package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/defproj/def/internal/core"
)

// headerRule описывает ожидаемый заголовок безопасности.
type headerRule struct {
	name     string
	ruleID   string
	title    string
	severity core.Severity
	advice   string
}

var securityHeaders = []headerRule{
	{"Strict-Transport-Security", "missing-hsts", "Нет заголовка HSTS", core.SevMedium,
		"Добавьте Strict-Transport-Security для принудительного HTTPS."},
	{"Content-Security-Policy", "missing-csp", "Нет Content-Security-Policy", core.SevMedium,
		"Настройте CSP для защиты от внедрения контента."},
	{"X-Content-Type-Options", "missing-xcto", "Нет X-Content-Type-Options", core.SevLow,
		"Установите X-Content-Type-Options: nosniff."},
	{"X-Frame-Options", "missing-xfo", "Нет X-Frame-Options / frame-ancestors", core.SevLow,
		"Задайте X-Frame-Options или CSP frame-ancestors против кликджекинга."},
	{"Referrer-Policy", "missing-referrer", "Нет Referrer-Policy", core.SevLow,
		"Установите ограничивающую Referrer-Policy."},
}

// SecurityHeaders — проверка заголовков безопасности HTTP(S)-ответа.
type SecurityHeaders struct {
	Timeout time.Duration
}

func (SecurityHeaders) Meta() core.CheckerMeta {
	return core.CheckerMeta{
		ID:            "web.security-headers",
		Module:        core.ModWeb,
		Title:         "Заголовки безопасности HTTP",
		ActiveNetwork: true,
	}
}

func (s SecurityHeaders) Run(ctx context.Context, t core.Target) <-chan core.Finding {
	out := make(chan core.Finding)
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	go func() {
		defer close(out)

		target := t.URL
		if target == "" {
			target = "https://" + t.Host
		}
		client := &http.Client{
			Timeout: timeout,
			// Мы анализируем заголовки; ошибки валидации TLS ловит network.tls.
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // не следуем редиректам, читаем как есть
			},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "def-scanner/0.1 (safe)")
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		loc := core.Location{Host: t.Host, URL: target}
		hasHeader := func(name string) bool {
			// CSP покрывает и frame-ancestors для X-Frame-Options.
			if resp.Header.Get(name) != "" {
				return true
			}
			if name == "X-Frame-Options" {
				return strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors")
			}
			return false
		}

		for _, r := range securityHeaders {
			if !hasHeader(r.name) {
				out <- core.Finding{
					Source:      core.ModWeb,
					RuleID:      r.ruleID,
					Title:       r.title,
					Severity:    r.severity,
					Location:    loc,
					Refs:        []string{"OWASP:secure-headers"},
					Remediation: core.Remediation{Advice: r.advice, AutoFixable: true},
				}
			}
		}

		// Раскрытие версии сервера/технологии.
		for _, h := range []string{"Server", "X-Powered-By"} {
			if v := resp.Header.Get(h); v != "" && strings.ContainsAny(v, "0123456789") {
				out <- core.Finding{
					Source:      core.ModWeb,
					RuleID:      "version-disclosure",
					Title:       fmt.Sprintf("Раскрытие версии в заголовке %s: %s", h, v),
					Severity:    core.SevLow,
					Location:    loc,
					Evidence:    []core.Artifact{{Kind: "response", Data: h + ": " + v}},
					Remediation: core.Remediation{Advice: "Скройте точную версию ПО в заголовках ответа.", AutoFixable: true},
				}
			}
		}
	}()
	return out
}
