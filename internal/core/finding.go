// Package core содержит модели и оркестрацию платформы анализа защищённости.
package core

import "time"

// Severity — уровень критичности находки.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// severityRank задаёт порядок для сортировки (больше = критичнее).
var severityRank = map[Severity]int{
	SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4,
}

// Rank возвращает числовой вес критичности.
func (s Severity) Rank() int { return severityRank[s] }

// Confidence — уверенность в находке. Confirmed выставляется после BAS-подтверждения.
type Confidence string

const (
	ConfReported  Confidence = "reported"  // заявлена сканером, не подтверждена
	ConfConfirmed Confidence = "confirmed" // подтверждена безопасной пробой
)

// Module — источник находки.
type Module string

const (
	ModRecon   Module = "recon"
	ModNetwork Module = "network"
	ModHost    Module = "host"
	ModCode    Module = "code"
	ModWeb     Module = "web"
	ModBAS     Module = "bas"
)

// Location — где обнаружена проблема (одно из полей заполнено по смыслу модуля).
type Location struct {
	File    string `json:"file,omitempty"`    // путь:строка для code
	Line    int    `json:"line,omitempty"`
	Host    string `json:"host,omitempty"`    // host:port для network/host
	Port    int    `json:"port,omitempty"`
	URL     string `json:"url,omitempty"`     // для web
	Package string `json:"package,omitempty"` // пакет@версия для SCA
}

// Artifact — безопасное доказательство находки.
type Artifact struct {
	Kind string `json:"kind"` // response|marker|banner|snippet
	Data string `json:"data"`
}

// Remediation — рекомендация по устранению и возможность автофикса.
type Remediation struct {
	Advice     string `json:"advice"`
	AutoFixable bool  `json:"auto_fixable"`
}

// Finding — единая модель находки. К ней приводят вывод все модули и движки.
type Finding struct {
	ID          string      `json:"id"` // стабильный хэш: source+location+rule
	Source      Module      `json:"source"`
	RuleID      string      `json:"rule_id"`
	Title       string      `json:"title"`
	Severity    Severity    `json:"severity"`
	Confidence  Confidence  `json:"confidence"`
	Location    Location    `json:"location"`
	Evidence    []Artifact  `json:"evidence,omitempty"`
	Refs        []string    `json:"refs,omitempty"` // CVE, CWE, ATT&CK, OWASP
	Remediation Remediation `json:"remediation"`
	FirstSeen   time.Time   `json:"first_seen"`
	LastSeen    time.Time   `json:"last_seen"`
}
