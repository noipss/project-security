package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Profile — режим агрессивности сканирования.
type Profile string

const (
	ProfileSafe       Profile = "safe"       // по умолчанию, неразрушающий
	ProfileNormal     Profile = "normal"
	ProfileAggressive Profile = "aggressive" // только стенд, требует явного флага
)

// Valid сообщает, известен ли профиль.
func (p Profile) Valid() bool {
	switch p {
	case ProfileSafe, ProfileNormal, ProfileAggressive:
		return true
	}
	return false
}

// Limits — ограничения ресурсов и темпа.
type Limits struct {
	RPS        int `json:"rps"`         // запросов в секунду на цель
	MaxWorkers int `json:"max_workers"` // параллельных проверок
}

// Scope — границы сканирования. За их пределами не делается ни одного запроса.
type Scope struct {
	Project     string   `json:"project"`
	Profile     Profile  `json:"profile"`
	Targets     []string `json:"targets"`      // хосты/домены/CIDR
	AllowedURLs []string `json:"allowed_urls"` // разрешённые пути для web
	Limits      Limits   `json:"limits"`

	// Authorized — подтверждение права на тестирование. Активные проверки
	// (BAS, профили normal/aggressive) блокируются, пока не true.
	Authorized bool `json:"authorized"`
}

// LoadScope читает конфиг из JSON-файла и валидирует его.
func LoadScope(path string) (*Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение scope: %w", err)
	}
	var s Scope
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("разбор scope: %w", err)
	}
	if s.Profile == "" {
		s.Profile = ProfileSafe // безопасный дефолт
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate проверяет обязательные поля и осмысленность значений.
func (s *Scope) Validate() error {
	if !s.Profile.Valid() {
		return fmt.Errorf("неизвестный профиль: %q", s.Profile)
	}
	if len(s.Targets) == 0 {
		return fmt.Errorf("не задано ни одной цели (targets)")
	}
	if s.Limits.MaxWorkers <= 0 {
		s.Limits.MaxWorkers = 4
	}
	return nil
}

// InScope сообщает, входит ли цель в разрешённый список.
func (s *Scope) InScope(target string) bool {
	for _, t := range s.Targets {
		if strings.EqualFold(strings.TrimSpace(t), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

// RequiresAuthorization истинно, если профиль подразумевает активные действия.
func (s *Scope) RequiresAuthorization() bool {
	return s.Profile != ProfileSafe
}
