package core

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ScanResult — итог прогона: находки и метаданные.
type ScanResult struct {
	Project   string    `json:"project"`
	Profile   Profile   `json:"profile"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Findings  []Finding `json:"findings"`
	Skipped   []string  `json:"skipped"` // проверки, пропущенные (нет движка / профиль / нет авторизации)
}

// Orchestrator запускает проверки над целями с учётом scope, профиля и лимитов.
type Orchestrator struct {
	scope    *Scope
	registry *Registry
	log      *Logger
}

// NewOrchestrator собирает оркестратор.
func NewOrchestrator(scope *Scope, reg *Registry, log *Logger) *Orchestrator {
	return &Orchestrator{scope: scope, registry: reg, log: log}
}

// Run выполняет прогон. Каждая проверка запускается по каждой цели из scope с
// ограничением на число одновременных воркеров.
func (o *Orchestrator) Run(ctx context.Context) (*ScanResult, error) {
	// Гейт авторизации: активные профили требуют подтверждения владения/договора.
	if o.scope.RequiresAuthorization() && !o.scope.Authorized {
		return nil, fmt.Errorf("профиль %q требует подтверждения владения/договора (authorized=true в scope)", o.scope.Profile)
	}

	res := &ScanResult{
		Project:   o.scope.Project,
		Profile:   o.scope.Profile,
		StartedAt: time.Now().UTC(),
	}
	o.log.Info("scan_start", "", "", fmt.Sprintf("проект=%s профиль=%s целей=%d", o.scope.Project, o.scope.Profile, len(o.scope.Targets)))

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, o.scope.Limits.MaxWorkers)
		seen     = make(map[string]struct{})
		skipSeen = make(map[string]struct{})
	)

	addFinding := func(f Finding) {
		f.Finalize()
		now := time.Now().UTC()
		if f.FirstSeen.IsZero() {
			f.FirstSeen = now
		}
		f.LastSeen = now
		mu.Lock()
		defer mu.Unlock()
		if _, dup := seen[f.ID]; dup {
			return // дедупликация по стабильному ID
		}
		seen[f.ID] = struct{}{}
		res.Findings = append(res.Findings, f)
	}

	markSkipped := func(reason string) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := skipSeen[reason]; ok {
			return
		}
		skipSeen[reason] = struct{}{}
		res.Skipped = append(res.Skipped, reason)
	}

	for _, checker := range o.registry.Checkers() {
		meta := checker.Meta()

		// Разрушающие проверки запрещены в профиле safe.
		if meta.Destructive && o.scope.Profile == ProfileSafe {
			markSkipped(fmt.Sprintf("%s: пропущено (разрушающая, профиль safe)", meta.ID))
			continue
		}
		// Активные сетевые проверки требуют подтверждения даже в safe.
		if meta.ActiveNetwork && !o.scope.Authorized {
			markSkipped(fmt.Sprintf("%s: пропущено (активная сетевая, нет authorized=true)", meta.ID))
			continue
		}
		// Проверка требует недоступного движка.
		if meta.NeedsEngine != "" {
			if e, ok := o.registry.Engine(meta.NeedsEngine); !ok || !e.Available() {
				markSkipped(fmt.Sprintf("%s: пропущено (движок %q недоступен)", meta.ID, meta.NeedsEngine))
				continue
			}
		}

		for _, host := range o.scope.Targets {
			select {
			case <-ctx.Done():
				o.log.Warn("scan_cancel", "", "", "прервано контекстом")
				wg.Wait()
				res.EndedAt = time.Now().UTC()
				return res, ctx.Err()
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(c Checker, m CheckerMeta, target Target) {
				defer wg.Done()
				defer func() { <-sem }()
				o.log.Info("check_run", target.Host, m.ID, "")
				for f := range c.Run(ctx, target) {
					addFinding(f)
				}
			}(checker, meta, Target{Host: host})
		}
	}

	wg.Wait()
	res.EndedAt = time.Now().UTC()

	// Сортировка: сначала критичные, затем по модулю и заголовку.
	sort.Slice(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Title < b.Title
	})

	o.log.Info("scan_end", "", "", fmt.Sprintf("находок=%d пропущено=%d", len(res.Findings), len(res.Skipped)))
	return res, nil
}
