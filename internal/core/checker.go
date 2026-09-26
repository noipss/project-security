package core

import "context"

// Target — единица сканирования, которую получает проверка.
type Target struct {
	Host string // хост/домен/IP из scope
	URL  string // опционально, для web-проверок
}

// CheckerMeta — паспорт проверки.
type CheckerMeta struct {
	ID            string // уникальный идентификатор проверки
	Module        Module // к какому слою относится
	Title         string
	Destructive   bool   // true запрещён в профиле safe
	ActiveNetwork bool   // шлёт пакеты цели -> требует authorized=true
	NeedsEngine   string // имя движка, если проверка его требует ("" если нет)
}

// Checker — плагин, выполняющий одну проверку. Реализации регистрируются в Registry.
// Run обязан завершиться при отмене ctx и закрыть возвращаемый канал.
type Checker interface {
	Meta() CheckerMeta
	Run(ctx context.Context, t Target) <-chan Finding
}

// Engine — внешний движок (nmap, nuclei, semgrep...). Проверки используют движки
// через этот интерфейс; отсутствие движка не роняет скан.
type Engine interface {
	Name() string
	Available() bool // установлен ли бинарник / доступна ли библиотека
}

// Registry — реестр доступных проверок и движков.
type Registry struct {
	checkers []Checker
	engines  map[string]Engine
}

// NewRegistry создаёт пустой реестр.
func NewRegistry() *Registry {
	return &Registry{engines: make(map[string]Engine)}
}

// AddChecker регистрирует проверку.
func (r *Registry) AddChecker(c Checker) { r.checkers = append(r.checkers, c) }

// AddEngine регистрирует движок.
func (r *Registry) AddEngine(e Engine) { r.engines[e.Name()] = e }

// Checkers возвращает все зарегистрированные проверки.
func (r *Registry) Checkers() []Checker { return r.checkers }

// Engine возвращает движок по имени и признак его наличия.
func (r *Registry) Engine(name string) (Engine, bool) {
	e, ok := r.engines[name]
	return e, ok
}
