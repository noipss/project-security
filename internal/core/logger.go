package core

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// LogEntry — одна запись аудит-журнала: что, когда, против чего.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Action  string    `json:"action"`
	Target  string    `json:"target,omitempty"`
	Checker string    `json:"checker,omitempty"`
	Message string    `json:"message,omitempty"`
}

// Logger пишет структурированный журнал действий в JSON Lines.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLogger создаёт логгер поверх произвольного writer'а.
func NewLogger(w io.Writer) *Logger { return &Logger{w: w} }

func (l *Logger) write(e LogEntry) {
	e.Time = time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, _ := json.Marshal(e)
	l.w.Write(append(b, '\n'))
}

// Info пишет информационную запись.
func (l *Logger) Info(action, target, checker, msg string) {
	l.write(LogEntry{Level: "info", Action: action, Target: target, Checker: checker, Message: msg})
}

// Warn пишет предупреждение.
func (l *Logger) Warn(action, target, checker, msg string) {
	l.write(LogEntry{Level: "warn", Action: action, Target: target, Checker: checker, Message: msg})
}

// Error пишет ошибку.
func (l *Logger) Error(action, target, checker, msg string) {
	l.write(LogEntry{Level: "error", Action: action, Target: target, Checker: checker, Message: msg})
}
