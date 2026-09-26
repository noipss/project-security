package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ComputeID строит стабильный идентификатор находки из источника, правила и места.
// Одинаковый вход всегда даёт одинаковый ID — это обеспечивает дедупликацию и
// сравнение прогонов между запусками.
func ComputeID(source Module, ruleID string, loc Location) string {
	key := fmt.Sprintf("%s|%s|%s:%d|%s|%s:%d|%s",
		source, ruleID, loc.File, loc.Line, loc.URL, loc.Host, loc.Port, loc.Package)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

// Finalize проставляет ID, если он пуст. Вызывается оркестратором при приёме находки.
func (f *Finding) Finalize() {
	if f.ID == "" {
		f.ID = ComputeID(f.Source, f.RuleID, f.Location)
	}
	if f.Confidence == "" {
		f.Confidence = ConfReported
	}
}
