// Package report формирует отчёты по результату скана в форматах JSON и HTML.
package report

import (
	"encoding/json"
	"html/template"
	"os"

	"github.com/defproj/def/internal/core"
)

// WriteJSON сохраняет результат в машиночитаемый JSON.
func WriteJSON(path string, res *core.ScanResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// WriteHTML сохраняет человекочитаемый HTML-отчёт.
func WriteHTML(path string, res *core.ScanResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return htmlTmpl.Execute(f, res)
}

var htmlTmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<title>Отчёт защищённости — {{.Project}}</title>
<style>
 body{font:15px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}
 h1{font-size:1.4rem} table{border-collapse:collapse;width:100%;margin-top:1rem}
 th,td{border:1px solid #ddd;padding:.5rem .6rem;text-align:left;vertical-align:top}
 th{background:#f0f0f0} .sev{font-weight:600;text-transform:uppercase;font-size:.8rem}
 .critical{color:#b00020}.high{color:#d35400}.medium{color:#b8860b}.low{color:#2c7}.info{color:#678}
 .muted{color:#888}.meta{color:#555;font-size:.9rem}
</style></head><body>
<h1>Отчёт защищённости — {{.Project}}</h1>
<p class="meta">Профиль: <b>{{.Profile}}</b> · Начало: {{.StartedAt.Format "2006-01-02 15:04:05 MST"}} · Находок: {{len .Findings}}</p>
{{if .Findings}}
<table><thead><tr><th>Крит.</th><th>Источник</th><th>Находка</th><th>Место</th><th>Увер.</th></tr></thead><tbody>
{{range .Findings}}<tr>
 <td class="sev {{.Severity}}">{{.Severity}}</td>
 <td>{{.Source}}</td>
 <td>{{.Title}}{{if .Remediation.Advice}}<br><span class="muted">{{.Remediation.Advice}}</span>{{end}}</td>
 <td>{{if .Location.Host}}{{.Location.Host}}{{if .Location.Port}}:{{.Location.Port}}{{end}}{{end}}{{.Location.URL}}{{.Location.File}}</td>
 <td>{{.Confidence}}</td>
</tr>{{end}}
</tbody></table>
{{else}}<p class="muted">Находок нет.</p>{{end}}
{{if .Skipped}}<h2 style="font-size:1.1rem">Пропущено</h2><ul class="muted">{{range .Skipped}}<li>{{.}}</li>{{end}}</ul>{{end}}
</body></html>`))
