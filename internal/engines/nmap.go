// Package engines содержит адаптеры внешних движков сканирования.
// Каждый адаптер опционален: если бинарник не установлен, Available()=false и
// связанные проверки помечаются оркестратором как «пропущено».
package engines

import (
	"context"
	"encoding/xml"
	"os/exec"
	"time"
)

// Nmap — адаптер к бинарнику nmap. Реализует core.Engine.
type Nmap struct{}

func (Nmap) Name() string { return "nmap" }

// Available сообщает, установлен ли nmap в PATH.
func (Nmap) Available() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// Port — результат по одному порту.
type Port struct {
	Number  int
	Proto   string
	State   string
	Service string
	Version string
}

// nmapXML описывает подмножество XML-вывода nmap (-oX).
type nmapXML struct {
	Hosts []struct {
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// ScanPorts запускает неразрушающий скан версий (-sV) с выводом в XML на stdout.
// Возвращает открытые порты. Флаги подобраны безопасно, без агрессивных опций.
func (Nmap) ScanPorts(ctx context.Context, host string) ([]Port, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	// -sV: версии сервисов; -oX -: XML в stdout; -Pn: не пинговать (часто фильтруется).
	cmd := exec.CommandContext(ctx, "nmap", "-sV", "-Pn", "-oX", "-", host)
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var parsed nmapXML
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	var ports []Port
	for _, h := range parsed.Hosts {
		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			ver := p.Service.Product
			if p.Service.Version != "" {
				ver += " " + p.Service.Version
			}
			ports = append(ports, Port{
				Number:  p.PortID,
				Proto:   p.Protocol,
				State:   p.State.State,
				Service: p.Service.Name,
				Version: ver,
			})
		}
	}
	return ports, nil
}
