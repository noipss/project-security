// Command def — CLI платформы анализа защищённости: читает scope,
// запускает конвейер проверок, пишет отчёт (JSON + HTML).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	netcheck "github.com/defproj/def/internal/checks/network"
	webcheck "github.com/defproj/def/internal/checks/web"
	"github.com/defproj/def/internal/core"
	"github.com/defproj/def/internal/engines"
	"github.com/defproj/def/internal/report"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		scopePath = flag.String("scope", "configs/scope.example.json", "путь к файлу scope (JSON)")
		outHTML   = flag.String("out-html", "report.html", "путь для HTML-отчёта")
		outJSON   = flag.String("out-json", "report.json", "путь для JSON-отчёта")
		logPath   = flag.String("log", "scan.log.jsonl", "путь для аудит-журнала")
	)
	flag.Parse()

	scope, err := core.LoadScope(*scopePath)
	if err != nil {
		return err
	}

	logFile, err := os.Create(*logPath)
	if err != nil {
		return fmt.Errorf("создание журнала: %w", err)
	}
	defer logFile.Close()
	logger := core.NewLogger(logFile)

	// Реестр движков и проверок.
	reg := core.NewRegistry()
	reg.AddEngine(engines.Nmap{})

	reg.AddChecker(netcheck.PortScan{})        // нативный connect-скан
	reg.AddChecker(netcheck.TLSCheck{})        // TLS: версия, сертификат
	reg.AddChecker(netcheck.NmapPorts{})       // движок nmap (если установлен)
	reg.AddChecker(webcheck.SecurityHeaders{}) // заголовки безопасности

	// Отмена по Ctrl+C — важно для длинных сканов.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	orch := core.NewOrchestrator(scope, reg, logger)
	res, err := orch.Run(ctx)
	if err != nil {
		return err
	}

	if err := report.WriteJSON(*outJSON, res); err != nil {
		return fmt.Errorf("запись JSON: %w", err)
	}
	if err := report.WriteHTML(*outHTML, res); err != nil {
		return fmt.Errorf("запись HTML: %w", err)
	}

	fmt.Printf("Готово. Находок: %d, пропущено: %d\n", len(res.Findings), len(res.Skipped))
	fmt.Printf("Отчёты: %s, %s · Журнал: %s\n", *outHTML, *outJSON, *logPath)
	return nil
}
