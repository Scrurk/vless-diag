package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
)

var (
	ColorCyan    = color.New(color.FgCyan, color.Bold)
	ColorGreen   = color.New(color.FgGreen, color.Bold)
	ColorYellow  = color.New(color.FgYellow, color.Bold)
	ColorRed     = color.New(color.FgRed, color.Bold)
	ColorMagenta = color.New(color.FgMagenta, color.Bold)
	ColorWhite   = color.New(color.FgWhite, color.Bold)
	ColorGray    = color.New(color.FgHiBlack)
	ColorBlue    = color.New(color.FgBlue, color.Bold)

	DimWhite = color.New(color.FgWhite)
	DimCyan  = color.New(color.FgCyan)
)

func init() {
	color.Output = colorable.NewColorableStdout()
}

func PrintBanner() {
	banner := `
 ██╗   ██╗██╗     ███████╗███████╗███████╗    ██████╗ ██╗ █████╗  ██████╗ 
 ██║   ██║██║     ██╔════╝██╔════╝██╔════╝    ██╔══██╗██║██╔══██╗██╔════╝ 
 ██║   ██║██║     █████╗  ███████╗███████╗    ██║  ██║██║███████║██║  ███╗ 
 ╚██╗ ██╔╝██║     ██╔══╝  ╚════██║╚════██║    ██║  ██║██║██╔══██║██║   ██║ 
  ╚████╔╝ ███████╗███████╗███████║███████║    ██████╔╝██║██║  ██║╚██████╔╝ 
   ╚═══╝  ╚══════╝╚══════╝╚══════╝╚══════╝    ╚═════╝ ╚═╝╚═╝  ╚═╝ ╚═════╝ 
`
	ColorCyan.Fprintln(color.Output, banner)
	ColorGray.Fprintln(color.Output, "  Professional VLESS Diagnostic Tool v1.0.0  |  Windows Native  |  Powered by sing-box")
	ColorGray.Fprintln(color.Output, "  ─────────────────────────────────────────────────────────────────────────────────────")
	fmt.Fprintln(color.Output)
}

func PrintUsage() {
	ColorWhite.Fprintln(color.Output, "USAGE:")
	fmt.Fprintln(color.Output, "  vless-diag.exe <vless://uri>")
	fmt.Fprintln(color.Output)
	ColorWhite.Fprintln(color.Output, "EXAMPLE:")
	DimCyan.Fprintln(color.Output, "  vless-diag.exe \"vless://uuid@host:443?security=reality&sni=google.com&pbk=...&sid=...&fp=chrome\"")
	fmt.Fprintln(color.Output)
	ColorWhite.Fprintln(color.Output, "SUPPORTED PROTOCOLS:")
	DimWhite.Fprintln(color.Output, "  VLESS + Reality, TLS, WS, gRPC, XTLS")
	fmt.Fprintln(color.Output)
	ColorWhite.Fprintln(color.Output, "SING-BOX ENGINE:")
	DimWhite.Fprintln(color.Output, "  sing-box is auto-located or downloaded from GitHub Releases on first run.")
	DimWhite.Fprintln(color.Output, "  Cache location: %TEMP%\\vless-diag\\sing-box.exe")
	fmt.Fprintln(color.Output)
	ColorWhite.Fprintln(color.Output, "EMBED SING-BOX (single-file build):")
	DimCyan.Fprintln(color.Output, "  1. Copy sing-box.exe → internal/embedded/sing-box.exe")
	DimCyan.Fprintln(color.Output, "  2. go build -tags embed_singbox -o vless-diag.exe .")
}

func PrintSection(title string) {
	fmt.Fprintln(color.Output)
	line := strings.Repeat("─", 68)
	ColorCyan.Fprintf(color.Output, "  ┌%s┐\n", line)
	padded := fmt.Sprintf("  │  %-66s│\n", "◆ "+title)
	ColorCyan.Fprint(color.Output, padded)
	ColorCyan.Fprintf(color.Output, "  └%s┘\n", line)
}

func PrintSubSection(title string) {
	fmt.Fprintln(color.Output)
	ColorMagenta.Fprintf(color.Output, "  ▸ %s\n", title)
	ColorGray.Fprintf(color.Output, "  %s\n", strings.Repeat("·", 60))
}

func PrintField(label, value string, status FieldStatus) {
	labelFormatted := fmt.Sprintf("    %-28s", label)
	ColorGray.Fprint(color.Output, labelFormatted)

	switch status {
	case StatusOK:
		ColorGreen.Fprint(color.Output, "✓  ")
		ColorWhite.Fprintln(color.Output, value)
	case StatusWarn:
		ColorYellow.Fprint(color.Output, "⚠  ")
		ColorYellow.Fprintln(color.Output, value)
	case StatusFail:
		ColorRed.Fprint(color.Output, "✗  ")
		ColorRed.Fprintln(color.Output, value)
	case StatusInfo:
		ColorBlue.Fprint(color.Output, "ℹ  ")
		DimWhite.Fprintln(color.Output, value)
	case StatusNeutral:
		fmt.Fprint(color.Output, "   ")
		DimWhite.Fprintln(color.Output, value)
	}
}

func PrintMetric(label, value, unit string, quality Quality) {
	labelFormatted := fmt.Sprintf("    %-28s", label)
	ColorGray.Fprint(color.Output, labelFormatted)

	switch quality {
	case QualityExcellent:
		ColorGreen.Fprintf(color.Output, "%-16s", value)
		ColorGreen.Fprintf(color.Output, " %s  [EXCELLENT]\n", unit)
	case QualityGood:
		ColorGreen.Fprintf(color.Output, "%-16s", value)
		DimWhite.Fprintf(color.Output, " %s  [GOOD]\n", unit)
	case QualityFair:
		ColorYellow.Fprintf(color.Output, "%-16s", value)
		ColorYellow.Fprintf(color.Output, " %s  [FAIR]\n", unit)
	case QualityPoor:
		ColorRed.Fprintf(color.Output, "%-16s", value)
		ColorRed.Fprintf(color.Output, " %s  [POOR]\n", unit)
	case QualityNA:
		ColorGray.Fprintf(color.Output, "%-16s", value)
		ColorGray.Fprintf(color.Output, " %s\n", unit)
	}
}

func PrintSpeedBar(label string, speedMbps float64) {
	labelFormatted := fmt.Sprintf("    %-28s", label)
	ColorGray.Fprint(color.Output, labelFormatted)

	barLen := 30
	filled := int(speedMbps / 100.0 * float64(barLen))
	if filled > barLen {
		filled = barLen
	}
	if filled < 0 {
		filled = 0
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)

	var q Quality
	switch {
	case speedMbps >= 50:
		q = QualityExcellent
	case speedMbps >= 20:
		q = QualityGood
	case speedMbps >= 5:
		q = QualityFair
	default:
		q = QualityPoor
	}

	switch q {
	case QualityExcellent:
		ColorGreen.Fprintf(color.Output, "[%s] %.2f Mbps\n", bar, speedMbps)
	case QualityGood:
		ColorGreen.Fprintf(color.Output, "[%s] %.2f Mbps\n", bar, speedMbps)
	case QualityFair:
		ColorYellow.Fprintf(color.Output, "[%s] %.2f Mbps\n", bar, speedMbps)
	case QualityPoor:
		ColorRed.Fprintf(color.Output, "[%s] %.2f Mbps\n", bar, speedMbps)
	}
}

func PrintLatencyBar(label string, ms float64) {
	labelFormatted := fmt.Sprintf("    %-28s", label)
	ColorGray.Fprint(color.Output, labelFormatted)

	barLen := 20
	filled := int(ms / 500.0 * float64(barLen))
	if filled > barLen {
		filled = barLen
	}
	bar := strings.Repeat("▓", filled) + strings.Repeat("░", barLen-filled)

	var q Quality
	switch {
	case ms < 50:
		q = QualityExcellent
	case ms < 150:
		q = QualityGood
	case ms < 300:
		q = QualityFair
	default:
		q = QualityPoor
	}

	switch q {
	case QualityExcellent:
		ColorGreen.Fprintf(color.Output, "[%s] %.1f ms\n", bar, ms)
	case QualityGood:
		ColorGreen.Fprintf(color.Output, "[%s] %.1f ms\n", bar, ms)
	case QualityFair:
		ColorYellow.Fprintf(color.Output, "[%s] %.1f ms\n", bar, ms)
	case QualityPoor:
		ColorRed.Fprintf(color.Output, "[%s] %.1f ms\n", bar, ms)
	}
}

func PrintStep(step, total int, msg string) {
	if step == 0 {
		ColorMagenta.Fprint(color.Output, "\n  [▸] ")
	} else {
		ColorMagenta.Fprintf(color.Output, "\n  [%d/%d] ", step, total)
	}
	ColorWhite.Fprintf(color.Output, "%s", msg)
	ColorGray.Fprintln(color.Output, " ...")
}

func PrintProgress(msg string) {
	ColorGray.Fprintf(color.Output, "         → %s\n", msg)
}

func PrintOK(msg string) {
	ColorGreen.Fprint(color.Output, "         ✓ ")
	DimWhite.Fprintln(color.Output, msg)
}

func PrintWarn(msg string) {
	ColorYellow.Fprint(color.Output, "         ⚠ ")
	ColorYellow.Fprintln(color.Output, msg)
}

func PrintError(msg string) {
	ColorRed.Fprint(color.Output, "\n  [ERROR] ")
	ColorRed.Fprintln(color.Output, msg)
}

func PrintInfo(msg string) {
	ColorBlue.Fprint(color.Output, "  [INFO]  ")
	DimWhite.Fprintln(color.Output, msg)
}

func PrintSummary(score int, issues []string) {
	fmt.Fprintln(color.Output)
	line := strings.Repeat("═", 68)
	ColorCyan.Fprintf(color.Output, "  ╔%s╗\n", line)
	ColorCyan.Fprintf(color.Output, "  ║  %-66s║\n", "OVERALL ASSESSMENT")
	ColorCyan.Fprintf(color.Output, "  ╚%s╝\n", line)
	fmt.Fprintln(color.Output)

	var rating string
	var ratingColor *color.Color
	switch {
	case score >= 90:
		rating = "EXCELLENT — Channel is clean, fast, and well-hidden"
		ratingColor = ColorGreen
	case score >= 75:
		rating = "GOOD — Minor issues detected, usable for most tasks"
		ratingColor = ColorGreen
	case score >= 55:
		rating = "FAIR — Noticeable degradation or exposure risks"
		ratingColor = ColorYellow
	case score >= 35:
		rating = "POOR — Significant problems, use with caution"
		ratingColor = ColorRed
	default:
		rating = "CRITICAL — Severe issues, channel unreliable or exposed"
		ratingColor = ColorRed
	}
	gaugeLen := 40
	filled := score * gaugeLen / 100
	gauge := strings.Repeat("█", filled) + strings.Repeat("░", gaugeLen-filled)

	fmt.Fprintf(color.Output, "  Health Score: ")
	ratingColor.Fprintf(color.Output, "%d/100  [%s]\n", score, gauge)
	fmt.Fprintln(color.Output)
	fmt.Fprintf(color.Output, "  Verdict: ")
	ratingColor.Fprintln(color.Output, rating)

	if len(issues) > 0 {
		fmt.Fprintln(color.Output)
		ColorYellow.Fprintln(color.Output, "  Issues Found:")
		for _, issue := range issues {
			ColorRed.Fprintf(color.Output, "    • %s\n", issue)
		}
	}

	fmt.Fprintln(color.Output)
	ColorGray.Fprintf(color.Output, "  Scan completed at %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintln(color.Output)
}

type FieldStatus int

const (
	StatusOK      FieldStatus = iota
	StatusWarn
	StatusFail
	StatusInfo
	StatusNeutral
)

type Quality int

const (
	QualityExcellent Quality = iota
	QualityGood
	QualityFair
	QualityPoor
	QualityNA
)

func Fprintln(s string) {
	fmt.Fprintln(os.Stdout, s)
}
