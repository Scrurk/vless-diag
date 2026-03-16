package main

import (
	"fmt"
	"os"

	"vless-diag/internal/cli"
	"vless-diag/internal/downloader"
	"vless-diag/internal/embedded"
	"vless-diag/internal/gui"
	"vless-diag/internal/ui"
)

func main() {
	if len(os.Args) == 1 || os.Args[1] == "--gui" || os.Args[1] == "-gui" {
		runGUI()
		return
	}

	ui.PrintBanner()

	if os.Args[1] == "--help" || os.Args[1] == "-h" {
		ui.PrintUsage()
		return
	}

	rawURI := os.Args[1]

	ui.PrintStep(0, 0, "Locating sing-box engine")
	singboxPath, cleanup, err := downloader.EnsureSingBox(embedded.SingBoxBinary)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Cannot obtain sing-box: %v", err))
		os.Exit(1)
	}
	defer cleanup()

	if err := cli.Run(rawURI, singboxPath); err != nil {
		ui.PrintError(fmt.Sprintf("Fatal: %v", err))
		os.Exit(1)
	}
}

func runGUI() {
	fmt.Println("VLESS Diagnostic Tool v1.0.0")
	fmt.Println("Starting GUI…")

	srv := gui.NewServer(7878, func(uri, singboxPath string, sink *gui.Sink) error {
		if singboxPath == "" {
			path, cleanup, err := downloader.EnsureSingBox(embedded.SingBoxBinary)
			if err != nil {
				return fmt.Errorf("cannot obtain sing-box: %w", err)
			}
			defer cleanup()
			singboxPath = path
		}
		return gui.Run(uri, singboxPath, sink)
	})

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "GUI server error: %v\n", err)
		os.Exit(1)
	}
}
