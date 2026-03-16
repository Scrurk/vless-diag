package downloader

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"vless-diag/internal/ui"
)

const (
	githubAPI      = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
	userAgent      = "vless-diag/1.0 (github.com/vless-diag)"
	singboxExeName = "sing-box.exe"
)
func EnsureSingBox(embeddedBinary []byte) (string, func(), error) {
	if len(embeddedBinary) > 0 {
		return extractEmbedded(embeddedBinary)
	}
	exeDir, err := executableDir()
	if err == nil {
		candidate := filepath.Join(exeDir, singboxExeName)
		if fileExists(candidate) {
			ui.PrintOK(fmt.Sprintf("Found sing-box at %s", candidate))
			return candidate, func() {}, nil
		}
	}
	if fileExists(singboxExeName) {
		abs, _ := filepath.Abs(singboxExeName)
		ui.PrintOK(fmt.Sprintf("Found sing-box at %s", abs))
		return abs, func() {}, nil
	}
	if path := findInPath("sing-box"); path != "" {
		ui.PrintOK(fmt.Sprintf("Found sing-box in PATH: %s", path))
		return path, func() {}, nil
	}
	cachedPath := cachedSingBoxPath()
	if fileExists(cachedPath) {
		ui.PrintOK(fmt.Sprintf("Using cached sing-box: %s", cachedPath))
		return cachedPath, func() {}, nil
	}
	ui.PrintWarn("sing-box not found — downloading from GitHub Releases...")
	downloadedPath, err := downloadSingBox(cachedPath)
	if err != nil {
		return "", func() {}, fmt.Errorf("auto-download failed: %w\n\n"+
			"  Please manually download sing-box from:\n"+
			"  https://github.com/SagerNet/sing-box/releases\n"+
			"  and place sing-box.exe next to vless-diag.exe", err)
	}

	return downloadedPath, func() {}, nil
}
func extractEmbedded(data []byte) (string, func(), error) {
	tmpFile, err := os.CreateTemp("", "vless-diag-singbox-*.exe")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temp file: %w", err)
	}
	tmpFile.Close()

	if err := os.WriteFile(tmpFile.Name(), data, 0700); err != nil {
		os.Remove(tmpFile.Name())
		return "", func() {}, fmt.Errorf("write embedded binary: %w", err)
	}

	cleanup := func() { os.Remove(tmpFile.Name()) }
	ui.PrintOK(fmt.Sprintf("Extracted embedded sing-box → %s", tmpFile.Name()))
	return tmpFile.Name(), cleanup, nil
}
func downloadSingBox(destPath string) (string, error) {
	ui.PrintProgress("Fetching latest release info from GitHub...")
	releaseInfo, err := fetchLatestRelease()
	if err != nil {
		return "", fmt.Errorf("fetch release info: %w", err)
	}
	ui.PrintOK(fmt.Sprintf("Latest version: %s", releaseInfo.TagName))
	assetURL, assetName, err := findAsset(releaseInfo)
	if err != nil {
		return "", err
	}
	ui.PrintProgress(fmt.Sprintf("Downloading: %s", assetName))
	zipData, err := downloadWithProgress(assetURL)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	ui.PrintOK(fmt.Sprintf("Downloaded %.1f MB", float64(len(zipData))/1024/1024))
	ui.PrintProgress("Extracting sing-box.exe from archive...")
	exeData, err := extractFromZip(zipData)
	if err != nil {
		return "", fmt.Errorf("extract: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}
	if err := os.WriteFile(destPath, exeData, 0700); err != nil {
		return "", fmt.Errorf("save binary: %w", err)
	}

	ui.PrintOK(fmt.Sprintf("Saved to: %s", destPath))
	return destPath, nil
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

func fetchLatestRelease() (*githubRelease, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", githubAPI, nil)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parse release JSON: %w", err)
	}
	return &release, nil
}

func findAsset(release *githubRelease) (url, name string, err error) {
	arch := runtime.GOARCH
	goos := runtime.GOOS
	archMap := map[string][]string{
		"amd64": {"amd64", "x86_64"},
		"arm64": {"arm64", "aarch64"},
		"386":   {"386", "i386", "x86"},
	}
	archVariants := archMap[arch]
	if archVariants == nil {
		archVariants = []string{arch}
	}

	osMap := map[string]string{
		"windows": "windows",
		"linux":   "linux",
		"darwin":  "darwin",
	}
	osName := osMap[goos]
	if osName == "" {
		osName = goos
	}

	for _, asset := range release.Assets {
		lower := strings.ToLower(asset.Name)
		if !strings.HasSuffix(lower, ".zip") {
			continue
		}
		if !strings.Contains(lower, osName) {
			continue
		}
		for _, a := range archVariants {
			if strings.Contains(lower, a) {
				return asset.BrowserDownloadURL, asset.Name, nil
			}
		}
	}

	return "", "", fmt.Errorf("no suitable asset found for %s/%s in release %s\nAvailable: %s",
		goos, arch, release.TagName, listAssets(release.Assets))
}

func listAssets(assets []githubAsset) string {
	names := make([]string, 0, len(assets))
	for _, a := range assets {
		names = append(names, a.Name)
	}
	return strings.Join(names, ", ")
}
func downloadWithProgress(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	totalSize := resp.ContentLength
	var buf bytes.Buffer
	progressBuf := make([]byte, 32768)
	var downloaded int64
	lastPrint := time.Now()

	for {
		n, err := resp.Body.Read(progressBuf)
		if n > 0 {
			buf.Write(progressBuf[:n])
			downloaded += int64(n)
			if time.Since(lastPrint) > 500*time.Millisecond {
				if totalSize > 0 {
					pct := float64(downloaded) / float64(totalSize) * 100
					barLen := 30
					filled := int(pct / 100 * float64(barLen))
					bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)
					fmt.Printf("\r         → [%s] %.1f%%  %.1f/%.1f MB",
						bar, pct,
						float64(downloaded)/1024/1024,
						float64(totalSize)/1024/1024)
				} else {
					fmt.Printf("\r         → %.1f MB downloaded...", float64(downloaded)/1024/1024)
				}
				lastPrint = time.Now()
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
	}
	fmt.Println()
	return buf.Bytes(), nil
}
func extractFromZip(zipData []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	for _, f := range r.File {
		base := strings.ToLower(filepath.Base(f.Name))
		if base == "sing-box.exe" || base == "sing-box" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open %s in zip: %w", f.Name, err)
			}
			defer rc.Close()

			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", f.Name, err)
			}
			return data, nil
		}
	}

	return nil, fmt.Errorf("sing-box(.exe) not found in archive. Files: %s", listZipFiles(r))
}

func listZipFiles(r *zip.Reader) string {
	names := make([]string, 0, len(r.File))
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	return strings.Join(names, ", ")
}
func cachedSingBoxPath() string {
	tmpDir := os.TempDir()
	return filepath.Join(tmpDir, "vless-diag", "sing-box.exe")
}

func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func findInPath(name string) string {
	paths := strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))
	for _, p := range paths {
		full := filepath.Join(p, name+".exe")
		if fileExists(full) {
			return full
		}
		full = filepath.Join(p, name)
		if fileExists(full) {
			return full
		}
	}
	return ""
}
