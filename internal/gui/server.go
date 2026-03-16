package gui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

//go:embed static
var staticFiles embed.FS

type MsgType string

const (
	MsgStep     MsgType = "step"
	MsgSection  MsgType = "section"
	MsgField    MsgType = "field"
	MsgMetric   MsgType = "metric"
	MsgSpeedBar MsgType = "speedbar"
	MsgLatBar   MsgType = "latbar"
	MsgSubSect  MsgType = "subsection"
	MsgWarn     MsgType = "warn"
	MsgOK       MsgType = "ok"
	MsgError    MsgType = "error"
	MsgProgress MsgType = "progress"
	MsgSummary  MsgType = "summary"
	MsgDone     MsgType = "done"
)

type WSMessage struct {
	Type    MsgType     `json:"type"`
	Payload interface{} `json:"payload"`
}

type FieldPayload struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Status string `json:"status"`
}

type MetricPayload struct {
	Label   string  `json:"label"`
	Value   string  `json:"value"`
	Unit    string  `json:"unit"`
	Quality string  `json:"quality"`
	Num     float64 `json:"num"`
}

type SpeedBarPayload struct {
	Label   string  `json:"label"`
	Mbps    float64 `json:"mbps"`
	Quality string  `json:"quality"`
}

type LatBarPayload struct {
	Label   string  `json:"label"`
	Ms      float64 `json:"ms"`
	Quality string  `json:"quality"`
}

type StepPayload struct {
	Step    int    `json:"step"`
	Total   int    `json:"total"`
	Message string `json:"message"`
}

type SummaryPayload struct {
	Score   int      `json:"score"`
	Verdict string   `json:"verdict"`
	Issues  []string `json:"issues"`
}

type Sink struct {
	mu      sync.RWMutex
	clients map[chan WSMessage]struct{}
}

func NewSink() *Sink {
	return &Sink{
		clients: make(map[chan WSMessage]struct{}),
	}
}

func (s *Sink) subscribe() chan WSMessage {
	ch := make(chan WSMessage, 256)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

func (s *Sink) unsubscribe(ch chan WSMessage) {
	s.mu.Lock()
	delete(s.clients, ch)
	s.mu.Unlock()
	close(ch)
}

func (s *Sink) broadcast(msg WSMessage) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (s *Sink) Send(t MsgType, payload interface{}) {
	s.broadcast(WSMessage{Type: t, Payload: payload})
}

func (s *Sink) Step(step, total int, msg string) {
	s.Send(MsgStep, StepPayload{Step: step, Total: total, Message: msg})
}

func (s *Sink) Section(title string) {
	s.Send(MsgSection, title)
}

func (s *Sink) SubSection(title string) {
	s.Send(MsgSubSect, title)
}

func (s *Sink) Field(label, value, status string) {
	s.Send(MsgField, FieldPayload{Label: label, Value: value, Status: status})
}

func (s *Sink) Metric(label, value, unit, quality string, num float64) {
	s.Send(MsgMetric, MetricPayload{Label: label, Value: value, Unit: unit, Quality: quality, Num: num})
}

func (s *Sink) SpeedBar(label string, mbps float64) {
	q := "poor"
	switch {
	case mbps >= 50:
		q = "excellent"
	case mbps >= 20:
		q = "good"
	case mbps >= 5:
		q = "fair"
	}
	s.Send(MsgSpeedBar, SpeedBarPayload{Label: label, Mbps: mbps, Quality: q})
}

func (s *Sink) LatBar(label string, ms float64) {
	q := "poor"
	switch {
	case ms < 50:
		q = "excellent"
	case ms < 150:
		q = "good"
	case ms < 300:
		q = "fair"
	}
	s.Send(MsgLatBar, LatBarPayload{Label: label, Ms: ms, Quality: q})
}

func (s *Sink) OK(msg string)       { s.Send(MsgOK, msg) }
func (s *Sink) Warn(msg string)     { s.Send(MsgWarn, msg) }
func (s *Sink) Error(msg string)    { s.Send(MsgError, msg) }
func (s *Sink) Progress(msg string) { s.Send(MsgProgress, msg) }

func (s *Sink) Summary(score int, verdict string, issues []string) {
	s.Send(MsgSummary, SummaryPayload{Score: score, Verdict: verdict, Issues: issues})
}

func (s *Sink) Done() {
	s.Send(MsgDone, nil)
}

type Server struct {
	sink    *Sink
	port    int
	runFunc func(uri, singboxPath string, sink *Sink) error
	mux     *http.ServeMux
}

func NewServer(port int, runFunc func(uri, singboxPath string, sink *Sink) error) *Server {
	s := &Server{
		sink:    NewSink(),
		port:    port,
		runFunc: runFunc,
		mux:     http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	staticFS, _ := fs.Sub(staticFiles, "static")
	s.mux.Handle("/", http.FileServer(http.FS(staticFS)))
	s.mux.HandleFunc("/ws", s.handleWS)
	s.mux.HandleFunc("/scan", s.handleScan)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	var req struct {
		URI         string `json:"uri"`
		SingboxPath string `json:"singboxPath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})

	go func() {
		if err := s.runFunc(req.URI, req.SingboxPath, s.sink); err != nil {
			s.sink.Error(err.Error())
			s.sink.Done()
		}
	}()
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgradeWebSocket(w, r)
	if err != nil {
		return
	}
	defer conn.Close()

	ch := s.sink.subscribe()
	defer s.sink.unsubscribe(ch)

	for msg := range ch {
		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		if err := wsWriteText(conn, data); err != nil {
			return
		}
	}
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", s.port, err)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", s.port)
	fmt.Printf("VLESS Diag GUI → %s\n", url)

	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(url)
	}()

	return http.Serve(ln, s.mux)
}

func (s *Server) StartWithContext(ctx context.Context) error {
	srv := &http.Server{Handler: s.mux}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		return err
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", s.port)
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(url)
	}()

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()

	return srv.Serve(ln)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}
