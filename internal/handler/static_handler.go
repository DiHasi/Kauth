package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type StaticHandler struct {
	staticDir string
}

func NewStaticHandler(staticDir string) *StaticHandler {
	return &StaticHandler{staticDir: staticDir}
}

func (h *StaticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(h.staticDir, r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "/") || !fileExists(path) {
		http.ServeFile(w, r, filepath.Join(h.staticDir, "index.html"))
		return
	}

	http.ServeFile(w, r, path)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
