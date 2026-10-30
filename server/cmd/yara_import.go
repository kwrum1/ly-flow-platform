package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	yaraImportDir      = "/data/yara"
	yaraImportFileName = "imported.yar"
	yaraImportMaxBytes = 32 << 20
)

var yaraRuleCountPattern = regexp.MustCompile(`(?m)^\s*rule\s+[A-Za-z_][A-Za-z0-9_]*`)

func yaraRuleFiles() []string {
	seen := map[string]bool{}
	files := make([]string, 0)
	for _, directory := range []string{yaraImportDir, "/etc/ly/rules/yara", "/app/rules/yara", "rules/yara", "../rules/yara"} {
		matches, err := filepath.Glob(filepath.Join(directory, "*.yar"))
		if err != nil {
			continue
		}
		for _, file := range matches {
			clean := filepath.Clean(file)
			if seen[clean] {
				continue
			}
			seen[clean] = true
			files = append(files, clean)
		}
	}
	sort.Strings(files)
	return files
}

func yaraPackStatus() map[string]interface{} {
	status := map[string]interface{}{
		"import_path": filepath.Join(yaraImportDir, yaraImportFileName),
		"files":       []string{},
		"total_rules": 0,
		"size_bytes":  0,
		"sha256":      "",
		"updated_at":  "",
		"imported":    false,
	}
	files := yaraRuleFiles()
	hasher := sha256.New()
	var updated time.Time
	totalRules := 0
	totalSize := int64(0)
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		hasher.Write(content)
		totalRules += len(yaraRuleCountPattern.FindAllIndex(content, -1))
		totalSize += int64(len(content))
		if info, err := os.Stat(file); err == nil && info.ModTime().After(updated) {
			updated = info.ModTime()
		}
	}
	status["files"] = files
	status["total_rules"] = totalRules
	status["size_bytes"] = totalSize
	status["sha256"] = hex.EncodeToString(hasher.Sum(nil))
	if importedContent, err := os.ReadFile(filepath.Join(yaraImportDir, yaraImportFileName)); err == nil {
		importedRules := len(yaraRuleCountPattern.FindAllIndex(importedContent, -1))
		status["imported_rules"] = importedRules
		status["builtin_rules"] = totalRules - importedRules
	} else {
		status["imported_rules"] = 0
		status["builtin_rules"] = totalRules
	}
	if !updated.IsZero() {
		status["updated_at"] = updated.UTC().Format(time.RFC3339)
	}
	if _, err := os.Stat(filepath.Join(yaraImportDir, yaraImportFileName)); err == nil {
		status["imported"] = true
	}
	return status
}

func yaraRulesStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": yaraPackStatus()})
		case http.MethodDelete:
			path := filepath.Join(yaraImportDir, yaraImportFileName)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				writeJSONError(w, http.StatusInternalServerError, "yara_import_clear_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": yaraPackStatus()})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func yaraRulesImportHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, yaraImportMaxBytes)
		var content []byte
		var err error
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
			if parseErr := r.ParseMultipartForm(yaraImportMaxBytes); parseErr != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_yara_upload", parseErr.Error())
				return
			}
			file, _, fileErr := r.FormFile("file")
			if fileErr != nil {
				writeJSONError(w, http.StatusBadRequest, "yara_file_required", "multipart field file is required")
				return
			}
			defer file.Close()
			content, err = io.ReadAll(io.LimitReader(file, yaraImportMaxBytes+1))
		} else {
			content, err = io.ReadAll(r.Body)
		}
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_yara_upload", err.Error())
			return
		}
		if len(content) == 0 || len(content) > yaraImportMaxBytes {
			writeJSONError(w, http.StatusBadRequest, "invalid_yara_size", "YARA rule file is empty or too large")
			return
		}
		if strings.ContainsRune(string(content), '\x00') || !strings.Contains(string(content), "rule ") || !strings.Contains(string(content), "{") {
			writeJSONError(w, http.StatusUnprocessableEntity, "invalid_yara_content", "file must contain at least one YARA rule")
			return
		}
		if err := os.MkdirAll(yaraImportDir, 0o750); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "yara_import_dir_failed", err.Error())
			return
		}
		target := filepath.Join(yaraImportDir, yaraImportFileName)
		temporary := target + ".tmp"
		if err := os.WriteFile(temporary, content, 0o640); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "yara_import_write_failed", err.Error())
			return
		}
		if err := os.Rename(temporary, target); err != nil {
			_ = os.Remove(temporary)
			writeJSONError(w, http.StatusInternalServerError, "yara_import_publish_failed", err.Error())
			return
		}
		status := yaraPackStatus()
		status["message"] = fmt.Sprintf("imported %d bytes", len(content))
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": status})
	}
}
