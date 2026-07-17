package eventinventory

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const canonicalSchema = "lyflow.security_event.v1"

type Inventory struct {
	CanonicalSchema      string   `json:"canonical_schema"`
	GeneratedBy          string   `json:"generated_by"`
	MigrationOrder       []string `json:"migration_order"`
	RetirementDependency string   `json:"retirement_dependency"`
	RetirementEnabled    bool     `json:"retirement_enabled"`
	Entries              []Entry  `json:"entries"`
}

type Entry struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
	Roles   []string `json:"roles"`
	Streams []string `json:"streams,omitempty"`
	Schemas []string `json:"schemas"`
	Owner   string   `json:"owner"`
	Phases  []string `json:"phases"`
}

type fileFacts struct {
	path          string
	functions     []string
	types         []string
	streams       []string
	schemas       []string
	selectors     map[string]bool
	contractTypes bool
	eventSQL      bool
}

func Scan(root string) (Inventory, error) {
	entries := make([]Entry, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relative inventory path: %w", err)
		}
		if entry.IsDir() {
			if shouldSkipDirectory(relative) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		facts, err := inspectFile(path, filepath.ToSlash(relative))
		if err != nil {
			return err
		}
		entries = append(entries, entriesForFacts(facts)...)
		return nil
	})
	if err != nil {
		return Inventory{}, fmt.Errorf("scan event inventory: %w", err)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].ID < entries[right].ID })
	return Inventory{
		CanonicalSchema:      canonicalSchema,
		GeneratedBy:          "go run ./cmd/generate-event-inventory",
		MigrationOrder:       []string{"reader_first", "dual_write", "reconcile", "read_switch", "observe"},
		RetirementDependency: "Todo 7 persisted maximum spool/retry horizon and zero legacy reads for that full horizon",
		RetirementEnabled:    false,
		Entries:              entries,
	}, nil
}

func inspectFile(path, relative string) (fileFacts, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return fileFacts{}, fmt.Errorf("parse %s: %w", relative, err)
	}
	facts := fileFacts{path: relative, selectors: make(map[string]bool)}
	for _, declaration := range parsed.Decls {
		switch value := declaration.(type) {
		case *ast.FuncDecl:
			facts.functions = append(facts.functions, value.Name.Name)
		case *ast.GenDecl:
			for _, specification := range value.Specs {
				if typeSpec, ok := specification.(*ast.TypeSpec); ok {
					facts.types = append(facts.types, typeSpec.Name.Name)
				}
			}
		}
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.SelectorExpr:
			facts.selectors[value.Sel.Name] = true
		case *ast.Ident:
			if isContractType(value.Name) {
				facts.contractTypes = true
			}
		case *ast.BasicLit:
			if value.Kind != token.STRING {
				return true
			}
			literal, err := strconv.Unquote(value.Value)
			if err != nil {
				return true
			}
			if isStreamName(literal) {
				facts.streams = append(facts.streams, literal)
			}
			if strings.HasPrefix(literal, "lyflow.") || strings.HasPrefix(literal, "xdr-eval.") || strings.HasPrefix(literal, "suricata.eve") || strings.HasPrefix(literal, "wazuh.alert") || strings.HasPrefix(literal, "yara.match") {
				facts.schemas = append(facts.schemas, literal)
			}
			upper := strings.ToUpper(literal)
			if strings.Contains(upper, "INSERT INTO EVENTS") || strings.Contains(upper, "DELETE FROM EVENTS") || strings.Contains(upper, "XDR_EVENTS") {
				facts.eventSQL = true
			}
		}
		return true
	})
	facts.functions = uniqueSorted(facts.functions)
	facts.types = uniqueSorted(facts.types)
	facts.streams = uniqueSorted(facts.streams)
	facts.schemas = uniqueSorted(append(facts.schemas, canonicalSchema))
	return facts, nil
}

func entriesForFacts(facts fileFacts) []Entry {
	kinds := make([]string, 0, 7)
	publishesStream := facts.selectors["XAdd"] || facts.selectors["PublishAuto"]
	if publishesStream || hasFunctionPrefix(facts.functions, "publish", "emit", "send", "store", "write") {
		kinds = append(kinds, "producer")
	}
	if facts.selectors["XRead"] || facts.selectors["XReadGroup"] || facts.selectors["XRange"] || facts.selectors["XRevRangeN"] || hasFunctionPrefix(facts.functions, "consume", "process", "read", "load") {
		kinds = append(kinds, "consumer")
	}
	if len(facts.streams) > 0 {
		kinds = append(kinds, "stream")
	}
	if publishesStream || facts.eventSQL || hasFunctionPrefix(facts.functions, "persist", "store") {
		kinds = append(kinds, "persistence")
	}
	if facts.contractTypes || hasFunctionFragment(facts.functions, "adapter", "canonical", "normalize", "convert") {
		kinds = append(kinds, "adapter")
	}
	if facts.contractTypes && strings.HasPrefix(facts.path, "pkg/contracts/") {
		kinds = append(kinds, "schema")
	}
	if hasFunctionFragment(facts.functions, "observe", "reconcile") {
		kinds = append(kinds, "observer")
	}
	namedEventFunction := hasFunctionFragment(facts.functions, "event", "alert", "telemetry", "migration", "governance", "canonical", "normalize", "adapter", "reconcile", "observe")
	if len(kinds) == 0 || (!facts.contractTypes && len(facts.streams) == 0 && !facts.eventSQL && !publishesStream && !facts.selectors["XRead"] && !facts.selectors["XReadGroup"] && !facts.selectors["XRange"] && !facts.selectors["XRevRangeN"] && !namedEventFunction) {
		return nil
	}
	symbols := facts.functions
	if len(symbols) == 0 {
		symbols = facts.types
	}
	entries := make([]Entry, 0, len(kinds))
	for _, kind := range uniqueSorted(kinds) {
		phases := []string{"reader_first", "dual_write", "reconcile", "read_switch", "observe"}
		if kind == "observer" {
			phases = []string{"reconcile", "observe"}
		}
		entries = append(entries, Entry{ID: kind + ":" + facts.path, Kind: kind, Path: facts.path,
			Symbols: symbols, Roles: []string{kind}, Streams: facts.streams, Schemas: facts.schemas,
			Owner: strings.Split(facts.path, "/")[0], Phases: phases})
	}
	return entries
}
