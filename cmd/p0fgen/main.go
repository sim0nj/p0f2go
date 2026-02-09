package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type entry struct {
	section string
	label   string
	sys     string
	sigs    []string
}

func parse(fpPath string) ([]entry, error) {
	f, err := os.Open(fpPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []entry
	var cur entry
	var section string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
			continue
		}
		if strings.HasPrefix(t, "label") {
			if cur.label != "" {
				entries = append(entries, cur)
				cur = entry{}
			}
			parts := strings.SplitN(t, "=", 2)
			if len(parts) == 2 {
				cur.section = section
				cur.label = strings.TrimSpace(parts[1])
			}
			continue
		}
		if strings.HasPrefix(t, "sys") {
			parts := strings.SplitN(t, "=", 2)
			if len(parts) == 2 {
				cur.sys = strings.TrimSpace(parts[1])
			}
			continue
		}
		if strings.HasPrefix(t, "sig") {
			parts := strings.SplitN(t, "=", 2)
			if len(parts) == 2 {
				cur.sigs = append(cur.sigs, strings.TrimSpace(parts[1]))
			}
			continue
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cur.label != "" {
		entries = append(entries, cur)
	}
	return entries, nil
}

func writeDataGo(outPath string, entries []entry) error {
	var b strings.Builder
	b.WriteString("package p0f\n\n")
	b.WriteString("var Data = DB{Entries: []Entry{\n")
	for _, e := range entries {
		b.WriteString("{Section: ")
		b.WriteString(fmt.Sprintf("%q", e.section))
		b.WriteString(", Label: ")
		b.WriteString(fmt.Sprintf("%q", e.label))
		b.WriteString(", Sys: ")
		b.WriteString(fmt.Sprintf("%q", e.sys))
		b.WriteString(", Sig: []string{")
		for i, s := range e.sigs {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(fmt.Sprintf("%q", s))
		}
		b.WriteString("}},\n")
	}
	b.WriteString("}}\n")
	return os.WriteFile(outPath, []byte(b.String()), 0o644)
}

func main() {
	root, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	fpPath := filepath.Join(root, "p0f.fp")
	entries, err := parse(fpPath)
	if err != nil {
		panic(err)
	}
	outPath := filepath.Join(root, "p0f", "data.go")
	if err := writeDataGo(outPath, entries); err != nil {
		panic(err)
	}
}
