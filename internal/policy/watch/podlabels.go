package watch

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LoadPodLabels reads a Kubernetes downward-API labels file and returns the
// pod's own labels.
//
// The whole label map is only obtainable through a downwardAPI volume; the env
// var form of fieldRef supports metadata.labels['key'] for one named key at a
// time, which cannot serve arbitrary policy selectors. The kubelet writes one
// label per line as key="escaped-value", using Go quoting for the value, and
// rewrites the file when the pod's labels change.
//
// A pod with no labels yields a present but empty file, which returns an empty
// map and no error. Every other failure -- missing file, unreadable file,
// malformed line -- is returned as an error so the caller can fail closed
// rather than silently proceed with an empty label set, which would match only
// selector-less policies and quietly change the pod's egress (#35).
func LoadPodLabels(path string) (map[string]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("watch: pod labels path must not be empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("watch: read pod labels %q: %w", path, err)
	}
	return ParsePodLabels(raw, path)
}

// ParsePodLabels parses the contents of a downward-API labels file.
func ParsePodLabels(raw []byte, source string) (map[string]string, error) {
	out := make(map[string]string)
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("watch: pod labels %q line %d: missing key=value separator", source, i+1)
		}
		key := trimmed[:eq]
		value, err := strconv.Unquote(trimmed[eq+1:])
		if err != nil {
			return nil, fmt.Errorf("watch: pod labels %q line %d: unquote value for %q: %w", source, i+1, key, err)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("watch: pod labels %q line %d: duplicate key %q", source, i+1, key)
		}
		out[key] = value
	}
	return out, nil
}
