package detector

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

// Traversal models a document-viewer endpoint that joins user input onto a
// virtual web root and resolves it. It fires when the resolved path escapes the
// root or reaches a sensitive absolute path. It NEVER touches the real file
// system; resolution is pure path math against a virtual tree.
type Traversal struct {
	root string
}

// sensitiveAbsolutePaths are targets that, if resolved to, count as a fire even
// when technically still expressible.
var sensitiveAbsolutePaths = []string{
	"/etc/passwd", "/etc/shadow", "/proc/self", "/root/",
}

// NewTraversal builds the path-traversal detector.
func NewTraversal() *Traversal {
	return &Traversal{root: "/srv/www/public"}
}

// Inspect evaluates the requested path against the virtual root.
func (d *Traversal) Inspect(input string) model.Verdict {
	decoded := decodeRepeated(input, 2)

	// A null byte is a classic truncation trick and never appears in a benign
	// filename.
	if strings.ContainsRune(decoded, '\x00') {
		return model.Fire(model.CategoryPathTraversal, "trav_null_byte",
			"path contains a NUL byte")
	}

	lower := strings.ToLower(decoded)
	for _, sensitive := range sensitiveAbsolutePaths {
		if strings.Contains(lower, sensitive) {
			return model.Fire(model.CategoryPathTraversal, "trav_sensitive_path",
				fmt.Sprintf("path references %s", sensitive))
		}
	}

	// A Windows-style absolute path also escapes a POSIX web root.
	if strings.Contains(lower, "c:\\") || strings.Contains(lower, "c:/") {
		return model.Fire(model.CategoryPathTraversal, "trav_windows_abs",
			"path references a Windows absolute path")
	}

	// Resolve the request the way a vulnerable app would: join onto the root and
	// clean, then check whether the result is still contained.
	joined := path.Join(d.root, filepathToSlash(decoded))
	cleaned := path.Clean(joined)
	if cleaned != d.root && !strings.HasPrefix(cleaned, d.root+"/") {
		return model.Fire(model.CategoryPathTraversal, "trav_escape",
			fmt.Sprintf("resolved to %s, outside %s", cleaned, d.root))
	}

	return model.NotFired()
}

// decodeRepeated URL-decodes up to n times to catch double-encoded payloads.
// It stops early when a pass makes no change or fails to decode.
func decodeRepeated(s string, n int) string {
	for i := 0; i < n; i++ {
		next, err := url.QueryUnescape(s)
		if err != nil || next == s {
			break
		}
		s = next
	}
	return s
}

// filepathToSlash normalises backslashes so a "..\" segment resolves like "../".
func filepathToSlash(s string) string {
	return strings.ReplaceAll(s, "\\", "/")
}
