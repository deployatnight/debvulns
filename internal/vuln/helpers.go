package vuln

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// bytesReader wraps a byte slice in a *bytes.Reader (kept as a tiny helper so
// the call site reads clearly).
func bytesReader(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}

// splitLines splits text on \n and \r\n, dropping a single trailing empty line
// introduced by a final newline (so the debsecan parser sees no spurious blank
// entries).
func splitLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	parts := strings.Split(text, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// isDir reports whether path exists and is a directory.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// joinPath joins two path components using the OS separator.
func joinPath(base, name string) string {
	return filepath.Join(base, name)
}
