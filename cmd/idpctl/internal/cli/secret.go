package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// secretFile is the destination of an IdP-issued secret: a new file with mode
// 0600 that idpctl.md requires so the plaintext never reaches the terminal
// (and with it, an AI's context).
type secretFile struct {
	path   string
	file   *os.File
	stored bool
}

// createSecretFile creates path exclusively. O_EXCL refuses an existing file
// or a symlink planted at the path, so a secret never overwrites another file
// or lands where the link points.
func createSecretFile(path string) (*secretFile, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve --secret-out: %w", err)
	}
	file, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create --secret-out (it must not exist yet): %w", err)
	}
	return &secretFile{path: abs, file: file}, nil
}

// store moves member's value from body into the file and returns body with
// the member replaced by <member>_file holding the path. The file is kept
// only after keep is called; until then discard removes it, so any failure
// before the output is printed reports the secret as lost and tells the
// admin to issue it again.
func (s *secretFile) store(body []byte, member string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("the response is not a JSON object: %w", err)
	}
	var value string
	raw, ok := fields[member]
	if !ok {
		return nil, fmt.Errorf("the response has no %s", member)
	}
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return nil, fmt.Errorf("the response's %s is not a non-empty string", member)
	}
	if _, err := s.file.WriteString(value + "\n"); err != nil {
		return nil, fmt.Errorf("write %s: %w", s.path, err)
	}
	if err := errors.Join(s.file.Sync(), s.file.Close()); err != nil {
		return nil, fmt.Errorf("write %s: %w", s.path, err)
	}

	delete(fields, member)
	path, err := json.Marshal(s.path)
	if err != nil {
		return nil, err
	}
	fields[member+"_file"] = path
	return json.Marshal(fields)
}

// keep marks the stored secret as delivered, once the output that names the
// file is known to be safe to print.
func (s *secretFile) keep() {
	s.stored = true
}

// discard removes the file unless keep was called, so a failed operation
// leaves no empty, partial, or unannounced secret file behind.
func (s *secretFile) discard() {
	if s.stored {
		return
	}
	_ = s.file.Close()
	_ = os.Remove(s.path)
}
