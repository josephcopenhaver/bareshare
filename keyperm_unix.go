//go:build !windows

package main

import "os"

// secureKeyDir is a no-op outside Windows: the 0700 mode applied at creation
// time already restricts the directory to the owner.
func secureKeyDir(path string) error {
	return nil
}

// writeKeyFile writes key material readable only by the owner. The 0600 mode
// takes effect at creation, so the file never exists with wider access.
func writeKeyFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}
