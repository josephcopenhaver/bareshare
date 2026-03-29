package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type downloadStatus struct {
	ExpectedSize *int64 `json:"expected_size,omitempty"`
	BytesWritten *int64 `json:"bytes_written,omitempty"`
}

func int64Ptr(v int64) *int64 { return &v }

func statusFilePath(outPath string) string {
	dir := filepath.Dir(outPath)
	base := filepath.Base(outPath)
	return filepath.Join(dir, "."+base+".dl.status.json")
}

func tempFilePath(outPath string) string {
	dir := filepath.Dir(outPath)
	base := filepath.Base(outPath)
	return filepath.Join(dir, "."+base+".dl.tmp")
}

func writeStatus(outPath string, s downloadStatus) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal status: %w", err)
	}
	path := statusFilePath(outPath)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write status file %s: %w", path, err)
	}
	return nil
}

func readStatus(outPath string) (downloadStatus, error) {
	path := statusFilePath(outPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return downloadStatus{}, fmt.Errorf("read status file %s: %w", path, err)
	}
	var s downloadStatus
	if err := json.Unmarshal(data, &s); err != nil {
		return downloadStatus{}, fmt.Errorf("parse status file %s: %w", path, err)
	}
	return s, nil
}

func removeStatusFiles(outPath string) error {
	var errsBuf [2]error
	errs := errsBuf[:0]

	if err := os.Remove(statusFilePath(outPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("failed to remove status file: %w", err))
	}

	if err := os.Remove(tempFilePath(outPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("failed to remove temp file: %w", err))
	}

	return errors.Join(errs...)
}

// checkDirWritable verifies the directory is writable by the current process.
func checkDirWritable(dir string) error {
	tmp, err := os.CreateTemp(dir, ".bareshare-write-check-*")
	if err != nil {
		return fmt.Errorf("not writable: %w", err)
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close write-check file failed: %w", err)
	}

	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove write-check file failed: %w", err)
	}

	return nil
}

// checkFileRemovable verifies that an existing non-empty file can be removed
// (i.e. the parent directory is writable). It does not actually remove the file.
func checkFileRemovable(path string) error {
	dir := filepath.Dir(path)
	if err := checkDirWritable(dir); err != nil {
		return fmt.Errorf("output file %s exists and is not empty, and parent directory is not writable; delete the file or fix permissions", path)
	}
	return nil
}
