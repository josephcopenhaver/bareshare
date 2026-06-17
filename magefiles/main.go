//go:build mage

package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	binName = "bareshare"
	pkgPath = "."
)

// target describes a single cross-compilation output.
//
// outDir preserves the same directory naming the original release script used
// (it encoded the libc/min-OS info in the path); for a CGO-free Go build the
// only thing that actually selects the artifact is GOOS/GOARCH.
type target struct {
	goos     string
	goarch   string
	tolerate bool // allow build failure without aborting (the script's `|| true`)
}

var targets = []target{
	{"darwin", "arm64", true},
	{"darwin", "amd64", true},
	{"linux", "amd64", false},
	{"linux", "arm64", false},
}

// Dist cross-compiles the redir binary for every release target, then for each
// produced binary writes a sha256 digest, a gzipped tarball (binary + digest),
// and a sha256 digest of that tarball under dist/.
func Dist() error {
	if err := os.RemoveAll("dist"); err != nil {
		return err
	}
	if err := os.RemoveAll("build"); err != nil {
		return err
	}
	if err := os.MkdirAll("dist", 0o755); err != nil {
		return err
	}

	for _, t := range targets {
		if err := buildTarget(t); err != nil {
			if t.tolerate {
				fmt.Fprintf(os.Stderr, "warning: skipping %s/%s: %v\n", t.goos, t.goarch, err)
				continue
			}
			return err
		}
		if err := packageTarget(t); err != nil {
			return err
		}
	}

	return nil
}

var versionLineReg = regexp.MustCompile(`^\s*(?:(?:const|var)\s+)?version\s*=\s*"([^"]+)"\s*(?://.*)?$`)

func version() string {
	f, err := os.Open("./version.go")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := versionLineReg.FindStringSubmatch(sc.Text()); m != nil && len(m) == 2 {
			return m[1]
		}
	}

	panic("version not set")
}

func buildTarget(t target) error {
	dir := filepath.Join("build", version(), t.goos, t.goarch)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	out := filepath.Join(dir, binName)
	fmt.Printf("building %s/%s -> %s\n", t.goos, t.goarch, out)

	// -buildvcs=false makes more reproducible builds
	//
	// -trimpath + -ldflags "-s -w" and a static (CGO-free) link
	cmd := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-ldflags", "-s -w", "-o", out, pkgPath)
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+t.goos,
		"GOARCH="+t.goarch,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func packageTarget(t target) error {
	dir := filepath.Join("build", version(), t.goos, t.goarch)
	binPath := filepath.Join(dir, binName)

	// digest of the binary, sitting next to it (e.g. build/.../redir.sha256)
	binSum, err := sha256File(binPath)
	if err != nil {
		return err
	}
	if err := writeSum(binPath+".sha256", binSum, binName); err != nil {
		return err
	}

	// dist/redir-<version>-<os>-<arch...>.tar.gz (path separators become dashes)
	slug := strings.ReplaceAll(version()+"/"+t.goos+"/"+t.goarch, "/", "-")
	tarName := fmt.Sprintf("%s-%s.tar.gz", binName, slug)
	tarPath := filepath.Join("dist", tarName)
	if err := writeTarGz(tarPath, dir, binName, binName+".sha256"); err != nil {
		return err
	}

	// digest of the tarball
	tarSum, err := sha256File(tarPath)
	if err != nil {
		return err
	}
	return writeSum(tarPath+".sha256", tarSum, tarName)
}

// writeSum writes a digest file in GNU coreutils `sha256sum` format:
// "<hex>  <name>\n".
func writeSum(path, sum, name string) error {
	return os.WriteFile(path, []byte(sum+"  "+name+"\n"), 0o644)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeTarGz creates dest as a gzip (level 9) tarball containing the named files
// from srcDir, stored under their base names.
func writeTarGz(dest, srcDir string, names ...string) (err error) {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)

	for _, name := range names {
		if err := addFile(tw, srcDir, name); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func addFile(tw *tar.Writer, srcDir, name string) error {
	p := filepath.Join(srcDir, name)
	info, err := os.Stat(p)
	if err != nil {
		return err
	}

	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = name // store under the base name, mirroring `tar -C <dir> <name>`
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	src, err := os.Open(p)
	if err != nil {
		return err
	}
	defer src.Close()

	_, err = io.Copy(tw, src)
	return err
}
