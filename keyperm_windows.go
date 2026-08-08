//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// secureKeyDir sets an explicit owner-only DACL on the key directory. Unix
// permission bits (0700) are not enforced by Windows, so without this the
// directory would be protected only by whatever ACLs it happens to inherit.
// The grant is inheritable so anything created inside is born owner-only,
// and PROTECTED_DACL_SECURITY_INFORMATION cuts inheritance from above.
func secureKeyDir(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("get current user SID: %w", err)
	}

	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("build owner-only DACL: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("set owner-only DACL on %s: %w", path, err)
	}
	return nil
}

// writeKeyFile creates path with an owner-only protected DACL passed to
// CreateFile itself, so there is no instant at which the file exists without
// that protection. CREATE_ALWAYS keeps the existing DACL when overwriting a
// file this code previously created, which is already owner-only.
func writeKeyFile(path string, data []byte) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("get current user SID: %w", err)
	}

	// D: DACL, P: protected (no inherited ACEs), A;;FA;;;<sid>: allow the
	// owner SID full file access. No other ACEs exist, so everyone else is
	// implicitly denied.
	sd, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("D:P(A;;FA;;;%s)", user.User.Sid.String()),
	)
	if err != nil {
		return fmt.Errorf("build owner-only security descriptor: %w", err)
	}

	namep, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode path %s: %w", path, err)
	}

	h, err := windows.CreateFile(
		namep,
		windows.GENERIC_WRITE,
		0, // no sharing while writing key material
		&windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: sd,
		},
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}

	f := os.NewFile(uintptr(h), path)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
