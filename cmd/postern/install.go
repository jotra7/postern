package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// installer writes a set of generated files as close to all-or-nothing as a
// multi-directory install can be made.
//
// The property it exists for is narrow and was learned the hard way twice.
// `postern init-standalone` refuses to overwrite an existing postern.yaml,
// because re-enrolling mints a new host_id and invalidates every operator's
// cached entry. That guard is correct, and it is also what turns any partial
// write into a trap: a run that failed on the fifth of six files leaves
// postern.yaml behind, and the operator's next attempt — after fixing
// whatever failed — is refused by a message warning them about cached
// entries that were never issued. Their way out is deleting files they did
// not know existed, on a host they are already worried about.
//
// So nothing lands in a destination directory until every file has been
// written successfully somewhere. Each destination gets a staging directory
// beside it (same filesystem, so the rename is a rename), every file is
// written there, and only then is each one renamed into place.
//
// What this does and does not guarantee, stated plainly because "atomic" is
// a word that invites more trust than it earns here:
//
//   - Every failure that has a plausible cause — a destination that is not a
//     directory, one that is not writable, a full disk, a rejected mode —
//     happens during staging, before any destination file exists. Rollback
//     then removes the staging directories and any destination directory
//     this run created, leaving the host exactly as it was found.
//   - The renames themselves are not one transaction. There is no primitive
//     that spans two directories, and postern installs into /etc/postern and
//     /etc/systemd/system. A failure between two renames is possible. It is
//     also several orders of magnitude less likely than the staging failures
//     above: by then the directory is known writable and the source file is
//     known to exist. That residual is not closed, and it is not claimed to
//     be.
type installer struct {
	staged []stagedFile
	// stagingDirs are removed on both commit and rollback.
	stagingDirs map[string]string
	// createdDirs are destination directories this run brought into
	// existence, newest first, removed on rollback if still empty.
	createdDirs []string
}

type stagedFile struct {
	tmp   string
	final string
}

func newInstaller() *installer {
	return &installer{stagingDirs: map[string]string{}}
}

// mkdirAll creates a destination directory, recording it so a rollback can
// take it away again.
func (i *installer) mkdirAll(dir string, mode os.FileMode) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	i.createdDirs = append([]string{dir}, i.createdDirs...)
	return nil
}

// staging returns the staging directory beside dir, creating it on first use.
// Beside rather than in /tmp, because a rename across filesystems is not a
// rename — it is a copy, which reintroduces the partial write this type
// exists to prevent.
func (i *installer) staging(dir string) (string, error) {
	if s, ok := i.stagingDirs[dir]; ok {
		return s, nil
	}
	s, err := os.MkdirTemp(dir, ".postern-install-*")
	if err != nil {
		return "", fmt.Errorf("create a staging directory in %s: %w", dir, err)
	}
	i.stagingDirs[dir] = s
	return s, nil
}

// stage writes one file's final content into staging, with its final mode.
func (i *installer) stage(final string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(final)
	s, err := i.staging(dir)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s, filepath.Base(final))
	if err := os.WriteFile(tmp, body, mode); err != nil { //nolint:gosec // the mode is chosen per artifact by the caller
		return fmt.Errorf("write %s: %w", final, err)
	}
	// WriteFile applies its mode only at creation, and this path is fresh, so
	// this is belt and braces against a umask surprise rather than a fix for
	// an overwrite. The mode has to be right here: the rename below preserves
	// whatever the staged file carries.
	if err := os.Chmod(tmp, mode); err != nil { //nolint:gosec // same
		return fmt.Errorf("chmod %s: %w", final, err)
	}
	i.staged = append(i.staged, stagedFile{tmp: tmp, final: final})
	return nil
}

// stageWith hands a staging path to a writer that insists on owning the
// write itself. identity.SaveFile is the only such caller: it does its own
// atomic temp-and-rename and refuses to hand back bytes.
func (i *installer) stageWith(final string, write func(path string) error) error {
	dir := filepath.Dir(final)
	s, err := i.staging(dir)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s, filepath.Base(final))
	if err := write(tmp); err != nil {
		return err
	}
	i.staged = append(i.staged, stagedFile{tmp: tmp, final: final})
	return nil
}

// commit renames every staged file into place.
func (i *installer) commit() error {
	for _, f := range i.staged {
		if err := os.Rename(f.tmp, f.final); err != nil {
			return fmt.Errorf("install %s: %w", f.final, err)
		}
	}
	i.cleanStaging()
	return nil
}

// rollback removes the staging directories and any destination directory
// this run created and left empty. Only if empty: a directory that already
// held something is not this command's to remove, and os.Remove refusing on
// a non-empty directory is exactly the guard that wants.
func (i *installer) rollback() {
	i.cleanStaging()
	for _, dir := range i.createdDirs {
		_ = os.Remove(dir)
	}
}

func (i *installer) cleanStaging() {
	for _, s := range i.stagingDirs {
		_ = os.RemoveAll(s)
	}
	i.stagingDirs = map[string]string{}
}
