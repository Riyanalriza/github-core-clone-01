package main

// Refs: loose ref files under <repo>/refs/, HEAD, and packed-refs (read
// only). A ref file holds "40-hex-sha\n". HEAD holds "ref: refs/heads/main"
// (or a bare SHA for a detached head). Refs are kept loose-only; we never
// write packed-refs, so a loose file is always authoritative when present.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// InitBareRepo creates a bare repository directory: objects/, refs/heads/,
// refs/tags/, HEAD pointing at refs/heads/main, and a minimal config with
// bare=true. It is safe to call on an existing repo (missing pieces are
// filled in, existing files are left alone).
func InitBareRepo(repoDir string) error {
	dirs := []string{
		filepath.Join(repoDir, "objects", "info"),
		filepath.Join(repoDir, "objects", "pack"),
		filepath.Join(repoDir, "refs", "heads"),
		filepath.Join(repoDir, "refs", "tags"),
		filepath.Join(repoDir, "info"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// HEAD -> refs/heads/main (only when HEAD does not exist yet).
	headPath := filepath.Join(repoDir, "HEAD")
	if _, err := os.Stat(headPath); os.IsNotExist(err) {
		if err := os.WriteFile(headPath, []byte("ref: refs/heads/main\n"), 0o644); err != nil {
			return err
		}
	}
	// Minimal config (only when missing).
	cfgPath := filepath.Join(repoDir, "config")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfg := "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"
		if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
			return err
		}
	}
	descPath := filepath.Join(repoDir, "description")
	if _, err := os.Stat(descPath); os.IsNotExist(err) {
		_ = os.WriteFile(descPath, []byte("Unnamed repository; edit this file 'description' to name the repository.\n"), 0o644)
	}
	return nil
}

// refPath returns the loose-ref file for a full ref name.
func refPath(repoDir, ref string) string {
	return filepath.Join(repoDir, filepath.FromSlash(ref))
}

// validRefName is a cheap sanity check for ref names we write.
func validRefName(ref string) bool {
	if !strings.HasPrefix(ref, "refs/") || strings.Contains(ref, "..") ||
		strings.ContainsAny(ref, " ~^:?*[\\") || strings.HasSuffix(ref, "/") ||
		strings.HasSuffix(ref, ".lock") || strings.Contains(ref, "//") {
		return false
	}
	return true
}

// WriteRef writes a loose ref (creating parent directories). The SHA must be
// a 40-hex id.
func WriteRef(repoDir, ref, sha string) error {
	if !validRefName(ref) {
		return fmt.Errorf("invalid ref name %q", ref)
	}
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !isObjectID(sha) {
		return fmt.Errorf("invalid sha %q for ref %s", sha, ref)
	}
	p := refPath(repoDir, ref)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	// Atomic-ish: write temp, rename.
	tmp, err := os.CreateTemp(filepath.Dir(p), "tmp_ref_*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(sha + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		return err
	}
	return nil
}

// DeleteRef removes a loose ref file. Deleting a ref that does not exist is
// a no-op success.
func DeleteRef(repoDir, ref string) error {
	if !validRefName(ref) {
		return fmt.Errorf("invalid ref name %q", ref)
	}
	err := os.Remove(refPath(repoDir, ref))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// readPackedRefs parses packed-refs (if present) into name -> sha. Peeled
// lines ("^<sha>") are ignored; a loose ref always wins over packed-refs.
func readPackedRefs(repoDir string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(repoDir, "packed-refs"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && isObjectID(fields[0]) {
			out[fields[1]] = strings.ToLower(fields[0])
		}
	}
	return out
}

// ListRefs returns every ref in the repo (loose, plus packed-refs for names
// without a loose file), as full name -> SHA. HEAD itself is not included.
func ListRefs(repoDir string) map[string]string {
	refs := readPackedRefs(repoDir)
	refsDir := filepath.Join(repoDir, "refs")
	_ = filepath.WalkDir(refsDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(repoDir, p)
		if err != nil {
			return nil
		}
		name := filepath.ToSlash(rel)
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		sha := strings.ToLower(strings.TrimSpace(string(b)))
		if isObjectID(sha) {
			refs[name] = sha
		}
		return nil
	})
	return refs
}

// readHeadRef returns the full ref name HEAD points at ("refs/heads/main"),
// or "" when HEAD is detached (a bare SHA) or missing.
func readHeadRef(repoDir string) string {
	b, err := os.ReadFile(filepath.Join(repoDir, "HEAD"))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "ref: ") {
		return strings.TrimSpace(s[5:])
	}
	return ""
}

// ResolveRef resolves a ref to a SHA. It accepts:
//   - "HEAD" (follows the HEAD file; a detached HEAD yields its SHA)
//   - a full ref ("refs/heads/main", "refs/tags/v1")
//   - a short name ("main" -> refs/heads/main, then refs/tags/main)
//   - a raw 40-hex SHA (returned as-is when the object exists)
// It returns the ref's stored SHA (for a tag ref, the tag object's SHA, not
// the peeled commit — use peelToCommit for that).
func ResolveRef(repoDir, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("empty ref")
	}
	if ref == "HEAD" {
		b, err := os.ReadFile(filepath.Join(repoDir, "HEAD"))
		if err != nil {
			return "", fmt.Errorf("HEAD not found")
		}
		s := strings.TrimSpace(string(b))
		if strings.HasPrefix(s, "ref: ") {
			return ResolveRef(repoDir, strings.TrimSpace(s[5:]))
		}
		if isObjectID(s) {
			return strings.ToLower(s), nil
		}
		return "", fmt.Errorf("HEAD is unborn")
	}
	if isObjectID(ref) {
		sha := strings.ToLower(ref)
		if _, _, err := ReadObject(repoDir, sha); err != nil {
			return "", fmt.Errorf("object %s not found", sha)
		}
		return sha, nil
	}
	// Full ref name.
	if strings.HasPrefix(ref, "refs/") {
		refs := ListRefs(repoDir)
		if sha, ok := refs[ref]; ok {
			return sha, nil
		}
		return "", fmt.Errorf("ref %s not found", ref)
	}
	// Short name: branch first, then tag.
	for _, cand := range []string{"refs/heads/" + ref, "refs/tags/" + ref} {
		if sha, err := ResolveRef(repoDir, cand); err == nil {
			return sha, nil
		}
	}
	return "", fmt.Errorf("ref %s not found", ref)
}

// peelToCommit follows annotated tag objects to the commit they point at.
// A commit SHA passes through unchanged; a non-commit, non-tag SHA (or a
// missing object) yields "".
func peelToCommit(repoDir, sha string) string {
	sha = strings.ToLower(strings.TrimSpace(sha))
	for i := 0; i < 10 && sha != "" && sha != zeroOID; i++ {
		typ, raw, err := ReadObject(repoDir, sha)
		if err != nil {
			return ""
		}
		if typ == "commit" {
			return sha
		}
		if typ != "tag" {
			return ""
		}
		// Tag object: "object <sha>" is its target.
		target := ""
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "object ") {
				target = strings.TrimSpace(line[7:])
				break
			}
			if line == "" {
				break
			}
		}
		if target == "" || !isObjectID(target) {
			return ""
		}
		sha = strings.ToLower(target)
	}
	return ""
}

// IsAncestor reports whether ancestorSHA is an ancestor of (or equal to)
// descendantSHA, by walking the commit parents through the object store.
// A zero ancestor is "no ancestor" and is never an ancestor of anything
// except itself being zero.
func IsAncestor(repoDir, ancestorSHA, descendantSHA string) bool {
	ancestorSHA = strings.ToLower(ancestorSHA)
	descendantSHA = strings.ToLower(descendantSHA)
	if ancestorSHA == "" || ancestorSHA == zeroOID {
		return false
	}
	if descendantSHA == "" || descendantSHA == zeroOID {
		return false
	}
	if ancestorSHA == descendantSHA {
		return true
	}
	// Peel tags: a ref update's new value may be a tag object.
	if p := peelToCommit(repoDir, descendantSHA); p != "" {
		descendantSHA = p
	}
	if p := peelToCommit(repoDir, ancestorSHA); p != "" {
		ancestorSHA = p
	}
	seen := map[string]bool{}
	queue := []string{descendantSHA}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		c, err := WalkCommit(repoDir, cur)
		if err != nil {
			continue
		}
		for _, p := range c.Parents {
			p = strings.ToLower(p)
			if p == ancestorSHA {
				return true
			}
			queue = append(queue, p)
		}
	}
	return false
}

// MergeBase returns the first common ancestor of a and b (the merge base),
// or "" when the two histories share nothing. It walks a's ancestors first
// (breadth-first), then b's, and returns the first commit found in both.
func MergeBase(repoDir, a, b string) string {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	if a == "" || b == "" || a == zeroOID || b == zeroOID {
		return ""
	}
	if a == b {
		return a
	}
	if p := peelToCommit(repoDir, a); p != "" {
		a = p
	}
	if p := peelToCommit(repoDir, b); p != "" {
		b = p
	}
	// All ancestors of a (BFS, nearest first).
	ancA := map[string]bool{}
	queue := []string{a}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if ancA[cur] {
			continue
		}
		ancA[cur] = true
		c, err := WalkCommit(repoDir, cur)
		if err != nil {
			continue
		}
		for _, p := range c.Parents {
			queue = append(queue, strings.ToLower(p))
		}
	}
	// BFS from b; the first commit also in a's set is the merge base.
	seen := map[string]bool{}
	queue = []string{b}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		if ancA[cur] {
			return cur
		}
		c, err := WalkCommit(repoDir, cur)
		if err != nil {
			continue
		}
		for _, p := range c.Parents {
			queue = append(queue, strings.ToLower(p))
		}
	}
	return ""
}

// sortedRefNames returns the ref names of a map in deterministic order:
// HEAD's target first (when present), then refs/heads/*, refs/tags/*, others.
func sortedRefNames(refs map[string]string) []string {
	names := make([]string, 0, len(refs))
	for n := range refs {
		names = append(names, n)
	}
	rank := func(n string) int {
		switch {
		case strings.HasPrefix(n, "refs/heads/"):
			return 0
		case strings.HasPrefix(n, "refs/tags/"):
			return 1
		default:
			return 2
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if rank(names[i]) != rank(names[j]) {
			return rank(names[i]) < rank(names[j])
		}
		return names[i] < names[j]
	})
	return names
}
