package main

// Pure-Go git object store: loose objects only.
//
// Objects live under <repo>/objects/xx/<38 hex>, zlib-compressed as
// "<type> <size>\0<content>" and addressed by the SHA-1 of that exact byte
// stream. No packfiles are stored on disk (packs we receive are unpacked
// into loose objects; packs we send are built in memory). No git binary,
// no exec, stdlib only.
//
// The helpers the REST layer needs live here too: ParseCommit / WalkCommit /
// ListCommits / ReadTree / ReadFileAtRef.

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// zeroOID is the all-zero object id: "no object" / "no ref".
const zeroOID = "0000000000000000000000000000000000000000"

// CommitInfo is one parsed commit object.
type CommitInfo struct {
	SHA            string
	Tree           string
	Parents        []string
	AuthorName     string
	AuthorEmail    string
	AuthorTime     int64
	AuthorTZ       string
	CommitterName  string
	CommitterEmail string
	CommitterTime  int64
	CommitterTZ    string
	Date           string // RFC3339 of the author time (what REST returns)
	Message        string
}

// objectSHA returns the SHA-1 id of an object with the given type and content.
func objectSHA(typ string, content []byte) string {
	h := sha1.New()
	h.Write([]byte(typ))
	h.Write([]byte(" "))
	h.Write([]byte(strconv.Itoa(len(content))))
	h.Write([]byte{0})
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// objectPath is the loose-object path for a SHA inside a repo dir.
func objectPath(repoDir, sha string) string {
	return filepath.Join(repoDir, "objects", sha[:2], sha[2:])
}

// isObjectID reports whether s is a 40-hex object id.
func isObjectID(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// WriteObject stores an object (type + content) as a loose object and returns
// its SHA-1. Writing an object that already exists is a no-op success.
func WriteObject(repoDir, typ string, content []byte) (string, error) {
	sha := objectSHA(typ, content)
	p := objectPath(repoDir, sha)
	if _, err := os.Stat(p); err == nil {
		return sha, nil // already there
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	// Write to a temp file in the same directory, then rename into place, so
	// a concurrent reader never sees a half-written object.
	tmp, err := os.CreateTemp(filepath.Dir(p), "tmp_obj_*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	var raw bytes.Buffer
	raw.WriteString(typ)
	raw.WriteByte(' ')
	raw.WriteString(strconv.Itoa(len(content)))
	raw.WriteByte(0)
	raw.Write(content)
	zw := zlib.NewWriter(tmp)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		tmp.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	// Best effort: make the object read-only like git does (ignoring errors).
	_ = os.Chmod(tmpName, 0o444)
	if err := os.Rename(tmpName, p); err != nil {
		// Lost a race with another writer of the same object: fine.
		if _, statErr := os.Stat(p); statErr == nil {
			return sha, nil
		}
		return "", err
	}
	return sha, nil
}

// ReadObject reads a loose object by SHA and returns its type and raw content
// (the bytes after "<type> <size>\0").
func ReadObject(repoDir, sha string) (string, []byte, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !isObjectID(sha) {
		return "", nil, fmt.Errorf("invalid object id %q", sha)
	}
	f, err := os.Open(objectPath(repoDir, sha))
	if err != nil {
		return "", nil, fmt.Errorf("object %s not found", sha)
	}
	defer f.Close()
	zr, err := zlib.NewReader(f)
	if err != nil {
		return "", nil, fmt.Errorf("object %s corrupt: %w", sha, err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return "", nil, fmt.Errorf("object %s corrupt: %w", sha, err)
	}
	nul := bytes.IndexByte(raw, 0)
	if nul < 0 {
		return "", nil, fmt.Errorf("object %s corrupt: no header", sha)
	}
	hdr := string(raw[:nul])
	sp := strings.IndexByte(hdr, ' ')
	if sp < 0 {
		return "", nil, fmt.Errorf("object %s corrupt: bad header", sha)
	}
	typ := hdr[:sp]
	size, err := strconv.Atoi(hdr[sp+1:])
	if err != nil || size != len(raw)-nul-1 {
		return "", nil, fmt.Errorf("object %s corrupt: bad size", sha)
	}
	return typ, raw[nul+1:], nil
}

// ParseCommit parses a commit object's raw content. The header block is
// "tree <sha>", "parent <sha>" (0..n), "author ...", "committer ...", then a
// blank line and the message.
func ParseCommit(raw []byte) *CommitInfo {
	c := &CommitInfo{}
	body := raw
	// Split header from message at the first blank line.
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		c.Message = strings.TrimRight(string(raw[i+2:]), "\n")
		body = raw[:i]
	} else {
		c.Message = ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		switch {
		case strings.HasPrefix(line, "tree "):
			c.Tree = strings.TrimSpace(line[5:])
		case strings.HasPrefix(line, "parent "):
			c.Parents = append(c.Parents, strings.TrimSpace(line[7:]))
		case strings.HasPrefix(line, "author "):
			c.AuthorName, c.AuthorEmail, c.AuthorTime, c.AuthorTZ = parseIdent(line[7:])
		case strings.HasPrefix(line, "committer "):
			c.CommitterName, c.CommitterEmail, c.CommitterTime, c.CommitterTZ = parseIdent(line[10:])
		}
	}
	c.Date = formatGitDate(c.AuthorTime, c.AuthorTZ)
	return c
}

// parseIdent parses "Name <email> <unix-ts> <+zzzz>" into its parts.
func parseIdent(s string) (name, email string, ts int64, tz string) {
	lt := strings.LastIndex(s, "<")
	gt := strings.LastIndex(s, ">")
	if lt < 0 || gt < 0 || gt < lt {
		return strings.TrimSpace(s), "", 0, "+0000"
	}
	name = strings.TrimSpace(s[:lt])
	email = s[lt+1 : gt]
	rest := strings.Fields(strings.TrimSpace(s[gt+1:]))
	if len(rest) >= 1 {
		ts, _ = strconv.ParseInt(rest[0], 10, 64)
	}
	if len(rest) >= 2 {
		tz = rest[1]
	} else {
		tz = "+0000"
	}
	return name, email, ts, tz
}

// formatGitDate renders a git timestamp + timezone as RFC3339.
func formatGitDate(ts int64, tz string) string {
	if ts == 0 {
		return time.Unix(0, 0).UTC().Format(time.RFC3339)
	}
	off := 0
	if len(tz) == 5 && (tz[0] == '+' || tz[0] == '-') {
		sign := 1
		if tz[0] == '-' {
			sign = -1
		}
		h, _ := strconv.Atoi(tz[1:3])
		m, _ := strconv.Atoi(tz[3:5])
		off = sign * (h*3600 + m*60)
	}
	return time.Unix(ts, 0).In(time.FixedZone("", off)).Format(time.RFC3339)
}

// WalkCommit reads and parses one commit object.
func WalkCommit(repoDir, sha string) (*CommitInfo, error) {
	typ, raw, err := ReadObject(repoDir, sha)
	if err != nil {
		return nil, err
	}
	if typ != "commit" {
		return nil, fmt.Errorf("%s is a %s, not a commit", sha, typ)
	}
	c := ParseCommit(raw)
	c.SHA = strings.ToLower(sha)
	return c, nil
}

// ListCommits returns up to n commits reachable from ref, newest first,
// following the first-parent chain. ref may be a branch name ("main"), a full
// ref ("refs/heads/main"), "HEAD", or a raw commit SHA.
func ListCommits(repoDir, ref string, n int) ([]CommitInfo, error) {
	sha := ""
	if isObjectID(ref) {
		sha = strings.ToLower(ref)
	} else {
		var err error
		sha, err = ResolveRef(repoDir, ref)
		if err != nil {
			return nil, err
		}
	}
	// A ref may point at a tag; peel it to the commit.
	sha = peelToCommit(repoDir, sha)
	if sha == "" {
		return nil, fmt.Errorf("ref %q does not resolve to a commit", ref)
	}
	var out []CommitInfo
	seen := map[string]bool{}
	cur := sha
	for cur != "" && cur != zeroOID && len(out) < n && !seen[cur] {
		seen[cur] = true
		c, err := WalkCommit(repoDir, cur)
		if err != nil {
			break
		}
		out = append(out, *c)
		if len(c.Parents) == 0 {
			break
		}
		cur = c.Parents[0]
	}
	if out == nil {
		out = []CommitInfo{}
	}
	return out, nil
}

// ReadTree reads a tree object and returns its entries (uses main.go's
// parseTree). Entries are returned in stored order.
func ReadTree(repoDir, treeSHA string) ([]treeEntry, error) {
	typ, raw, err := ReadObject(repoDir, treeSHA)
	if err != nil {
		return nil, err
	}
	if typ != "tree" {
		return nil, fmt.Errorf("%s is a %s, not a tree", treeSHA, typ)
	}
	return parseTree(raw), nil
}

// ReadFileAtRef returns the bytes of the file at path inside the tree of the
// commit ref points to. Directories in the path are walked one level at a time.
func ReadFileAtRef(repoDir, ref, path string) ([]byte, error) {
	sha, err := ResolveRef(repoDir, ref)
	if err != nil {
		return nil, err
	}
	sha = peelToCommit(repoDir, sha)
	c, err := WalkCommit(repoDir, sha)
	if err != nil {
		return nil, err
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	treeSHA := c.Tree
	for i, seg := range segments {
		entries, err := ReadTree(repoDir, treeSHA)
		if err != nil {
			return nil, err
		}
		var found *treeEntry
		for j := range entries {
			if entries[j].Name == seg {
				found = &entries[j]
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("path %q not found", path)
		}
		if i == len(segments)-1 {
			if gitIsDirMode(found.Mode) {
				return nil, fmt.Errorf("path %q is a directory", path)
			}
			typ, raw, err := ReadObject(repoDir, found.SHA)
			if err != nil {
				return nil, err
			}
			if typ != "blob" {
				return nil, fmt.Errorf("path %q is a %s, not a blob", path, typ)
			}
			return raw, nil
		}
		if !gitIsDirMode(found.Mode) {
			return nil, fmt.Errorf("path %q: %q is not a directory", path, seg)
		}
		treeSHA = found.SHA
	}
	return nil, fmt.Errorf("path %q not found", path)
}

// collectReachable walks commits (and their trees/blobs) reachable from the
// given commit SHAs and returns every object id in the closure, plus the
// per-commit generation (distance from the nearest tip, 0 = the tips
// themselves). Trees and blobs are recorded with generation -1 (they are not
// commits). The walk stops descending past maxGen generations when maxGen >= 0.
func collectReachable(repoDir string, tips []string, maxGen int) (objects map[string]string, gen map[string]int) {
	objects = map[string]string{}
	gen = map[string]int{}
	type item struct {
		sha string
		g   int
	}
	queue := []item{}
	for _, t := range tips {
		t = strings.ToLower(t)
		if t == "" || t == zeroOID {
			continue
		}
		queue = append(queue, item{t, 0})
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if _, done := objects[it.sha]; done {
			continue
		}
		typ, raw, err := ReadObject(repoDir, it.sha)
		if err != nil {
			continue
		}
		objects[it.sha] = typ
		if typ != "commit" {
			continue
		}
		gen[it.sha] = it.g
		c := ParseCommit(raw)
		// Record the commit's tree and blobs.
		collectTree(repoDir, c.Tree, objects)
		if maxGen >= 0 && it.g >= maxGen {
			continue
		}
		for _, p := range c.Parents {
			queue = append(queue, item{strings.ToLower(p), it.g + 1})
		}
	}
	return objects, gen
}

// gitIsDirMode reports whether a tree entry mode denotes a directory (a tree
// object). Git stores the directory mode as "40000"; some writers (including
// this forge's own REST layer) emit "040000". A prefix check for "04" is
// wrong: "40000" does not start with "04", so subtrees would silently be
// skipped (and their blobs never sent on fetch).
func gitIsDirMode(mode string) bool {
	n, err := strconv.ParseInt(strings.TrimLeft(mode, "0"), 8, 32)
	if err != nil {
		return mode == "40000" || mode == "040000"
	}
	return n == 0o40000
}

// collectTree records a tree and everything under it (recursively) in objects.
func collectTree(repoDir, treeSHA string, objects map[string]string) {
	treeSHA = strings.ToLower(treeSHA)
	if treeSHA == "" || treeSHA == zeroOID {
		return
	}
	if _, done := objects[treeSHA]; done {
		return
	}
	typ, raw, err := ReadObject(repoDir, treeSHA)
	if err != nil || typ != "tree" {
		return
	}
	objects[treeSHA] = "tree"
	for _, e := range parseTree(raw) {
		if gitIsDirMode(e.Mode) {
			collectTree(repoDir, e.SHA, objects)
			continue
		}
		if _, done := objects[e.SHA]; !done {
			objects[e.SHA] = "blob"
		}
	}
}

// sortedKeys returns the map's keys in sorted order (deterministic pack order).
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
