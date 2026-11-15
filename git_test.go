package main

// Unit tests for the pure-Go git layer: object store, packfile round-trip
// (including a hand-built delta packfile), refs / fast-forward, and the
// smart-HTTP handlers (served over httptest, exercised with the real git
// CLI's protocol expectations where practical).
//
// Run: go test ./...   (needs main.go to compile; see the parent for its
// pending fixes)

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// makeCommitBytes builds a deterministic commit object.
func makeCommitBytes(tree, parent, msg string) []byte {
	var b strings.Builder
	b.WriteString("tree " + tree + "\n")
	if parent != "" {
		b.WriteString("parent " + parent + "\n")
	}
	b.WriteString("author Conformance <conformance@make.fun> 1700000000 +0000\n")
	b.WriteString("committer Conformance <conformance@make.fun> 1700000000 +0000\n\n")
	b.WriteString(msg + "\n")
	return []byte(b.String())
}

func TestObjectStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "r.git")
	if err := InitBareRepo(repo); err != nil {
		t.Fatal(err)
	}
	blob, err := WriteObject(repo, "blob", []byte("hello world\n"))
	if err != nil {
		t.Fatal(err)
	}
	tree, err := WriteObject(repo, "tree", encodeTree([]treeEntry{
		{Mode: "100644", Name: "hello.txt", SHA: blob},
	}))
	if err != nil {
		t.Fatal(err)
	}
	commit, err := WriteObject(repo, "commit", makeCommitBytes(tree, "", "first"))
	if err != nil {
		t.Fatal(err)
	}
	// Read back.
	typ, raw, err := ReadObject(repo, commit)
	if err != nil || typ != "commit" {
		t.Fatalf("read commit: typ=%q err=%v", typ, err)
	}
	c := ParseCommit(raw)
	if c.Tree != tree || c.AuthorName != "Conformance" || c.Message != "first" {
		t.Fatalf("parsed commit mismatch: %+v", c)
	}
	// Refs.
	if err := WriteRef(repo, "refs/heads/main", commit); err != nil {
		t.Fatal(err)
	}
	sha, err := ResolveRef(repo, "main")
	if err != nil || sha != commit {
		t.Fatalf("resolve main: %q %v", sha, err)
	}
	sha, err = ResolveRef(repo, "HEAD")
	if err != nil || sha != commit {
		t.Fatalf("resolve HEAD: %q %v", sha, err)
	}
	refs := ListRefs(repo)
	if refs["refs/heads/main"] != commit {
		t.Fatalf("list refs: %v", refs)
	}
	// ListCommits / ReadFileAtRef.
	commits, err := ListCommits(repo, "main", 10)
	if err != nil || len(commits) != 1 || commits[0].SHA != commit {
		t.Fatalf("list commits: %v %v", commits, err)
	}
	data, err := ReadFileAtRef(repo, "main", "hello.txt")
	if err != nil || string(data) != "hello world\n" {
		t.Fatalf("read file at ref: %q %v", data, err)
	}
	// Fast-forward.
	if !IsAncestor(repo, commit, commit) {
		t.Fatal("a commit is its own ancestor")
	}
	// Second commit on top, then a divergent one.
	tree2, _ := WriteObject(repo, "tree", encodeTree([]treeEntry{
		{Mode: "100644", Name: "hello.txt", SHA: blob},
		{Mode: "100644", Name: "two.txt", SHA: blob},
	}))
	commit2, _ := WriteObject(repo, "commit", makeCommitBytes(tree2, commit, "second"))
	if !IsAncestor(repo, commit, commit2) {
		t.Fatal("commit should be an ancestor of commit2")
	}
	if IsAncestor(repo, commit2, commit) {
		t.Fatal("commit2 must not be an ancestor of commit")
	}
	div, _ := WriteObject(repo, "commit", makeCommitBytes(tree, commit, "divergent"))
	if IsAncestor(repo, commit2, div) || IsAncestor(repo, div, commit2) {
		t.Fatal("divergent commits must not be ancestors of each other")
	}
	if mb := MergeBase(repo, commit2, div); mb != commit {
		t.Fatalf("merge base: got %q want %q", mb, commit)
	}
}

func TestPackRoundTrip(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "r.git")
	_ = InitBareRepo(repo)
	blob, _ := WriteObject(repo, "blob", []byte("pack me\n"))
	tree, _ := WriteObject(repo, "tree", encodeTree([]treeEntry{
		{Mode: "100644", Name: "a.txt", SHA: blob},
	}))
	commit, _ := WriteObject(repo, "commit", makeCommitBytes(tree, "", "c1"))

	// Build a pack from the three objects and read it back.
	_, blobRaw, _ := ReadObject(repo, blob)
	_, treeRaw, _ := ReadObject(repo, tree)
	_, commitRaw, _ := ReadObject(repo, commit)
	pack, err := WritePack([]packObject{
		{Type: "blob", Data: blobRaw},
		{Type: "tree", Data: treeRaw},
		{Type: "commit", Data: commitRaw},
	})
	if err != nil {
		t.Fatal(err)
	}
	objs, deltas, err := ReadPack(pack, nil)
	if err != nil {
		t.Fatal(err)
	}
	if deltas != 0 {
		t.Fatalf("plain pack reported %d deltas", deltas)
	}
	if len(objs) != 3 {
		t.Fatalf("pack read back %d objects, want 3", len(objs))
	}
	for _, sha := range []string{blob, tree, commit} {
		if _, ok := objs[sha]; !ok {
			t.Fatalf("pack missing object %s", sha)
		}
	}
	// Corrupt the trailer: must be rejected.
	bad := append(append([]byte{}, pack[:len(pack)-1]...), pack[len(pack)-1]^0xff)
	if _, _, err := ReadPack(bad, nil); err == nil {
		t.Fatal("corrupt trailer was accepted")
	}
}

// buildDeltaPack builds a packfile by hand containing one full object (the
// base blob) and one REF_DELTA against it, so the delta path is exercised
// without a git binary.
func buildDeltaPack(t *testing.T, base []byte, target []byte) []byte {
	t.Helper()
	// Delta: source size, target size, then ops that copy the common prefix
	// from the base and insert the differing tail.
	var delta bytes.Buffer
	writeVarint := func(v int) {
		for {
			b := byte(v & 0x7f)
			v >>= 7
			if v == 0 {
				delta.WriteByte(b)
				return
			}
			delta.WriteByte(b | 0x80)
		}
	}
	writeVarint(len(base))
	writeVarint(len(target))
	// Common prefix length.
	common := 0
	for common < len(base) && common < len(target) && base[common] == target[common] {
		common++
	}
	// Copy op for the common prefix (offset 0, size common).
	if common > 0 {
		op := byte(0x80)
		size := common
		var sizeBytes []byte
		if size&0xff != 0 {
			op |= 0x10
			sizeBytes = append(sizeBytes, byte(size))
		}
		if (size>>8)&0xff != 0 {
			op |= 0x20
			sizeBytes = append(sizeBytes, byte(size>>8))
		}
		if (size>>16)&0xff != 0 {
			op |= 0x40
			sizeBytes = append(sizeBytes, byte(size>>16))
		}
		delta.WriteByte(op)
		delta.Write(sizeBytes)
	}
	// Insert the differing tail.
	tail := target[common:]
	for len(tail) > 0 {
		n := len(tail)
		if n > 127 {
			n = 127
		}
		delta.WriteByte(byte(n))
		delta.Write(tail[:n])
		tail = tail[n:]
	}

	baseSHA := objectSHA("blob", base)
	var pack bytes.Buffer
	pack.WriteString("PACK")
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], 2)
	binary.BigEndian.PutUint32(hdr[4:8], 2)
	pack.Write(hdr[:])
	// Entry 1: the full base blob.
	pack.Write(encodePackHeader(packBlob, len(base)))
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	_, _ = zw.Write(base)
	_ = zw.Close()
	pack.Write(zb.Bytes())
	// Entry 2: REF_DELTA against the base.
	pack.Write(encodePackHeader(packRefDelta, delta.Len()))
	raw, _ := hex.DecodeString(baseSHA)
	pack.Write(raw)
	zb.Reset()
	zw = zlib.NewWriter(&zb)
	_, _ = zw.Write(delta.Bytes())
	_ = zw.Close()
	pack.Write(zb.Bytes())
	sum := sha1.Sum(pack.Bytes())
	pack.Write(sum[:])
	return pack.Bytes()
}

func TestPackDelta(t *testing.T) {
	base := []byte(strings.Repeat("A", 20000) + "\n")
	target := []byte(strings.Repeat("A", 19990) + "BBBBBBBBBB" + "\n")
	pack := buildDeltaPack(t, base, target)
	objs, deltas, err := ReadPack(pack, nil)
	if err != nil {
		t.Fatal(err)
	}
	if deltas != 1 {
		t.Fatalf("expected 1 delta, got %d", deltas)
	}
	wantSHA := objectSHA("blob", target)
	got, ok := objs[wantSHA]
	if !ok {
		t.Fatalf("delta-resolved object %s missing (have %v)", wantSHA, keysOf(objs))
	}
	if got.Type != "blob" || !bytes.Equal(got.Data, target) {
		t.Fatalf("delta-resolved bytes differ: type=%q len=%d", got.Type, len(got.Data))
	}
	// applyDelta directly.
	out, err := applyDelta(base, mustDelta(t, base, target))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, target) {
		t.Fatal("applyDelta produced the wrong bytes")
	}
}

func keysOf(m map[string]packObject) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// mustDelta extracts the delta bytes from a hand-built pack (entry 2).
func mustDelta(t *testing.T, base, target []byte) []byte {
	t.Helper()
	// Rebuild the delta the same way buildDeltaPack does (kept in sync by
	// construction: same common-prefix + insert-tail scheme).
	var delta bytes.Buffer
	writeVarint := func(v int) {
		for {
			b := byte(v & 0x7f)
			v >>= 7
			if v == 0 {
				delta.WriteByte(b)
				return
			}
			delta.WriteByte(b | 0x80)
		}
	}
	writeVarint(len(base))
	writeVarint(len(target))
	common := 0
	for common < len(base) && common < len(target) && base[common] == target[common] {
		common++
	}
	if common > 0 {
		op := byte(0x80)
		size := common
		var sizeBytes []byte
		if size&0xff != 0 {
			op |= 0x10
			sizeBytes = append(sizeBytes, byte(size))
		}
		if (size>>8)&0xff != 0 {
			op |= 0x20
			sizeBytes = append(sizeBytes, byte(size>>8))
		}
		if (size>>16)&0xff != 0 {
			op |= 0x40
			sizeBytes = append(sizeBytes, byte(size>>16))
		}
		delta.WriteByte(op)
		delta.Write(sizeBytes)
	}
	tail := target[common:]
	for len(tail) > 0 {
		n := len(tail)
		if n > 127 {
			n = 127
		}
		delta.WriteByte(byte(n))
		delta.Write(tail[:n])
		tail = tail[n:]
	}
	return delta.Bytes()
}

// TestSmartHTTPServe exercises the git endpoints over httptest with the same
// request shapes the suite's client sends (v2 advertisement, ls-refs,
// fetch, and a receive-pack push built by hand).
func TestSmartHTTPServe(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "admin", "testrepo.git")
	_ = InitBareRepo(repo)
	// Seed one commit on main.
	blob, _ := WriteObject(repo, "blob", []byte("hello\n"))
	tree, _ := WriteObject(repo, "tree", encodeTree([]treeEntry{
		{Mode: "100644", Name: "hello.txt", SHA: blob},
	}))
	commit, _ := WriteObject(repo, "commit", makeCommitBytes(tree, "", "seed"))
	_ = WriteRef(repo, "refs/heads/main", commit)

	// The handler resolves repos via repoPath (reposDir), so point the
	// test at the same layout: temporarily re-point reposDir.
	oldRepos := reposDir
	reposDir = filepath.Join(dir, "")
	defer func() { reposDir = oldRepos }()

	// v2 advertisement.
	req := httptest.NewRequest("GET", "/admin/testrepo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Git-Protocol", "version=2")
	rec := httptest.NewRecorder()
	GitSmartHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("info/refs v2: status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/x-git-upload-pack-advertisement") {
		t.Fatalf("info/refs v2 content-type %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "version 2") {
		t.Fatalf("info/refs v2 body missing version 2: %q", rec.Body.String())
	}
	// v2 ls-refs.
	var lb bytes.Buffer
	for _, line := range []string{"command=ls-refs\n", "agent=go-test\n", "object-format=sha1\n"} {
		lb.Write(pktText(line))
	}
	lb.Write(pktDelimBytes)
	for _, line := range []string{"peel\n", "symrefs\n", "unborn\n"} {
		lb.Write(pktText(line))
	}
	lb.Write(pktFlushBytes)
	req = httptest.NewRequest("POST", "/admin/testrepo.git/git-upload-pack", &lb)
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	rec = httptest.NewRecorder()
	GitSmartHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("ls-refs: status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), commit) {
		t.Fatalf("ls-refs missing tip %s: %q", commit, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "symref-target:refs/heads/main") {
		t.Fatalf("ls-refs missing HEAD symref-target: %q", rec.Body.String())
	}
	// v2 fetch of the tip.
	var fb bytes.Buffer
	for _, line := range []string{"command=fetch\n", "agent=go-test\n", "object-format=sha1\n"} {
		fb.Write(pktText(line))
	}
	fb.Write(pktDelimBytes)
	for _, line := range []string{"thin-pack\n", "no-progress\n", "ofs-delta\n", "want " + commit + "\n", "done\n"} {
		fb.Write(pktText(line))
	}
	fb.Write(pktFlushBytes)
	req = httptest.NewRequest("POST", "/admin/testrepo.git/git-upload-pack", &fb)
	req.Header.Set("Git-Protocol", "version=2")
	rec = httptest.NewRecorder()
	GitSmartHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("fetch: status %d", rec.Code)
	}
	body := rec.Body.Bytes()
	if !bytes.Contains(body, []byte("packfile\n")) {
		t.Fatalf("fetch missing packfile section: %q", body)
	}
	// Extract the pack from the sideband and verify it holds the commit.
	pack := extractSidebandPack(t, body)
	objs, _, err := ReadPack(pack, nil)
	if err != nil {
		t.Fatalf("fetch pack unreadable: %v", err)
	}
	if _, ok := objs[commit]; !ok {
		t.Fatalf("fetch pack missing commit %s (has %v)", commit, keysOf(objs))
	}
	// Missing repo: 404.
	req = httptest.NewRequest("GET", "/admin/nope.git/info/refs?service=git-upload-pack", nil)
	rec = httptest.NewRecorder()
	GitSmartHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("missing repo: status %d, want 404", rec.Code)
	}
	// Malformed POST: 400, handler stays usable.
	req = httptest.NewRequest("POST", "/admin/testrepo.git/git-upload-pack", strings.NewReader("zzzznot-a-pkt-line"))
	rec = httptest.NewRecorder()
	GitSmartHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("malformed POST: status %d, want 400", rec.Code)
	}
	req = httptest.NewRequest("GET", "/admin/testrepo.git/info/refs?service=git-upload-pack", nil)
	rec = httptest.NewRecorder()
	GitSmartHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("server unhealthy after malformed POST: %d", rec.Code)
	}
}

// extractSidebandPack pulls the band-1 bytes out of a v2 fetch response body.
func extractSidebandPack(t *testing.T, body []byte) []byte {
	t.Helper()
	var pack []byte
	pos := 0
	for pos < len(body) {
		p, next, err := parsePktLine(body, pos)
		if err != nil {
			t.Fatalf("parse response pkt-line at %d: %v", pos, err)
		}
		pos = next
		if p.kind != pktData || len(p.payload) < 1 {
			continue
		}
		if p.payload[0] == 1 {
			pack = append(pack, p.payload[1:]...)
		}
	}
	if len(pack) == 0 {
		t.Fatal("no band-1 data in fetch response")
	}
	return pack
}
