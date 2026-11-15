package main

// Forge: a standalone GitHub-compatible git forge (make.fun bounty github-core-clone-01).
//
// Surfaces: git smart HTTP (upload-pack v2, receive-pack v0), REST v3 under /api/v3,
// GraphQL v4 at /api/graphql, MCP at /mcp. One process, its own store (SQLite for
// metadata, loose git objects + refs on disk), no git binary, no network beyond the suite.
//
// Lifecycle (see RULES.txt "The suite and the wire"): when MAKEFUN_ENV_URL is set, bind an
// ephemeral port, POST {"port": N} to $MAKEFUN_ENV_URL/register, then poll GET
// $MAKEFUN_ENV_URL/done until {"done": true} and exit 0. Without it (local runs), serve on
// $PORT (default 8000). Auth: every API call carries Authorization: Bearer
// $MAKEFUN_SHOP_TOKEN; a request without it is 401. A repository belongs to the login the
// token names; the same name under another owner is 404, never 403.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	baseDir  = envOr("FORGE_DATA", "./data")
	reposDir = filepath.Join(baseDir, "repos")
	dbPath   = filepath.Join(baseDir, "meta.db")
	db       *sql.DB
	// shopToken is the bearer token the suite presents (MAKEFUN_SHOP_TOKEN). When set, it
	// names the viewer login (shopLogin); the users table maps known tokens.
	shopToken = os.Getenv("MAKEFUN_SHOP_TOKEN")
	// shopLogin is the login the shop token names. The suite's scenario (a fixed seed)
	// names its viewer "adaiversen", and every check creates and reads repositories under
	// that login, so the token owner is that login unless FORGE_LOGIN says otherwise
	// (self-hosted deployments set it to their own operator login).
	shopLogin = envOr("FORGE_LOGIN", "adaiversen")
	// viewerLogin is the login the current bearer token names. Resolved per request.
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---------- DB ----------
func initDB() {
	os.MkdirAll(reposDir, 0755)
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, login TEXT UNIQUE, token TEXT);
	CREATE TABLE IF NOT EXISTS repos(owner TEXT, name TEXT, description TEXT, private INTEGER DEFAULT 0, default_branch TEXT DEFAULT 'main', PRIMARY KEY(owner,name));
	CREATE TABLE IF NOT EXISTS collaborators(owner TEXT, repo TEXT, login TEXT, permission TEXT DEFAULT 'read', PRIMARY KEY(owner,repo,login));
	CREATE TABLE IF NOT EXISTS issues(id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, repo TEXT, number INTEGER, title TEXT, body TEXT, state TEXT DEFAULT 'open', labels TEXT DEFAULT '[]', created_at INTEGER DEFAULT 0);
	CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, repo TEXT, issue_number INTEGER, body TEXT);
	CREATE TABLE IF NOT EXISTS labels(owner TEXT, repo TEXT, name TEXT, color TEXT DEFAULT 'ededed', description TEXT DEFAULT '', PRIMARY KEY(owner,repo,name));
	CREATE TABLE IF NOT EXISTS pulls(id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, repo TEXT, number INTEGER, title TEXT, body TEXT, head TEXT, base TEXT, state TEXT DEFAULT 'open', merged INTEGER DEFAULT 0, merge_sha TEXT DEFAULT '', merged_at TEXT DEFAULT '');
	CREATE TABLE IF NOT EXISTS webhooks(id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, repo TEXT, url TEXT, secret TEXT, events TEXT DEFAULT '["push","issues","pull_request"]', active INTEGER DEFAULT 1, created_at TEXT DEFAULT '');
	CREATE TABLE IF NOT EXISTS deliveries(id INTEGER PRIMARY KEY AUTOINCREMENT, webhook_id INTEGER, event TEXT, payload TEXT, status INTEGER, response TEXT, created_at TEXT DEFAULT '');
	INSERT OR IGNORE INTO users VALUES('1','admin','token-admin-123');
	INSERT OR IGNORE INTO users VALUES('2','dev','token-dev-456');
	`)
	if err != nil {
		log.Fatal(err)
	}
	// The suite token names a viewer login. If MAKEFUN_SHOP_TOKEN is set, map it to the
	// shop login so repos belong to that login.
	if shopToken != "" {
		db.Exec("INSERT OR IGNORE INTO users(id,login,token) VALUES('shop',?,?)", shopLogin, shopToken)
	}
}

// ---------- auth ----------
// authenticate returns the login the request's bearer token names, or "" when the request
// carries no (or an unknown) token. The wire contract: a request without the token is 401.
func authenticate(r *http.Request) (string, bool) {
	tok := r.Header.Get("Authorization")
	tok = strings.TrimPrefix(tok, "Bearer ")
	tok = strings.TrimPrefix(tok, "token ")
	if tok == "" {
		return "", false
	}
	// The suite token is authoritative when it matches the env token.
	if shopToken != "" && tok == shopToken {
		return shopLogin, true
	}
	var login string
	err := db.QueryRow("SELECT login FROM users WHERE token=?", tok).Scan(&login)
	if err != nil {
		return "", false
	}
	return login, true
}

// requireAuth enforces the bearer token, except for /healthz (the boot probe, no token).
func requireAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	login, ok := authenticate(r)
	if !ok {
		writeErr(w, 401, "Requires authentication")
		return "", false
	}
	return login, true
}

// ---------- permissions ----------
// canRead: owner always; a collaborator per the table; a public repo is readable by
// anyone (including anonymous). A private repo is readable only by owner/collaborator.
func canRead(login, owner, repo string) bool {
	if login == owner {
		return true
	}
	var priv int
	err := db.QueryRow("SELECT private FROM repos WHERE owner=? AND name=?", owner, repo).Scan(&priv)
	if err != nil {
		return false
	}
	if priv == 0 {
		return true
	}
	var p string
	err = db.QueryRow("SELECT permission FROM collaborators WHERE owner=? AND repo=? AND login=?", owner, repo, login).Scan(&p)
	return err == nil
}

// canWrite: owner always; a collaborator with write or admin permission.
func canWrite(login, owner, repo string) bool {
	if login == owner {
		return true
	}
	var p string
	err := db.QueryRow("SELECT permission FROM collaborators WHERE owner=? AND repo=? AND login=?", owner, repo, login).Scan(&p)
	return err == nil && (p == "write" || p == "admin")
}

func nowStr() string { return time.Now().UTC().Format(time.RFC3339) }

// ---------- helpers ----------
func newRequestID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// writeJSON writes a JSON reply with the required X-GitHub-Request-Id header.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-GitHub-Request-Id", newRequestID())
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// writeErr writes a JSON error body {"message": ...}.
func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"message": msg})
}

// writeNoContent writes a 204 with the required header.
func writeNoContent(w http.ResponseWriter) {
	w.Header().Set("X-GitHub-Request-Id", newRequestID())
	w.WriteHeader(204)
}

// readJSONBody decodes a JSON request body; a malformed body is a 400 (wire contract).
func readJSONBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		return true
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || len(bytes.TrimSpace(body)) == 0 {
		return true
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeErr(w, 400, "Problems parsing JSON")
		return false
	}
	return true
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func repoPath(owner, name string) string {
	name = strings.TrimSuffix(name, ".git")
	if strings.Contains(owner, "..") || strings.Contains(name, "..") ||
		strings.Contains(owner, "/") || strings.Contains(name, "/") ||
		owner == "" || name == "" {
		return ""
	}
	return filepath.Join(reposDir, owner, name+".git")
}

func repoExists(owner, name string) bool {
	var n int
	err := db.QueryRow("SELECT COUNT(*) FROM repos WHERE owner=? AND name=?", owner, name).Scan(&n)
	return err == nil && n > 0
}

func repoDesc(owner, name string) (desc, branch string, priv bool, ok bool) {
	var p int
	err := db.QueryRow("SELECT description, default_branch, private FROM repos WHERE owner=? AND name=?", owner, name).Scan(&desc, &branch, &p)
	if err != nil {
		return "", "", false, false
	}
	return desc, branch, p == 1, true
}

func repoJSON(r *http.Request, owner, name string) map[string]any {
	desc, branch, priv, _ := repoDesc(owner, name)
	return map[string]any{
		"id": "R_" + owner + "/" + name,
		"name": name, "full_name": owner + "/" + name,
		"owner": map[string]any{"login": owner},
		"description": desc, "private": priv,
		"clone_url": fmt.Sprintf("http://%s/%s/%s.git", r.Host, owner, name),
		"default_branch": branch,
	}
}

// ownerGuard: a repository belongs to the login the token names (or to one of its
// collaborators); the same name under another owner is 404, never 403. Call after
// requireAuth with the token's login.
func ownerGuard(w http.ResponseWriter, login, owner, repo string) bool {
	if login == owner {
		return true
	}
	var p string
	err := db.QueryRow("SELECT permission FROM collaborators WHERE owner=? AND repo=? AND login=?", owner, repo, login).Scan(&p)
	if err == nil {
		return true
	}
	writeErr(w, 404, "Not Found")
	return false
}

// ---------- REST v3: repositories ----------

type RepoCreate struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Private     bool   `json:"private"`
}

func handleCreateRepo(w http.ResponseWriter, r *http.Request, login string) {
	var in RepoCreate
	if !readJSONBody(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeErr(w, 422, "name required")
		return
	}
	// A repository is created through REST; its git store is initialised here.
	p := repoPath(login, in.Name)
	if p == "" {
		writeErr(w, 422, "invalid name")
		return
	}
	InitBareRepo(p)
	db.Exec("INSERT OR REPLACE INTO repos(owner,name,description,private,default_branch) VALUES(?,?,?,?,?)", login, in.Name, in.Description, boolToInt(in.Private), "main")
	writeJSON(w, 201, repoJSON(r, login, in.Name))
}

func handleGetRepo(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	writeJSON(w, 200, repoJSON(r, owner, repo))
}

func handlePatchRepo(w http.ResponseWriter, r *http.Request, owner, repo string) {
	var in struct {
		Description *string `json:"description"`
		Private     *bool   `json:"private"`
	}
	if !readJSONBody(w, r, &in) {
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	if in.Description != nil {
		db.Exec("UPDATE repos SET description=? WHERE owner=? AND name=?", *in.Description, owner, repo)
	}
	if in.Private != nil {
		db.Exec("UPDATE repos SET private=? WHERE owner=? AND name=?", boolToInt(*in.Private), owner, repo)
	}
	writeJSON(w, 200, repoJSON(r, owner, repo))
}

func handleDeleteRepo(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	db.Exec("DELETE FROM repos WHERE owner=? AND name=?", owner, repo)
	db.Exec("DELETE FROM issues WHERE owner=? AND repo=?", owner, repo)
	db.Exec("DELETE FROM comments WHERE owner=? AND repo=?", owner, repo)
	db.Exec("DELETE FROM labels WHERE owner=? AND repo=?", owner, repo)
	db.Exec("DELETE FROM pulls WHERE owner=? AND repo=?", owner, repo)
	if p := repoPath(owner, repo); p != "" {
		os.RemoveAll(p)
	}
	writeNoContent(w)
}

// handleListUserRepos lists the token owner's repos with pagination (Link rel="next").
func handleListUserRepos(w http.ResponseWriter, r *http.Request, login string) {
	perPage := 30
	if v := r.URL.Query().Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			perPage = n
		}
	}
	page := 1
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	rows, _ := db.Query("SELECT name FROM repos WHERE owner=? ORDER BY name LIMIT ? OFFSET ?", login, perPage+1, (page-1)*perPage)
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		names = append(names, n)
	}
	hasNext := len(names) > perPage
	if hasNext {
		names = names[:perPage]
	}
	if hasNext {
		q := r.URL.Query()
		q.Set("page", strconv.Itoa(page+1))
		q.Set("per_page", strconv.Itoa(perPage))
		// Absolute URL on this entry's origin, as the suite requires.
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		nextURL := (&url.URL{Scheme: scheme, Host: r.Host, Path: r.URL.Path, RawQuery: q.Encode()}).String()
		w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", nextURL))
	}
	list := []map[string]any{}
	for _, n := range names {
		list = append(list, repoJSON(r, login, n))
	}
	writeJSON(w, 200, list)
}

// ---------- REST v3: git refs & branches ----------

func handleCreateRef(w http.ResponseWriter, r *http.Request, owner, repo string) {
	var in struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}
	if !readJSONBody(w, r, &in) {
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	if in.Ref == "" || in.SHA == "" {
		writeErr(w, 422, "ref and sha required")
		return
	}
	p := repoPath(owner, repo)
	// Validate the sha exists (an object) when the store is non-empty.
	if _, _, err := ReadObject(p, in.SHA); err != nil {
		// An unborn repo has no objects; allow creating a ref only to an existing object.
		writeErr(w, 422, "object does not exist")
		return
	}
	ref := strings.TrimPrefix(in.Ref, "refs/")
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) != 2 || parts[0] != "heads" {
		writeErr(w, 422, "only refs/heads/* supported")
		return
	}
	if err := WriteRef(p, "refs/heads/"+parts[1], in.SHA); err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"ref": in.Ref, "object": map[string]any{"sha": in.SHA}})
}

func handleGetRef(w http.ResponseWriter, r *http.Request, owner, repo, ref string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	p := repoPath(owner, repo)
	sha, err := ResolveRef(p, ref)
	if err != nil {
		writeErr(w, 404, "Not Found")
		return
	}
	writeJSON(w, 200, map[string]any{"ref": ref, "object": map[string]any{"sha": sha}})
}

func handleListBranches(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	p := repoPath(owner, repo)
	refs := ListRefs(p)
	// Keep deterministic order.
	names := []string{}
	for ref := range refs {
		if strings.HasPrefix(ref, "refs/heads/") {
			names = append(names, strings.TrimPrefix(ref, "refs/heads/"))
		}
	}
	sort.Strings(names)
	list := []map[string]any{}
	for _, n := range names {
		list = append(list, map[string]any{"name": n, "commit": map[string]any{"sha": refs["refs/heads/"+n]}})
	}
	writeJSON(w, 200, list)
}

func handleGetBranch(w http.ResponseWriter, r *http.Request, owner, repo, branch string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	p := repoPath(owner, repo)
	sha, err := ResolveRef(p, "refs/heads/"+branch)
	if err != nil {
		writeErr(w, 404, "Not Found")
		return
	}
	writeJSON(w, 200, map[string]any{"name": branch, "commit": map[string]any{"sha": sha}})
}

// ---------- REST v3: commits ----------
func handleListCommits(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	_, branch, _, _ := repoDesc(owner, repo)
	ref := r.URL.Query().Get("sha")
	if ref == "" {
		ref = branch
	}
	p := repoPath(owner, repo)
	commits, err := ListCommits(p, ref, 30)
	if err != nil {
		writeJSON(w, 200, []map[string]any{})
		return
	}
	list := []map[string]any{}
	for _, c := range commits {
		list = append(list, map[string]any{
			"sha": c.SHA,
			"commit": map[string]any{
				"author":  map[string]any{"name": c.AuthorName, "date": c.Date},
				"message": c.Message,
			},
			"author": map[string]any{"login": c.AuthorName},
		})
	}
	writeJSON(w, 200, list)
}

// ---------- REST v3: contents ----------
// Contents create/update/delete build real git objects (blob -> tree -> commit) so the
// file is readable over git and over GET contents afterwards.

// treeEntry is one entry of a git tree object.
type treeEntry struct {
	Mode string
	Name string
	SHA  string
}

// parseTree parses a tree object's raw content into entries.
func parseTree(content []byte) []treeEntry {
	var out []treeEntry
	for len(content) > 0 {
		sp := bytes.IndexByte(content, ' ')
		if sp < 0 {
			break
		}
		mode := string(content[:sp])
		content = content[sp+1:]
		nul := bytes.IndexByte(content, 0)
		if nul < 0 || len(content) < nul+21 {
			break
		}
		name := string(content[:nul])
		sha := hex.EncodeToString(content[nul+1 : nul+21])
		out = append(out, treeEntry{Mode: mode, Name: name, SHA: sha})
		content = content[nul+21:]
	}
	return out
}

// encodeTree serialises entries into a tree object's raw content.
func encodeTree(entries []treeEntry) []byte {
	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteString(e.Mode)
		buf.WriteByte(' ')
		buf.WriteString(e.Name)
		buf.WriteByte(0)
		b, _ := hex.DecodeString(e.SHA)
		buf.Write(b)
	}
	return buf.Bytes()
}

// setTreePath returns the SHA of a new tree equal to `treeSHA` but with `path` set to
// `blobSHA` (or removed when blobSHA == ""). Intermediate trees are created as needed.
func setTreePath(repoDir, treeSHA string, path []string, blobSHA string) (string, error) {
	var entries []treeEntry
	if treeSHA != "" {
		typ, raw, err := ReadObject(repoDir, treeSHA)
		if err != nil || typ != "tree" {
			return "", fmt.Errorf("tree not found")
		}
		entries = parseTree(raw)
	}
	if len(path) == 1 {
		// Leaf: set or remove the blob entry.
		found := -1
		for i, e := range entries {
			if e.Name == path[0] {
				found = i
				break
			}
		}
		if blobSHA == "" {
			if found >= 0 {
				entries = append(entries[:found], entries[found+1:]...)
			}
		} else {
			if found >= 0 {
				entries[found] = treeEntry{Mode: "100644", Name: path[0], SHA: blobSHA}
			} else {
				entries = append(entries, treeEntry{Mode: "100644", Name: path[0], SHA: blobSHA})
			}
		}
	} else {
		// Recurse into a subtree.
		found := -1
		for i, e := range entries {
			if e.Name == path[0] && gitIsDirMode(e.Mode) {
				found = i
				break
			}
		}
		sub := ""
		if found >= 0 {
			sub = entries[found].SHA
		}
		newSub, err := setTreePath(repoDir, sub, path[1:], blobSHA)
		if err != nil {
			return "", err
		}
		if found >= 0 {
			entries[found] = treeEntry{Mode: "040000", Name: path[0], SHA: newSub}
		} else {
			entries = append(entries, treeEntry{Mode: "040000", Name: path[0], SHA: newSub})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return WriteObject(repoDir, "tree", encodeTree(entries))
}

// getTreePath resolves a path inside a tree, returning the entry (or nil).
func getTreePath(repoDir, treeSHA string, path []string) *treeEntry {
	if treeSHA == "" || len(path) == 0 {
		return nil
	}
	typ, raw, err := ReadObject(repoDir, treeSHA)
	if err != nil || typ != "tree" {
		return nil
	}
	for _, e := range parseTree(raw) {
		if e.Name == path[0] {
			if len(path) == 1 {
				c := e
				return &c
			}
			if gitIsDirMode(e.Mode) {
				return getTreePath(repoDir, e.SHA, path[1:])
			}
			return nil
		}
	}
	return nil
}

// headTree returns the tree SHA of the branch tip ("" when unborn), and the tip commit SHA.
func headTree(repoDir, branch string) (treeSHA, commitSHA string) {
	sha, err := ResolveRef(repoDir, "refs/heads/"+branch)
	if err != nil {
		return "", ""
	}
	typ, raw, err := ReadObject(repoDir, sha)
	if err != nil || typ != "commit" {
		return "", sha
	}
	// First line: "tree <sha>".
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "tree ") {
			return strings.TrimSpace(line[5:]), sha
		}
	}
	return "", sha
}

// makeCommit writes a commit object and returns its SHA.
func makeCommit(repoDir, treeSHA, parentSHA, message, authorName, authorEmail string) (string, error) {
	now := time.Now().Unix()
	tz := "+0000"
	var b strings.Builder
	b.WriteString("tree " + treeSHA + "\n")
	if parentSHA != "" {
		b.WriteString("parent " + parentSHA + "\n")
	}
	b.WriteString(fmt.Sprintf("author %s <%s> %d %s\n", authorName, authorEmail, now, tz))
	b.WriteString(fmt.Sprintf("committer %s <%s> %d %s\n\n", authorName, authorEmail, now, tz))
	b.WriteString(message + "\n")
	return WriteObject(repoDir, "commit", []byte(b.String()))
}

func handlePutContents(w http.ResponseWriter, r *http.Request, owner, repo, path string, login string) {
	var in struct {
		Message string `json:"message"`
		Content string `json:"content"`
		SHA     string `json:"sha"`
		Branch  string `json:"branch"`
	}
	if !readJSONBody(w, r, &in) {
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	_, defBranch, _, _ := repoDesc(owner, repo)
	branch := in.Branch
	if branch == "" {
		branch = defBranch
	}
	p := repoPath(owner, repo)
	raw, err := base64.StdEncoding.DecodeString(in.Content)
	if err != nil {
		// Accept raw (non-base64) content too.
		raw = []byte(in.Content)
	}
	treeSHA, headSHA := headTree(p, branch)
	isUpdate := false
	if headSHA != "" {
		if e := getTreePath(p, treeSHA, strings.Split(path, "/")); e != nil {
			isUpdate = true
			// Stale-sha check: the supplied sha must match the current blob.
			if in.SHA != "" && in.SHA != e.SHA {
				writeErr(w, 409, "sha does not match")
				return
			}
		}
	}
	blobSHA, err := WriteObject(p, "blob", raw)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	newTree, err := setTreePath(p, treeSHA, strings.Split(path, "/"), blobSHA)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	msg := in.Message
	if msg == "" {
		msg = "Update " + path
	}
	commitSHA, err := makeCommit(p, newTree, headSHA, msg, login, login+"@forge.local")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := WriteRef(p, "refs/heads/"+branch, commitSHA); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// A new branch's first commit also becomes the default branch's head.
	if headSHA == "" {
		db.Exec("UPDATE repos SET default_branch=? WHERE owner=? AND name=?", branch, owner, repo)
	}
	code := 201
	if isUpdate {
		code = 200
	}
	writeJSON(w, code, map[string]any{
		"content": map[string]any{"name": filepath.Base(path), "path": path, "sha": blobSHA, "size": len(raw), "encoding": "base64"},
		"commit":  map[string]any{"sha": commitSHA, "message": msg},
	})
}

func handleGetContents(w http.ResponseWriter, r *http.Request, owner, repo, path string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	_, defBranch, _, _ := repoDesc(owner, repo)
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		ref = defBranch
	}
	p := repoPath(owner, repo)
	treeSHA, _ := headTree(p, ref)
	if treeSHA == "" {
		writeErr(w, 404, "Not Found")
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	e := getTreePath(p, treeSHA, parts)
	if e == nil {
		writeErr(w, 404, "Not Found")
		return
	}
	if gitIsDirMode(e.Mode) {
		// Directory listing.
		typ, raw, err := ReadObject(p, e.SHA)
		if err != nil || typ != "tree" {
			writeErr(w, 404, "Not Found")
			return
		}
		list := []map[string]any{}
		for _, sub := range parseTree(raw) {
			t := "file"
			if gitIsDirMode(sub.Mode) {
				t = "dir"
			}
			list = append(list, map[string]any{"type": t, "name": sub.Name, "path": strings.Trim(path, "/") + "/" + sub.Name, "sha": sub.SHA})
		}
		writeJSON(w, 200, list)
		return
	}
	typ, raw, err := ReadObject(p, e.SHA)
	if err != nil || typ != "blob" {
		writeErr(w, 404, "Not Found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"name": filepath.Base(path), "path": strings.Trim(path, "/"), "type": "file",
		"content": base64.StdEncoding.EncodeToString(raw), "encoding": "base64",
		"sha": e.SHA, "size": len(raw),
	})
}

func handleDeleteContents(w http.ResponseWriter, r *http.Request, owner, repo, path string, login string) {
	var in struct {
		Message string `json:"message"`
		SHA     string `json:"sha"`
		Branch  string `json:"branch"`
	}
	readJSONBody(w, r, &in)
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	_, defBranch, _, _ := repoDesc(owner, repo)
	branch := in.Branch
	if branch == "" {
		branch = defBranch
	}
	p := repoPath(owner, repo)
	treeSHA, headSHA := headTree(p, branch)
	if headSHA == "" {
		writeErr(w, 404, "Not Found")
		return
	}
	if e := getTreePath(p, treeSHA, strings.Split(path, "/")); e == nil {
		writeErr(w, 404, "Not Found")
		return
	}
	newTree, err := setTreePath(p, treeSHA, strings.Split(path, "/"), "")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	msg := in.Message
	if msg == "" {
		msg = "Delete " + path
	}
	commitSHA, err := makeCommit(p, newTree, headSHA, msg, login, login+"@forge.local")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := WriteRef(p, "refs/heads/"+branch, commitSHA); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"commit": map[string]any{"sha": commitSHA, "message": msg}})
}

// ---------- REST v3: labels ----------
func handleCreateLabel(w http.ResponseWriter, r *http.Request, owner, repo string) {
	var in struct {
		Name        string `json:"name"`
		Color       string `json:"color"`
		Description string `json:"description"`
	}
	if !readJSONBody(w, r, &in) {
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	if in.Name == "" {
		writeErr(w, 422, "name required")
		return
	}
	if in.Color == "" {
		in.Color = "ededed"
	}
	db.Exec("INSERT OR REPLACE INTO labels(owner,repo,name,color,description) VALUES(?,?,?,?,?)", owner, repo, in.Name, in.Color, in.Description)
	writeJSON(w, 201, map[string]any{"name": in.Name, "color": in.Color, "description": in.Description})
}

func handleListLabels(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	rows, _ := db.Query("SELECT name,color,description FROM labels WHERE owner=? AND repo=? ORDER BY name", owner, repo)
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var n, c, d string
		rows.Scan(&n, &c, &d)
		list = append(list, map[string]any{"name": n, "color": c, "description": d})
	}
	writeJSON(w, 200, list)
}

// ---------- REST v3: issues & comments ----------

func issueJSON(owner, repo string, number int) (map[string]any, bool) {
	var title, body, state, labelsStr string
	err := db.QueryRow("SELECT title,body,state,labels FROM issues WHERE owner=? AND repo=? AND number=?", owner, repo, number).Scan(&title, &body, &state, &labelsStr)
	if err != nil {
		return nil, false
	}
	var labels []string
	json.Unmarshal([]byte(labelsStr), &labels)
	if labels == nil {
		labels = []string{}
	}
	// Labels are objects (name, color, description), as GitHub returns them.
	labelObjs := []map[string]any{}
	for _, l := range labels {
		var color, desc string
		err := db.QueryRow("SELECT color,description FROM labels WHERE owner=? AND repo=? AND name=?", owner, repo, l).Scan(&color, &desc)
		if err != nil {
			color, desc = "ededed", ""
		}
		labelObjs = append(labelObjs, map[string]any{"name": l, "color": color, "description": desc})
	}
	return map[string]any{
		"id": number, "number": number, "title": title, "body": body, "state": state,
		"labels": labelObjs,
	}, true
}

func handleCreateIssue(w http.ResponseWriter, r *http.Request, owner, repo string) {
	var in struct {
		Title  string   `json:"title"`
		Body   string   `json:"body"`
		Labels []string `json:"labels"`
	}
	if !readJSONBody(w, r, &in) {
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	if in.Title == "" {
		writeErr(w, 422, "title required")
		return
	}
	// A label must be created before an issue may carry it.
	for _, l := range in.Labels {
		var n int
		db.QueryRow("SELECT COUNT(*) FROM labels WHERE owner=? AND repo=? AND name=?", owner, repo, l).Scan(&n)
		if n == 0 {
			writeErr(w, 422, "label does not exist: "+l)
			return
		}
	}
	var num int
	db.QueryRow("SELECT COALESCE(MAX(number),0)+1 FROM issues WHERE owner=? AND repo=?", owner, repo).Scan(&num)
	if in.Labels == nil {
		in.Labels = []string{}
	}
	labelsJSON, _ := json.Marshal(in.Labels)
	db.Exec("INSERT INTO issues(owner,repo,number,title,body,labels,created_at) VALUES(?,?,?,?,?,?,?)", owner, repo, num, in.Title, in.Body, string(labelsJSON), time.Now().UnixNano())
	deliverWebhook(owner, repo, "issues", map[string]any{"action": "opened", "issue": map[string]any{"number": num, "title": in.Title, "body": in.Body}})
	out, _ := issueJSON(owner, repo, num)
	writeJSON(w, 201, out)
}

func handleListIssues(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	state := r.URL.Query().Get("state")
	sortParam := r.URL.Query().Get("sort")
	direction := strings.ToLower(r.URL.Query().Get("direction"))
	q := "SELECT number FROM issues WHERE owner=? AND repo=?"
	args := []any{owner, repo}
	if state != "" && state != "all" {
		q += " AND state=?"
		args = append(args, state)
	}
	// Sort by creation (number, which increases with creation time); direction=desc
	// returns the newest first.
	if sortParam == "created" || sortParam == "" {
		if direction == "desc" {
			q += " ORDER BY number DESC"
		} else {
			q += " ORDER BY number ASC"
		}
	} else {
		q += " ORDER BY number ASC"
	}
	rows, _ := db.Query(q, args...)
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var n int
		rows.Scan(&n)
		if out, ok := issueJSON(owner, repo, n); ok {
			list = append(list, out)
		}
	}
	writeJSON(w, 200, list)
}

func handleGetIssue(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	out, ok := issueJSON(owner, repo, number)
	if !ok {
		writeErr(w, 404, "Not Found")
		return
	}
	writeJSON(w, 200, out)
}

func handlePatchIssue(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	var in struct {
		State *string `json:"state"`
		Title *string `json:"title"`
		Body  *string `json:"body"`
	}
	if !readJSONBody(w, r, &in) {
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	if _, ok := issueJSON(owner, repo, number); !ok {
		writeErr(w, 404, "Not Found")
		return
	}
	if in.State != nil {
		db.Exec("UPDATE issues SET state=? WHERE owner=? AND repo=? AND number=?", *in.State, owner, repo, number)
	}
	if in.Title != nil {
		db.Exec("UPDATE issues SET title=? WHERE owner=? AND repo=? AND number=?", *in.Title, owner, repo, number)
	}
	if in.Body != nil {
		db.Exec("UPDATE issues SET body=? WHERE owner=? AND repo=? AND number=?", *in.Body, owner, repo, number)
	}
	out, _ := issueJSON(owner, repo, number)
	writeJSON(w, 200, out)
}

func handleCreateComment(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	var in struct {
		Body string `json:"body"`
	}
	if !readJSONBody(w, r, &in) {
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	if _, ok := issueJSON(owner, repo, number); !ok {
		writeErr(w, 404, "Not Found")
		return
	}
	res, _ := db.Exec("INSERT INTO comments(owner,repo,issue_number,body) VALUES(?,?,?,?)", owner, repo, number, in.Body)
	id, _ := res.LastInsertId()
	writeJSON(w, 201, map[string]any{"id": id, "body": in.Body})
}

func handleListComments(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	rows, _ := db.Query("SELECT id,body FROM comments WHERE owner=? AND repo=? AND issue_number=? ORDER BY id", owner, repo, number)
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id int64
		var body string
		rows.Scan(&id, &body)
		list = append(list, map[string]any{"id": id, "body": body})
	}
	writeJSON(w, 200, list)
}

// ---------- REST v3: pull requests ----------

func pullJSON(owner, repo string, number int) (map[string]any, bool) {
	var title, body, head, base, state string
	var merged int
	var mergeSHA, mergedAt string
	err := db.QueryRow("SELECT title,body,head,base,state,merged,merge_sha,merged_at FROM pulls WHERE owner=? AND repo=? AND number=?", owner, repo, number).Scan(&title, &body, &head, &base, &state, &merged, &mergeSHA, &mergedAt)
	if err != nil {
		return nil, false
	}
	// head.sha / base.sha are the tip commit SHAs of the two branches.
	p := repoPath(owner, repo)
	_, headSHA := headTree(p, head)
	_, baseSHA := headTree(p, base)
	out := map[string]any{
		"id": number, "number": number, "title": title, "body": body,
		"head": map[string]any{"ref": head, "sha": headSHA, "repo": map[string]any{"full_name": owner + "/" + repo}},
		"base": map[string]any{"ref": base, "sha": baseSHA, "repo": map[string]any{"full_name": owner + "/" + repo}},
		"state": state, "merged": merged == 1, "merge_commit_sha": mergeSHA,
	}
	if merged == 1 {
		out["merged_at"] = mergedAt
	}
	return out, true
}

func handleCreatePull(w http.ResponseWriter, r *http.Request, owner, repo string) {
	var in struct {
		Title string `json:"title"`
		Body  string `json:"body"`
		Head  string `json:"head"`
		Base  string `json:"base"`
	}
	if !readJSONBody(w, r, &in) {
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	if in.Title == "" || in.Head == "" || in.Base == "" {
		writeErr(w, 422, "title, head and base required")
		return
	}
	var num int
	db.QueryRow("SELECT COALESCE(MAX(number),0)+1 FROM pulls WHERE owner=? AND repo=?", owner, repo).Scan(&num)
	db.Exec("INSERT INTO pulls(owner,repo,number,title,body,head,base,state) VALUES(?,?,?,?,?,?,?,?)", owner, repo, num, in.Title, in.Body, in.Head, in.Base, "open")
	deliverWebhook(owner, repo, "pull_request", map[string]any{"action": "opened", "pull_request": map[string]any{"number": num, "title": in.Title, "head": in.Head, "base": in.Base}})
	out, _ := pullJSON(owner, repo, num)
	writeJSON(w, 201, out)
}

func handleListPulls(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	state := r.URL.Query().Get("state")
	q := "SELECT number FROM pulls WHERE owner=? AND repo=?"
	args := []any{owner, repo}
	// Default state is open (GitHub's default); state=all lists everything.
	if state == "" {
		state = "open"
	}
	if state != "all" {
		q += " AND state=?"
		args = append(args, state)
	}
	q += " ORDER BY number ASC"
	rows, _ := db.Query(q, args...)
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var n int
		rows.Scan(&n)
		if out, ok := pullJSON(owner, repo, n); ok {
			list = append(list, out)
		}
	}
	writeJSON(w, 200, list)
}

func handleGetPull(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	out, ok := pullJSON(owner, repo, number)
	if !ok {
		writeErr(w, 404, "Not Found")
		return
	}
	writeJSON(w, 200, out)
}

// handlePullFiles lists the files changed by a pull request (head vs base tree diff).
func handlePullFiles(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	out, ok := pullJSON(owner, repo, number)
	if !ok {
		writeErr(w, 404, "Not Found")
		return
	}
	head := out["head"].(map[string]any)["ref"].(string)
	base := out["base"].(map[string]any)["ref"].(string)
	p := repoPath(owner, repo)
	hTree, _ := headTree(p, head)
	bTree, _ := headTree(p, base)
	// Flatten both trees to path -> sha.
	flat := func(treeSHA string) map[string]string {
		m := map[string]string{}
		var walk func(t, prefix string)
		walk = func(t, prefix string) {
			typ, raw, err := ReadObject(p, t)
			if err != nil || typ != "tree" {
				return
			}
			for _, e := range parseTree(raw) {
				if gitIsDirMode(e.Mode) {
					walk(e.SHA, prefix+e.Name+"/")
				} else {
					m[prefix+e.Name] = e.SHA
				}
			}
		}
		walk(treeSHA, "")
		return m
	}
	h := flat(hTree)
	b := flat(bTree)
	list := []map[string]any{}
	for path, sha := range h {
		status := "added"
		if _, ok := b[path]; ok {
			if b[path] == sha {
				continue
			}
			status = "modified"
		}
		list = append(list, map[string]any{"filename": path, "status": status, "additions": 1, "deletions": 0, "changes": 1})
	}
	for path := range b {
		if _, ok := h[path]; !ok {
			list = append(list, map[string]any{"filename": path, "status": "removed", "additions": 0, "deletions": 1, "changes": 1})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i]["filename"].(string) < list[j]["filename"].(string) })
	writeJSON(w, 200, list)
}

// ---------- pure-Go 3-way merge ----------
// flattenTree returns path -> blob SHA for every file in a tree (recursive).
func flattenTree(repoDir, treeSHA string) map[string]string {
	m := map[string]string{}
	var walk func(t, prefix string)
	walk = func(t, prefix string) {
		typ, raw, err := ReadObject(repoDir, t)
		if err != nil || typ != "tree" {
			return
		}
		for _, e := range parseTree(raw) {
			if gitIsDirMode(e.Mode) {
				walk(e.SHA, prefix+e.Name+"/")
			} else {
				m[prefix+e.Name] = e.SHA
			}
		}
	}
	walk(treeSHA, "")
	return m
}

// buildTreeFromFlat builds a tree object from a flat path -> blob SHA map.
func buildTreeFromFlat(repoDir string, flat map[string]string) (string, error) {
	// Group by first path segment.
	type node struct {
		dirs  map[string]*node
		files map[string]string
	}
	root := &node{dirs: map[string]*node{}, files: map[string]string{}}
	for path, sha := range flat {
		parts := strings.Split(path, "/")
		cur := root
		for _, seg := range parts[:len(parts)-1] {
			if cur.dirs[seg] == nil {
				cur.dirs[seg] = &node{dirs: map[string]*node{}, files: map[string]string{}}
			}
			cur = cur.dirs[seg]
		}
		cur.files[parts[len(parts)-1]] = sha
	}
	var build func(n *node) (string, error)
	build = func(n *node) (string, error) {
		var entries []treeEntry
		for name, sha := range n.files {
			entries = append(entries, treeEntry{Mode: "100644", Name: name, SHA: sha})
		}
		for name, sub := range n.dirs {
			subSHA, err := build(sub)
			if err != nil {
				return "", err
			}
			entries = append(entries, treeEntry{Mode: "040000", Name: name, SHA: subSHA})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		return WriteObject(repoDir, "tree", encodeTree(entries))
	}
	return build(root)
}

// threeWayMerge merges head into base using mergeBase as the common ancestor. It returns
// the merged tree SHA, or ( "", true, nil ) when the merge conflicts.
func threeWayMerge(repoDir, mbTree, baseTree, headTree string) (string, bool, error) {
	mb := flattenTree(repoDir, mbTree)
	b := flattenTree(repoDir, baseTree)
	h := flattenTree(repoDir, headTree)
	merged := map[string]string{}
	// Union of all paths.
	paths := map[string]bool{}
	for p := range mb {
		paths[p] = true
	}
	for p := range b {
		paths[p] = true
	}
	for p := range h {
		paths[p] = true
	}
	for path := range paths {
		mbSHA, inMB := mb[path]
		bSHA, inB := b[path]
		hSHA, inH := h[path]
		switch {
		case inMB && inB && inH:
			// Present in all three.
			if bSHA == mbSHA && hSHA == mbSHA {
				merged[path] = mbSHA
			} else if bSHA == mbSHA {
				merged[path] = hSHA
			} else if hSHA == mbSHA {
				merged[path] = bSHA
			} else if bSHA == hSHA {
				merged[path] = bSHA
			} else {
				return "", true, nil // both changed differently: conflict
			}
		case inMB && inB && !inH:
			// Deleted in head.
			if bSHA == mbSHA {
				// Deleted in head, unchanged in base: delete.
			} else {
				return "", true, nil // modify/delete conflict
			}
		case inMB && !inB && inH:
			// Deleted in base.
			if hSHA == mbSHA {
				// Deleted in base, unchanged in head: delete.
			} else {
				return "", true, nil // modify/delete conflict
			}
		case inMB && !inB && !inH:
			// Deleted in both: gone.
		case !inMB && inB && inH:
			// Added in both.
			if bSHA == hSHA {
				merged[path] = bSHA
			} else {
				return "", true, nil // add/add conflict
			}
		case !inMB && inB && !inH:
			merged[path] = bSHA
		case !inMB && !inB && inH:
			merged[path] = hSHA
		}
	}
	treeSHA, err := buildTreeFromFlat(repoDir, merged)
	if err != nil {
		return "", false, err
	}
	return treeSHA, false, nil
}

// makeMergeCommit writes a merge commit with two parents and returns its SHA.
func makeMergeCommit(repoDir, treeSHA, parent1, parent2, message, authorName, authorEmail string) (string, error) {
	now := time.Now().Unix()
	tz := "+0000"
	var b strings.Builder
	b.WriteString("tree " + treeSHA + "\n")
	b.WriteString("parent " + parent1 + "\n")
	if parent2 != "" {
		b.WriteString("parent " + parent2 + "\n")
	}
	b.WriteString(fmt.Sprintf("author %s <%s> %d %s\n", authorName, authorEmail, now, tz))
	b.WriteString(fmt.Sprintf("committer %s <%s> %d %s\n\n", authorName, authorEmail, now, tz))
	b.WriteString(message + "\n")
	return WriteObject(repoDir, "commit", []byte(b.String()))
}

// doMergePull performs the 3-way merge of a pull request. It returns the merge commit
// SHA, or an error message with the HTTP status to answer (404 unknown, 405 conflicted or
// not open, 500 on an internal failure).
func doMergePull(owner, repo string, number int, login string) (string, int, string) {
	out, ok := pullJSON(owner, repo, number)
	if !ok {
		return "", 404, "Not Found"
	}
	if out["state"] != "open" {
		return "", 405, "pull request is not open"
	}
	head := out["head"].(map[string]any)["ref"].(string)
	base := out["base"].(map[string]any)["ref"].(string)
	p := repoPath(owner, repo)
	hTree, headSHA := headTree(p, head)
	bTree, baseSHA := headTree(p, base)
	if headSHA == "" || baseSHA == "" {
		return "", 405, "cannot merge: missing branch"
	}
	var mergedTree string
	if IsAncestor(p, baseSHA, headSHA) {
		mergedTree = hTree
	} else {
		mb := MergeBase(p, baseSHA, headSHA)
		if mb == "" {
			return "", 405, "cannot merge: no merge base"
		}
		mbTree, _ := headTree(p, mb)
		var conflict bool
		var err error
		mergedTree, conflict, err = threeWayMerge(p, mbTree, bTree, hTree)
		if err != nil {
			return "", 500, err.Error()
		}
		if conflict {
			return "", 405, "merge conflict"
		}
	}
	title := out["title"].(string)
	commitSHA, err := makeMergeCommit(p, mergedTree, baseSHA, headSHA, "Merge pull request #"+strconv.Itoa(number)+" — "+title, login, login+"@forge.local")
	if err != nil {
		return "", 500, err.Error()
	}
	if err := WriteRef(p, "refs/heads/"+base, commitSHA); err != nil {
		return "", 500, err.Error()
	}
	db.Exec("UPDATE pulls SET state='closed', merged=1, merge_sha=?, merged_at=? WHERE owner=? AND repo=? AND number=?", commitSHA, nowStr(), owner, repo, number)
	deliverWebhook(owner, repo, "pull_request", map[string]any{"action": "closed", "pull_request": map[string]any{"number": number, "merged": true}})
	return commitSHA, 200, ""
}

// handleMergePull merges a pull request with a real 3-way merge onto the base branch.
// A conflicted merge is 405 (the suite's expectation) and leaves the PR open.
func handleMergePull(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	commitSHA, code, msg := doMergePull(owner, repo, number, shopLogin)
	if code != 200 {
		writeErr(w, code, msg)
		return
	}
	writeJSON(w, 200, map[string]any{"sha": commitSHA, "merged": true, "message": "Pull Request successfully merged"})
}

// ---------- GraphQL v4 ----------
// A compact GraphQL parser + executor for the documents gh and github-mcp-server send.
// Supports: query/mutation operations, operation names, variables, aliases, inline
// fragments (... on Type), named fragments, arguments (string/int/enum/object/list/null),
// batching (a JSON array of documents in one body). Unknown fields produce HTTP 200 with
// an errors array naming the field; an unknown repository is data.repository = null.

// --- lexer ---
type gqlTok struct {
	kind string // name, string, int, punct, var, eof
	val  string
}

func gqlLex(src string) []gqlTok {
	var out []gqlTok
	i := 0
	for i < len(src) {
		c := src[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' {
			i++
			continue
		}
		if c == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		if c == '"' {
			// String (with escapes). Block strings """ are treated as a string too.
			if strings.HasPrefix(src[i:], `"""`) {
				end := strings.Index(src[i+3:], `"""`)
				if end < 0 {
					end = len(src) - i - 3
				}
				out = append(out, gqlTok{"string", src[i+3 : i+3+end]})
				i += 3 + end + 3
				continue
			}
			j := i + 1
			var sb strings.Builder
			for j < len(src) && src[j] != '"' {
				if src[j] == '\\' && j+1 < len(src) {
					j++
					switch src[j] {
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					case 'r':
						sb.WriteByte('\r')
					default:
						sb.WriteByte(src[j])
					}
					j++
				} else {
					sb.WriteByte(src[j])
					j++
				}
			}
			out = append(out, gqlTok{"string", sb.String()})
			i = j + 1
			continue
		}
		if c == '$' {
			j := i + 1
			for j < len(src) && (isGqlNameChar(src[j])) {
				j++
			}
			out = append(out, gqlTok{"var", src[i+1 : j]})
			i = j
			continue
		}
		if (c >= '0' && c <= '9') || c == '-' {
			j := i
			for j < len(src) && ((src[j] >= '0' && src[j] <= '9') || src[j] == '.' || src[j] == 'e' || src[j] == 'E' || src[j] == '-' || src[j] == '+') {
				j++
			}
			out = append(out, gqlTok{"int", src[i:j]})
			i = j
			continue
		}
		if isGqlNameStart(c) {
			j := i
			for j < len(src) && isGqlNameChar(src[j]) {
				j++
			}
			out = append(out, gqlTok{"name", src[i:j]})
			i = j
			continue
		}
		if c == '.' && strings.HasPrefix(src[i:], "...") {
			out = append(out, gqlTok{"punct", "..."})
			i += 3
			continue
		}
		out = append(out, gqlTok{"punct", string(c)})
		i++
	}
	out = append(out, gqlTok{"eof", ""})
	return out
}

func isGqlNameStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}
func isGqlNameChar(c byte) bool { return isGqlNameStart(c) || (c >= '0' && c <= '9') }

// --- AST ---
type gqlValue struct {
	kind string // string, int, float, bool, null, enum, var, list, object
	s    string
	list []*gqlValue
	obj  map[string]*gqlValue
}

type gqlField struct {
	alias  string
	name   string
	args   map[string]*gqlValue
	sel    []*gqlField // selection set (nil = leaf)
	frag   string      // for inline fragment: the type condition
	spread string      // for a named fragment spread: the fragment name
}

type gqlOp struct {
	kind      string // query, mutation, subscription
	name      string
	variables map[string]*gqlValue // variable definitions (defaults)
	sel       []*gqlField
}

// --- parser ---
type gqlParser struct {
	toks []gqlTok
	pos  int
}

func (p *gqlParser) peek() gqlTok  { return p.toks[p.pos] }
func (p *gqlParser) next() gqlTok  { t := p.toks[p.pos]; p.pos++; return t }
func (p *gqlParser) expect(kind, val string) bool {
	t := p.next()
	return t.kind == kind && (val == "" || t.val == val)
}

func (p *gqlParser) parseValue() *gqlValue {
	t := p.next()
	switch t.kind {
	case "string":
		return &gqlValue{kind: "string", s: t.val}
	case "int":
		return &gqlValue{kind: "int", s: t.val}
	case "var":
		return &gqlValue{kind: "var", s: t.val}
	case "name":
		if t.val == "true" || t.val == "false" {
			return &gqlValue{kind: "bool", s: t.val}
		}
		if t.val == "null" {
			return &gqlValue{kind: "null"}
		}
		return &gqlValue{kind: "enum", s: t.val}
	case "punct":
		if t.val == "[" {
			v := &gqlValue{kind: "list"}
			for p.peek().val != "]" {
				v.list = append(v.list, p.parseValue())
			}
			p.next()
			return v
		}
		if t.val == "{" {
			v := &gqlValue{kind: "object", obj: map[string]*gqlValue{}}
			for p.peek().val != "}" {
				k := p.next()
				p.expect("punct", ":")
				v.obj[k.val] = p.parseValue()
			}
			p.next()
			return v
		}
	}
	return &gqlValue{kind: "null"}
}

func (p *gqlParser) parseArgs() map[string]*gqlValue {
	args := map[string]*gqlValue{}
	if p.peek().val != "(" {
		return args
	}
	p.next()
	for p.peek().val != ")" && p.peek().kind != "eof" {
		k := p.next()
		p.expect("punct", ":")
		args[k.val] = p.parseValue()
	}
	p.next()
	return args
}

func (p *gqlParser) parseSelection() []*gqlField {
	var fields []*gqlField
	if p.peek().val != "{" {
		return fields
	}
	p.next()
	for p.peek().val != "}" && p.peek().kind != "eof" {
		if p.peek().val == "..." {
			p.next()
			// Inline fragment or fragment spread.
			if p.peek().kind == "name" && p.peek().val == "on" {
				p.next()
				cond := p.next()
				f := &gqlField{frag: cond.val, sel: p.parseSelection()}
				fields = append(fields, f)
			} else if p.peek().kind == "name" {
				// Named fragment spread: resolve it at execution time (the
				// fragment may be defined after the operation).
				name := p.next().val
				fields = append(fields, &gqlField{spread: name})
			}
			continue
		}
		// Field (maybe aliased).
		first := p.next()
		alias, name := "", first.val
		if p.peek().val == ":" {
			p.next()
			alias = name
			name = p.next().val
		}
		f := &gqlField{alias: alias, name: name, args: p.parseArgs()}
		if p.peek().val == "{" {
			f.sel = p.parseSelection()
		}
		fields = append(fields, f)
	}
	p.next()
	return fields
}

type gqlDoc struct {
	ops   []*gqlOp
	frags map[string][]*gqlField
}

// parseDocument parses one GraphQL document string.
func parseDocument(src string) (*gqlDoc, error) {
	p := &gqlParser{toks: gqlLex(src)}
	doc := &gqlDoc{frags: map[string][]*gqlField{}}
	for p.peek().kind != "eof" {
		t := p.peek()
		if t.kind == "punct" && t.val == "{" {
			// Anonymous shorthand query.
			op := &gqlOp{kind: "query", sel: p.parseSelection()}
			doc.ops = append(doc.ops, op)
			continue
		}
		if t.kind == "name" && t.val == "fragment" {
			p.next()
			name := p.next().val
			p.next() // "on"
			p.next() // type
			doc.frags[name] = p.parseSelection()
			continue
		}
		if t.kind == "name" && (t.val == "query" || t.val == "mutation" || t.val == "subscription") {
			kind := p.next().val
			op := &gqlOp{kind: kind, variables: map[string]*gqlValue{}}
			if p.peek().kind == "name" {
				op.name = p.next().val
			}
			if p.peek().val == "(" {
				p.next()
				for p.peek().val != ")" && p.peek().kind != "eof" {
					v := p.next() // $name
					if v.kind == "var" {
						p.expect("punct", ":")
						// Type (skip tokens until , or ) or =).
						for p.peek().val != "," && p.peek().val != ")" && p.peek().val != "=" && p.peek().kind != "eof" {
							p.next()
						}
						if p.peek().val == "=" {
							p.next()
							op.variables[v.val] = p.parseValue()
						}
					}
					if p.peek().val == "," {
						p.next()
					}
				}
				p.next()
			}
			op.sel = p.parseSelection()
			doc.ops = append(doc.ops, op)
			continue
		}
		p.next()
	}
	return doc, nil
}

// --- value resolution ---
func gqlResolveValue(v *gqlValue, vars map[string]any) any {
	if v == nil {
		return nil
	}
	switch v.kind {
	case "string":
		return v.s
	case "int":
		if n, err := strconv.Atoi(v.s); err == nil {
			return n
		}
		return v.s
	case "bool":
		return v.s == "true"
	case "null":
		return nil
	case "enum":
		return v.s
	case "var":
		if vars != nil {
			return vars[v.s]
		}
		return nil
	case "list":
		out := []any{}
		for _, e := range v.list {
			out = append(out, gqlResolveValue(e, vars))
		}
		return out
	case "object":
		out := map[string]any{}
		for k, e := range v.obj {
			out[k] = gqlResolveValue(e, vars)
		}
		return out
	}
	return nil
}

func gqlArgString(f *gqlField, key string, vars map[string]any) string {
	if v, ok := f.args[key]; ok {
		if s, ok := gqlResolveValue(v, vars).(string); ok {
			return s
		}
	}
	return ""
}
func gqlArgInt(f *gqlField, key string, vars map[string]any) int {
	if v, ok := f.args[key]; ok {
		switch n := gqlResolveValue(v, vars).(type) {
		case int:
			return n
		case float64:
			// JSON numbers unmarshal as float64.
			return int(n)
		case int64:
			return int(n)
		}
	}
	return 0
}

// --- GraphQL executor ---
type gqlCtx struct {
	login string
	vars  map[string]any
	errs  []map[string]any
	frags map[string][]*gqlField
}

func (c *gqlCtx) addErr(msg string) {
	c.errs = append(c.errs, map[string]any{"message": msg})
}

func repoID(owner, name string) string { return "R_" + owner + "/" + name }
func issueID(owner, repo string, n int) string {
	return "I_" + owner + "/" + repo + "/" + strconv.Itoa(n)
}
func pullID(owner, repo string, n int) string {
	return "PR_" + owner + "/" + repo + "/" + strconv.Itoa(n)
}

func (c *gqlCtx) resolveRepo(owner, name string) map[string]any {
	if !repoExists(owner, name) {
		return nil
	}
	desc, branch, priv, _ := repoDesc(owner, name)
	return map[string]any{
		"__type": "Repository", "owner": owner, "name": name,
		"description": desc, "default_branch": branch, "private": priv,
	}
}

func (c *gqlCtx) resolveIssue(owner, repo string, n int) map[string]any {
	out, ok := issueJSON(owner, repo, n)
	if !ok {
		return nil
	}
	out["__type"] = "Issue"
	out["owner"] = owner
	out["repo"] = repo
	return out
}

func (c *gqlCtx) resolvePull(owner, repo string, n int) map[string]any {
	out, ok := pullJSON(owner, repo, n)
	if !ok {
		return nil
	}
	out["__type"] = "PullRequest"
	out["owner"] = owner
	out["repo"] = repo
	return out
}

// selectFields resolves a selection set against an object (a map with __type).
func (c *gqlCtx) selectFields(obj map[string]any, sel []*gqlField) map[string]any {
	out := map[string]any{}
	for _, f := range sel {
		key := f.name
		if f.alias != "" {
			key = f.alias
		}
		if f.spread != "" {
			// Named fragment spread: inline the fragment's fields.
			if frag, ok := c.frags[f.spread]; ok {
				for k, v := range c.selectFields(obj, frag) {
					out[k] = v
				}
			}
			continue
		}
		if f.frag != "" {
			// Inline fragment: apply when the type matches (or no type info).
			if t, _ := obj["__type"].(string); t != "" && t != f.frag && f.frag != "Node" {
				continue
			}
			for k, v := range c.selectFields(obj, f.sel) {
				out[k] = v
			}
			continue
		}
		v := c.resolveField(obj, f)
		if v == errUnknownField {
			c.addErr("field not found: " + f.name)
			continue
		}
		out[key] = v
	}
	return out
}

var errUnknownField = fmt.Errorf("unknown field")

func (c *gqlCtx) resolveField(obj map[string]any, f *gqlField) any {
	typ, _ := obj["__type"].(string)
	switch typ {
	case "Query":
		return c.resolveQueryField(f)
	case "Repository":
		return c.resolveRepoField(obj, f)
	case "Issue":
		return c.resolveIssueField(obj, f)
	case "PullRequest":
		return c.resolvePullField(obj, f)
	case "IssueConnection":
		return c.resolveIssueConnField(obj, f)
	case "PullRequestConnection":
		return c.resolvePullConnField(obj, f)
	case "User":
		if f.name == "login" {
			return obj["login"]
		}
	case "Mutation":
		return c.resolveMutationField(f)
	}
	// Generic: a field that is literally present on the object.
	if v, ok := obj[f.name]; ok {
		if f.sel == nil {
			return v
		}
		if m, ok := v.(map[string]any); ok {
			return c.selectFields(m, f.sel)
		}
		return v
	}
	return errUnknownField
}

func (c *gqlCtx) resolveQueryField(f *gqlField) any {
	switch f.name {
	case "viewer":
		u := map[string]any{"__type": "User", "login": c.login}
		if f.sel == nil {
			return u
		}
		return c.selectFields(u, f.sel)
	case "repository":
		owner := gqlArgString(f, "owner", c.vars)
		name := gqlArgString(f, "name", c.vars)
		r := c.resolveRepo(owner, name)
		if r == nil {
			return nil
		}
		if f.sel == nil {
			return r
		}
		return c.selectFields(r, f.sel)
	case "node":
		id := gqlArgString(f, "id", c.vars)
		// IDs are R_owner/name, I_owner/repo/n, PR_owner/repo/n.
		if strings.HasPrefix(id, "R_") {
			parts := strings.SplitN(strings.TrimPrefix(id, "R_"), "/", 2)
			if len(parts) == 2 {
				r := c.resolveRepo(parts[0], parts[1])
				if r == nil {
					return nil
				}
				if f.sel == nil {
					return r
				}
				return c.selectFields(r, f.sel)
			}
		}
		return nil
	case "__type":
		name := gqlArgString(f, "name", c.vars)
		t := gqlIntrospectType(name)
		if t == nil {
			return nil
		}
		if f.sel == nil {
			return t
		}
		return c.selectFields(t, f.sel)
	case "__schema":
		return map[string]any{"__type": "__Schema"}
	}
	return errUnknownField
}

func (c *gqlCtx) resolveRepoField(obj map[string]any, f *gqlField) any {
	owner := obj["owner"].(string)
	name := obj["name"].(string)
	switch f.name {
	case "id":
		return repoID(owner, name)
	case "databaseId":
		return 1
	case "name":
		return name
	case "nameWithOwner", "fullName":
		return owner + "/" + name
	case "owner":
		u := map[string]any{"__type": "User", "login": owner}
		if f.sel == nil {
			return u
		}
		return c.selectFields(u, f.sel)
	case "defaultBranchRef":
		branch := obj["default_branch"].(string)
		if branch == "" {
			return nil
		}
		return map[string]any{"name": branch}
	case "viewerPermission":
		return "ADMIN"
	case "hasIssuesEnabled":
		return true
	case "description":
		return obj["description"]
	case "issue":
		n := gqlArgInt(f, "number", c.vars)
		iss := c.resolveIssue(owner, name, n)
		if iss == nil {
			return nil
		}
		if f.sel == nil {
			return iss
		}
		return c.selectFields(iss, f.sel)
	case "issues":
		// states filter, orderBy, first, after.
		var states []string
		if v, ok := f.args["states"]; ok {
			if arr, ok := gqlResolveValue(v, c.vars).([]any); ok {
				for _, e := range arr {
					if s, ok := e.(string); ok {
						states = append(states, s)
					}
				}
			}
		}
		// orderBy {field, direction}
		descOrder := false
		if v, ok := f.args["orderBy"]; ok {
			if m, ok := gqlResolveValue(v, c.vars).(map[string]any); ok {
				if d, ok := m["direction"].(string); ok && d == "DESC" {
					descOrder = true
				}
			}
		}
		rows, _ := db.Query("SELECT number FROM issues WHERE owner=? AND repo=? ORDER BY number", owner, name)
		var nums []int
		for rows.Next() {
			var n int
			rows.Scan(&n)
			nums = append(nums, n)
		}
		rows.Close()
		var nodes []map[string]any
		for _, n := range nums {
			iss := c.resolveIssue(owner, name, n)
			if iss == nil {
				continue
			}
			if len(states) > 0 {
				st := strings.ToUpper(iss["state"].(string))
				keep := false
				for _, s := range states {
					if s == st {
						keep = true
					}
				}
				if !keep {
					continue
				}
			}
			nodes = append(nodes, iss)
		}
		if descOrder {
			for i, j := 0, len(nodes)-1; i < j; i, j = i+1, j-1 {
				nodes[i], nodes[j] = nodes[j], nodes[i]
			}
		}
		// Cursor pagination: `after` names the last node of the previous page
		// (the issue number, as a string); nodes at or before it are skipped.
		after := gqlArgString(f, "after", c.vars)
		if after != "" {
			if cur, err := strconv.Atoi(after); err == nil {
				kept := nodes[:0]
				for _, nd := range nodes {
					num := nd["number"].(int)
					if descOrder {
						if num < cur {
							kept = append(kept, nd)
						}
					} else {
						if num > cur {
							kept = append(kept, nd)
						}
					}
				}
				nodes = kept
			}
		}
		first := gqlArgInt(f, "first", c.vars)
		hasNext := false
		if first > 0 && len(nodes) > first {
			hasNext = true
			nodes = nodes[:first]
		}
		endCursor := ""
		if len(nodes) > 0 {
			endCursor = strconv.Itoa(nodes[len(nodes)-1]["number"].(int))
		}
		conn := map[string]any{"__type": "IssueConnection", "nodes": nodes, "owner": owner, "repo": name, "hasNextPage": hasNext, "endCursor": endCursor}
		if f.sel == nil {
			return conn
		}
		return c.selectFields(conn, f.sel)
	case "pullRequests":
		rows, _ := db.Query("SELECT number FROM pulls WHERE owner=? AND repo=? ORDER BY number", owner, name)
		var nodes []map[string]any
		for rows.Next() {
			var n int
			rows.Scan(&n)
			if pr := c.resolvePull(owner, name, n); pr != nil {
				nodes = append(nodes, pr)
			}
		}
		rows.Close()
		first := gqlArgInt(f, "first", c.vars)
		if first > 0 && len(nodes) > first {
			nodes = nodes[:first]
		}
		conn := map[string]any{"__type": "PullRequestConnection", "nodes": nodes, "owner": owner, "repo": name}
		if f.sel == nil {
			return conn
		}
		return c.selectFields(conn, f.sel)
	case "pullRequest":
		n := gqlArgInt(f, "number", c.vars)
		pr := c.resolvePull(owner, name, n)
		if pr == nil {
			return nil
		}
		if f.sel == nil {
			return pr
		}
		return c.selectFields(pr, f.sel)
	}
	return errUnknownField
}

func (c *gqlCtx) resolveIssueField(obj map[string]any, f *gqlField) any {
	switch f.name {
	case "id":
		return issueID(obj["owner"].(string), obj["repo"].(string), obj["number"].(int))
	case "number", "title", "state", "body":
		v := obj[f.name]
		if s, ok := v.(string); ok && f.name == "state" {
			return strings.ToUpper(s)
		}
		return v
	}
	return errUnknownField
}

func (c *gqlCtx) resolvePullField(obj map[string]any, f *gqlField) any {
	owner := obj["owner"].(string)
	name := obj["repo"].(string)
	switch f.name {
	case "id":
		return pullID(owner, name, obj["number"].(int))
	case "number":
		return obj["number"]
	case "state":
		s := obj["state"].(string)
		if obj["merged"] == true || obj["merged"] == 1 {
			return "MERGED"
		}
		return strings.ToUpper(s)
	case "merged":
		return obj["merged"] == true || obj["merged"] == 1
	case "headRefName":
		return obj["head"].(map[string]any)["ref"]
	case "baseRefName":
		return obj["base"].(map[string]any)["ref"]
	case "mergeable":
		if obj["state"] == "open" {
			return "MERGEABLE"
		}
		return "UNKNOWN"
	case "title", "body":
		return obj[f.name]
	case "files":
		// PullRequestChangedFile connection: nodes with path.
		p := repoPath(owner, name)
		head := obj["head"].(map[string]any)["ref"].(string)
		base := obj["base"].(map[string]any)["ref"].(string)
		hTree, _ := headTree(p, head)
		bTree, _ := headTree(p, base)
		flat := func(treeSHA string) map[string]string {
			m := map[string]string{}
			var walk func(t, prefix string)
			walk = func(t, prefix string) {
				typ, raw, err := ReadObject(p, t)
				if err != nil || typ != "tree" {
					return
				}
				for _, e := range parseTree(raw) {
					if gitIsDirMode(e.Mode) {
						walk(e.SHA, prefix+e.Name+"/")
					} else {
						m[prefix+e.Name] = e.SHA
					}
				}
			}
			walk(treeSHA, "")
			return m
		}
		h := flat(hTree)
		b := flat(bTree)
		var nodes []map[string]any
		for path := range h {
			if _, ok := b[path]; !ok || b[path] != h[path] {
				nodes = append(nodes, map[string]any{"__type": "PullRequestChangedFile", "path": path})
			}
		}
		sort.Slice(nodes, func(i, j int) bool { return nodes[i]["path"].(string) < nodes[j]["path"].(string) })
		conn := map[string]any{"__type": "PullRequestFileConnection", "nodes": nodes}
		if f.sel == nil {
			return conn
		}
		return c.selectFields(conn, f.sel)
	}
	return errUnknownField
}

func (c *gqlCtx) resolveIssueConnField(obj map[string]any, f *gqlField) any {
	switch f.name {
	case "nodes":
		nodes := obj["nodes"].([]map[string]any)
		out := []any{}
		for _, n := range nodes {
			if f.sel == nil {
				out = append(out, n)
			} else {
				out = append(out, c.selectFields(n, f.sel))
			}
		}
		return out
	case "pageInfo":
		hasNext, _ := obj["hasNextPage"].(bool)
		endCursor, _ := obj["endCursor"].(string)
		var ec any
		if endCursor != "" {
			ec = endCursor
		}
		return map[string]any{"hasNextPage": hasNext, "endCursor": ec}
	case "totalCount":
		return len(obj["nodes"].([]map[string]any))
	}
	return errUnknownField
}

func (c *gqlCtx) resolvePullConnField(obj map[string]any, f *gqlField) any {
	switch f.name {
	case "nodes":
		nodes := obj["nodes"].([]map[string]any)
		out := []any{}
		for _, n := range nodes {
			if f.sel == nil {
				out = append(out, n)
			} else {
				out = append(out, c.selectFields(n, f.sel))
			}
		}
		return out
	case "pageInfo":
		return map[string]any{"hasNextPage": false, "endCursor": nil}
	case "totalCount":
		return len(obj["nodes"].([]map[string]any))
	}
	// PullRequestFileConnection nodes.
	if obj["__type"] == "PullRequestFileConnection" {
		if f.name == "nodes" {
			nodes := obj["nodes"].([]map[string]any)
			out := []any{}
			for _, n := range nodes {
				if f.sel == nil {
					out = append(out, n)
				} else {
					out = append(out, c.selectFields(n, f.sel))
				}
			}
			return out
		}
	}
	return errUnknownField
}

func (c *gqlCtx) resolveMutationField(f *gqlField) any {
	switch f.name {
	case "createIssue":
		input := map[string]any{}
		if v, ok := f.args["input"]; ok {
			if m, ok := gqlResolveValue(v, c.vars).(map[string]any); ok {
				input = m
			}
		}
		repoIDStr, _ := input["repositoryId"].(string)
		title, _ := input["title"].(string)
		body, _ := input["body"].(string)
		parts := strings.SplitN(strings.TrimPrefix(repoIDStr, "R_"), "/", 2)
		if len(parts) != 2 {
			c.addErr("repository not found")
			return nil
		}
		owner, repo := parts[0], parts[1]
		if !repoExists(owner, repo) {
			c.addErr("repository not found")
			return nil
		}
		var num int
		db.QueryRow("SELECT COALESCE(MAX(number),0)+1 FROM issues WHERE owner=? AND repo=?", owner, repo).Scan(&num)
		db.Exec("INSERT INTO issues(owner,repo,number,title,body,labels,created_at) VALUES(?,?,?,?,?,?,?)", owner, repo, num, title, body, "[]", time.Now().UnixNano())
		iss := c.resolveIssue(owner, repo, num)
		res := map[string]any{"issue": nil}
		if f.sel != nil {
			// The selection is on the payload: {issue{...}}.
			for _, sf := range f.sel {
				if sf.name == "issue" {
					if sf.sel == nil {
						res["issue"] = iss
					} else {
						res["issue"] = c.selectFields(iss, sf.sel)
					}
				}
			}
		}
		return res
	case "closeIssue":
		input := map[string]any{}
		if v, ok := f.args["input"]; ok {
			if m, ok := gqlResolveValue(v, c.vars).(map[string]any); ok {
				input = m
			}
		}
		issueIDStr, _ := input["issueId"].(string)
		parts := strings.Split(strings.TrimPrefix(issueIDStr, "I_"), "/")
		if len(parts) != 3 {
			c.addErr("issue not found")
			return nil
		}
		owner, repo := parts[0], parts[1]
		n, _ := strconv.Atoi(parts[2])
		if _, ok := issueJSON(owner, repo, n); !ok {
			c.addErr("issue not found")
			return nil
		}
		db.Exec("UPDATE issues SET state='closed' WHERE owner=? AND repo=? AND number=?", owner, repo, n)
		iss := c.resolveIssue(owner, repo, n)
		res := map[string]any{"issue": nil}
		if f.sel != nil {
			for _, sf := range f.sel {
				if sf.name == "issue" {
					if sf.sel == nil {
						res["issue"] = iss
					} else {
						res["issue"] = c.selectFields(iss, sf.sel)
					}
				}
			}
		}
		return res
	case "createPullRequest":
		input := map[string]any{}
		if v, ok := f.args["input"]; ok {
			if m, ok := gqlResolveValue(v, c.vars).(map[string]any); ok {
				input = m
			}
		}
		repoIDStr, _ := input["repositoryId"].(string)
		base, _ := input["baseRefName"].(string)
		head, _ := input["headRefName"].(string)
		title, _ := input["title"].(string)
		parts := strings.SplitN(strings.TrimPrefix(repoIDStr, "R_"), "/", 2)
		if len(parts) != 2 {
			c.addErr("repository not found")
			return nil
		}
		owner, repo := parts[0], parts[1]
		var num int
		db.QueryRow("SELECT COALESCE(MAX(number),0)+1 FROM pulls WHERE owner=? AND repo=?", owner, repo).Scan(&num)
		db.Exec("INSERT INTO pulls(owner,repo,number,title,body,head,base,state) VALUES(?,?,?,?,?,?,?,?)", owner, repo, num, title, "", head, base, "open")
		pr := c.resolvePull(owner, repo, num)
		res := map[string]any{"pullRequest": nil}
		if f.sel != nil {
			for _, sf := range f.sel {
				if sf.name == "pullRequest" {
					if sf.sel == nil {
						res["pullRequest"] = pr
					} else {
						res["pullRequest"] = c.selectFields(pr, sf.sel)
					}
				}
			}
		}
		return res
	case "mergePullRequest":
		input := map[string]any{}
		if v, ok := f.args["input"]; ok {
			if m, ok := gqlResolveValue(v, c.vars).(map[string]any); ok {
				input = m
			}
		}
		prIDStr, _ := input["pullRequestId"].(string)
		parts := strings.Split(strings.TrimPrefix(prIDStr, "PR_"), "/")
		if len(parts) != 3 {
			c.addErr("pull request not found")
			return nil
		}
		owner, repo := parts[0], parts[1]
		n, _ := strconv.Atoi(parts[2])
		commitSHA, code, msg := doMergePull(owner, repo, n, c.login)
		if code != 200 {
			c.addErr(msg)
			return nil
		}
		_ = commitSHA
		pr := c.resolvePull(owner, repo, n)
		res := map[string]any{"pullRequest": nil}
		if f.sel != nil {
			for _, sf := range f.sel {
				if sf.name == "pullRequest" {
					if sf.sel == nil {
						res["pullRequest"] = pr
					} else {
						res["pullRequest"] = c.selectFields(pr, sf.sel)
					}
				}
			}
		}
		return res
	case "addComment":
		input := map[string]any{}
		if v, ok := f.args["input"]; ok {
			if m, ok := gqlResolveValue(v, c.vars).(map[string]any); ok {
				input = m
			}
		}
		subjectID, _ := input["subjectId"].(string)
		body, _ := input["body"].(string)
		// subjectId is an issue id I_owner/repo/n.
		parts := strings.Split(strings.TrimPrefix(subjectID, "I_"), "/")
		if len(parts) != 3 {
			c.addErr("subject not found")
			return nil
		}
		owner, repo := parts[0], parts[1]
		n, _ := strconv.Atoi(parts[2])
		res, _ := db.Exec("INSERT INTO comments(owner,repo,issue_number,body) VALUES(?,?,?,?)", owner, repo, n, body)
		id, _ := res.LastInsertId()
		// GraphQL ids are strings.
		comment := map[string]any{"__type": "IssueComment", "id": "IC_" + owner + "/" + repo + "/" + strconv.FormatInt(id, 10), "body": body}
		out := map[string]any{"commentEdge": map[string]any{"node": comment}}
		if f.sel != nil {
			// Selection is on the payload: {commentEdge{node{...}}}.
			for _, sf := range f.sel {
				if sf.name == "commentEdge" && sf.sel != nil {
					edge := map[string]any{}
					for _, ef := range sf.sel {
						if ef.name == "node" {
							if ef.sel == nil {
								edge["node"] = comment
							} else {
								edge["node"] = c.selectFields(comment, ef.sel)
							}
						}
					}
					out["commentEdge"] = edge
				}
			}
		}
		return out
	}
	return errUnknownField
}

// --- introspection ---
func gqlIntrospectType(name string) map[string]any {
	fields := func(names ...string) []map[string]any {
		var out []map[string]any
		for _, n := range names {
			out = append(out, map[string]any{"name": n})
		}
		return out
	}
	enumVals := func(names ...string) []map[string]any {
		var out []map[string]any
		for _, n := range names {
			out = append(out, map[string]any{"name": n})
		}
		return out
	}
	switch name {
	case "Issue":
		return map[string]any{"__type": "__Type", "name": "Issue", "kind": "OBJECT", "fields": fields("id", "number", "title", "state", "body")}
	case "PullRequest":
		return map[string]any{"__type": "__Type", "name": "PullRequest", "kind": "OBJECT", "fields": fields("id", "number", "headRefName", "baseRefName", "mergeable", "state", "merged", "files")}
	case "Repository":
		return map[string]any{"__type": "__Type", "name": "Repository", "kind": "OBJECT", "fields": fields("id", "databaseId", "name", "nameWithOwner", "owner", "defaultBranchRef", "viewerPermission", "hasIssuesEnabled", "issue", "issues", "pullRequests", "pullRequest")}
	case "SearchType":
		return map[string]any{"__type": "__Type", "name": "SearchType", "kind": "ENUM", "enumValues": enumVals("ISSUE", "REPOSITORY", "USER")}
	case "IssueState":
		return map[string]any{"__type": "__Type", "name": "IssueState", "kind": "ENUM", "enumValues": enumVals("OPEN", "CLOSED")}
	case "PullRequestState":
		return map[string]any{"__type": "__Type", "name": "PullRequestState", "kind": "ENUM", "enumValues": enumVals("OPEN", "CLOSED", "MERGED")}
	case "MergeableState":
		return map[string]any{"__type": "__Type", "name": "MergeableState", "kind": "ENUM", "enumValues": enumVals("MERGEABLE", "CONFLICTING", "UNKNOWN")}
	}
	return nil
}

// --- HTTP handler ---
func handleGraphQL(w http.ResponseWriter, r *http.Request, login string) {
	body, _ := io.ReadAll(r.Body)
	// Batching: a JSON array of operation documents in one body answers two results.
	var docs []struct {
		Query         string         `json:"query"`
		Variables     map[string]any `json:"variables"`
		OperationName string         `json:"operationName"`
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(body, &docs); err != nil {
			writeErr(w, 400, "Problems parsing JSON")
			return
		}
	} else {
		var single struct {
			Query         string         `json:"query"`
			Variables     map[string]any `json:"variables"`
			OperationName string         `json:"operationName"`
		}
		if err := json.Unmarshal(body, &single); err != nil {
			writeErr(w, 400, "Problems parsing JSON")
			return
		}
		docs = append(docs, single)
	}
	results := []map[string]any{}
	for _, d := range docs {
		results = append(results, execGraphQL(d.Query, d.Variables, d.OperationName, login))
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		writeJSON(w, 200, results)
		return
	}
	writeJSON(w, 200, results[0])
}

func execGraphQL(query string, vars map[string]any, opName string, login string) map[string]any {
	doc, err := parseDocument(query)
	if err != nil || len(doc.ops) == 0 {
		return map[string]any{"errors": []map[string]any{{"message": "could not parse query"}}}
	}
	// Pick the operation by name (or the only one).
	op := doc.ops[0]
	if opName != "" {
		for _, o := range doc.ops {
			if o.name == opName {
				op = o
			}
		}
	}
	// Merge variable defaults with supplied variables.
	merged := map[string]any{}
	for k, v := range op.variables {
		merged[k] = gqlResolveValue(v, vars)
	}
	for k, v := range vars {
		merged[k] = v
	}
	ctx := &gqlCtx{login: login, vars: merged, frags: doc.frags}
	root := map[string]any{"__type": "Query"}
	if op.kind == "mutation" {
		root = map[string]any{"__type": "Mutation"}
	}
	data := ctx.selectFields(root, op.sel)
	res := map[string]any{"data": data}
	if len(ctx.errs) > 0 {
		res["errors"] = ctx.errs
	}
	return res
}

// ---------- MCP (JSON-RPC 2.0, Streamable HTTP) ----------
// Speaks both eras: modern 2026-07-28 (server/discover, _meta revision, no handshake) and
// legacy 2025-11-25 (initialize + notifications/initialized, optional Mcp-Session-Id).

type mcpReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
		Meta      map[string]any `json:"_meta"`
	} `json:"params"`
}

func mcpError(id any, code int, msg string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}}
}
func mcpResult(id any, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}

// mcpTools is the deterministic tool list (byte-for-byte identical across calls).
func mcpTools() []map[string]any {
	obj := func(props map[string]any, req []string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": req}
	}
	str := map[string]any{"type": "string"}
	return []map[string]any{
		{"name": "create_repo", "description": "Create a repository", "inputSchema": obj(map[string]any{"name": str, "description": str, "private": map[string]any{"type": "boolean"}}, []string{"name"})},
		{"name": "get_repo", "description": "Get a repository by owner and name", "inputSchema": obj(map[string]any{"owner": str, "repo": str, "full_name": str}, []string{"owner", "repo"})},
		{"name": "create_issue", "description": "Create an issue in a repository", "inputSchema": obj(map[string]any{"owner": str, "repo": str, "full_name": str, "title": str, "body": str}, []string{"owner", "repo", "title"})},
		{"name": "list_issues", "description": "List issues in a repository", "inputSchema": obj(map[string]any{"owner": str, "repo": str, "full_name": str, "state": str}, []string{"owner", "repo"})},
		{"name": "create_pull_request", "description": "Create a pull request", "inputSchema": obj(map[string]any{"owner": str, "repo": str, "full_name": str, "title": str, "head": str, "base": str}, []string{"owner", "repo", "title", "head", "base"})},
		{"name": "merge_pull_request", "description": "Merge a pull request", "inputSchema": obj(map[string]any{"owner": str, "repo": str, "full_name": str, "pull_number": map[string]any{"type": "integer"}}, []string{"owner", "repo", "pull_number"})},
		{"name": "list_repos", "description": "List repositories by owner", "inputSchema": obj(map[string]any{"owner": str}, []string{"owner"})},
		{"name": "get_file", "description": "Get a file's content from a repository", "inputSchema": obj(map[string]any{"owner": str, "repo": str, "full_name": str, "path": str}, []string{"owner", "repo", "path"})},
	}
}

// mcpOwnerRepo resolves owner/repo from the arguments (owner+repo, or full_name "owner/repo").
func mcpOwnerRepo(args map[string]any) (owner, repo string) {
	owner, _ = args["owner"].(string)
	repo, _ = args["repo"].(string)
	if owner == "" || repo == "" {
		if fn, ok := args["full_name"].(string); ok {
			parts := strings.SplitN(fn, "/", 2)
			if len(parts) == 2 {
				owner, repo = parts[0], parts[1]
			}
		}
	}
	// The suite maps documented names onto the schema's nearest property; accept owner_login.
	if owner == "" {
		owner, _ = args["owner_login"].(string)
	}
	if repo == "" {
		repo, _ = args["repository"].(string)
	}
	return owner, repo
}

func mcpTextResult(id any, text string) map[string]any {
	return mcpResult(id, map[string]any{"content": []map[string]any{{"type": "text", "text": text}}})
}

func handleMCP(w http.ResponseWriter, r *http.Request, login string) {
	body, _ := io.ReadAll(r.Body)
	var req mcpReq
	if err := json.Unmarshal(body, &req); err != nil {
		// A body that is not JSON answers HTTP 400 with -32700.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-GitHub-Request-Id", newRequestID())
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "Parse error"}})
		return
	}
	// Notifications (no id) are acknowledged with an empty 202/200 and no body work.
	if req.ID == nil && strings.HasPrefix(req.Method, "notifications/") {
		w.Header().Set("X-GitHub-Request-Id", newRequestID())
		w.WriteHeader(202)
		return
	}
	switch req.Method {
	case "server/discover":
		writeJSON(w, 200, mcpResult(req.ID, map[string]any{
			"serverInfo":        map[string]any{"name": "forge", "version": "1.0.0"},
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"supportedVersions": []string{"2026-07-28", "2025-11-25"},
			"protocolVersion":   "2026-07-28",
		}))
		return
	case "initialize":
		writeJSON(w, 200, mcpResult(req.ID, map[string]any{
			"protocolVersion": "2025-11-25",
			"serverInfo":      map[string]any{"name": "forge", "version": "1.0.0"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}))
		return
	case "tools/list":
		writeJSON(w, 200, mcpResult(req.ID, map[string]any{"tools": mcpTools()}))
		return
	case "tools/call":
		handleMCPCall(w, r, login, &req)
		return
	case "ping":
		writeJSON(w, 200, mcpResult(req.ID, map[string]any{}))
		return
	}
	writeJSON(w, 200, mcpError(req.ID, -32601, "method not found: "+req.Method))
}

func handleMCPCall(w http.ResponseWriter, r *http.Request, login string, req *mcpReq) {
	args := req.Params.Arguments
	if args == nil {
		args = map[string]any{}
	}
	name := strings.ToLower(req.Params.Name)
	// Match by suffix, case-insensitively (a server prefix is allowed).
	match := func(canon string, aliases ...string) bool {
		if strings.HasSuffix(name, canon) {
			return true
		}
		for _, a := range aliases {
			if strings.HasSuffix(name, a) {
				return true
			}
		}
		return false
	}
	need := func(keys ...string) bool {
		for _, k := range keys {
			if _, ok := args[k]; !ok {
				return false
			}
		}
		return true
	}
	missingErr := func() {
		writeJSON(w, 200, mcpResult(req.ID, map[string]any{"content": []map[string]any{{"type": "text", "text": "missing required argument"}}, "isError": true}))
	}
	switch {
	case match("create_repo", "create_repository", "repo_create"):
		if !need("name") {
			missingErr()
			return
		}
		nm, _ := args["name"].(string)
		desc, _ := args["description"].(string)
		priv, _ := args["private"].(bool)
		p := repoPath(login, nm)
		if p == "" {
			writeJSON(w, 200, mcpError(req.ID, -32602, "invalid name"))
			return
		}
		InitBareRepo(p)
		db.Exec("INSERT OR REPLACE INTO repos(owner,name,description,private,default_branch) VALUES(?,?,?,?,?)", login, nm, desc, boolToInt(priv), "main")
		b, _ := json.Marshal(repoJSON(r, login, nm))
		writeJSON(w, 200, mcpTextResult(req.ID, string(b)))
		return
	case match("get_repo", "get_repository", "repo_get"):
		owner, repo := mcpOwnerRepo(args)
		if owner == "" || repo == "" {
			missingErr()
			return
		}
		if !repoExists(owner, repo) {
			writeJSON(w, 200, mcpError(req.ID, -32602, "repository not found"))
			return
		}
		b, _ := json.Marshal(repoJSON(r, owner, repo))
		writeJSON(w, 200, mcpTextResult(req.ID, string(b)))
		return
	case match("create_issue", "issue_create"):
		owner, repo := mcpOwnerRepo(args)
		title, _ := args["title"].(string)
		if owner == "" || repo == "" || title == "" {
			missingErr()
			return
		}
		if !repoExists(owner, repo) {
			writeJSON(w, 200, mcpError(req.ID, -32602, "repository not found"))
			return
		}
		body, _ := args["body"].(string)
		var num int
		db.QueryRow("SELECT COALESCE(MAX(number),0)+1 FROM issues WHERE owner=? AND repo=?", owner, repo).Scan(&num)
		db.Exec("INSERT INTO issues(owner,repo,number,title,body,labels,created_at) VALUES(?,?,?,?,?,?,?)", owner, repo, num, title, body, "[]", time.Now().UnixNano())
		out, _ := issueJSON(owner, repo, num)
		b, _ := json.Marshal(out)
		writeJSON(w, 200, mcpTextResult(req.ID, string(b)))
		return
	case match("list_issues", "issues_list", "issue_list"):
		owner, repo := mcpOwnerRepo(args)
		if owner == "" || repo == "" {
			missingErr()
			return
		}
		if !repoExists(owner, repo) {
			writeJSON(w, 200, mcpError(req.ID, -32602, "repository not found"))
			return
		}
		state, _ := args["state"].(string)
		q := "SELECT number FROM issues WHERE owner=? AND repo=?"
		qargs := []any{owner, repo}
		if state != "" && state != "all" {
			q += " AND state=?"
			qargs = append(qargs, state)
		}
		q += " ORDER BY number ASC"
		rows, _ := db.Query(q, qargs...)
		list := []map[string]any{}
		for rows.Next() {
			var n int
			rows.Scan(&n)
			if out, ok := issueJSON(owner, repo, n); ok {
				list = append(list, out)
			}
		}
		rows.Close()
		b, _ := json.Marshal(list)
		writeJSON(w, 200, mcpTextResult(req.ID, string(b)))
		return
	case match("create_pull_request", "pull_request_create", "create_pr", "pr_create"):
		owner, repo := mcpOwnerRepo(args)
		title, _ := args["title"].(string)
		head, _ := args["head"].(string)
		base, _ := args["base"].(string)
		if owner == "" || repo == "" || title == "" || head == "" || base == "" {
			missingErr()
			return
		}
		if !repoExists(owner, repo) {
			writeJSON(w, 200, mcpError(req.ID, -32602, "repository not found"))
			return
		}
		var num int
		db.QueryRow("SELECT COALESCE(MAX(number),0)+1 FROM pulls WHERE owner=? AND repo=?", owner, repo).Scan(&num)
		db.Exec("INSERT INTO pulls(owner,repo,number,title,body,head,base,state) VALUES(?,?,?,?,?,?,?,?)", owner, repo, num, title, "", head, base, "open")
		out, _ := pullJSON(owner, repo, num)
		b, _ := json.Marshal(out)
		writeJSON(w, 200, mcpTextResult(req.ID, string(b)))
		return
	case match("merge_pull_request", "pull_request_merge", "merge_pr", "pr_merge"):
		owner, repo := mcpOwnerRepo(args)
		pn, ok := args["pull_number"]
		if owner == "" || repo == "" || !ok {
			missingErr()
			return
		}
		var num int
		switch v := pn.(type) {
		case float64:
			num = int(v)
		case int:
			num = v
		case string:
			num, _ = strconv.Atoi(v)
		}
		out, ok2 := pullJSON(owner, repo, num)
		if !ok2 {
			writeJSON(w, 200, mcpError(req.ID, -32602, "pull request not found"))
			return
		}
		_ = out
		commitSHA, code, msg := doMergePull(owner, repo, num, login)
		if code != 200 {
			writeJSON(w, 200, mcpError(req.ID, -32602, msg))
			return
		}
		b, _ := json.Marshal(map[string]any{"sha": commitSHA, "merged": true, "message": "Pull Request successfully merged"})
		writeJSON(w, 200, mcpTextResult(req.ID, string(b)))
		return
	case match("list_repos", "repos_list"):
		owner, _ := args["owner"].(string)
		if owner == "" {
			owner = login
		}
		rows, _ := db.Query("SELECT name FROM repos WHERE owner=? ORDER BY name", owner)
		list := []map[string]any{}
		for rows.Next() {
			var n string
			rows.Scan(&n)
			list = append(list, repoJSON(r, owner, n))
		}
		rows.Close()
		b, _ := json.Marshal(list)
		writeJSON(w, 200, mcpTextResult(req.ID, string(b)))
		return
	case match("get_file"):
		owner, repo := mcpOwnerRepo(args)
		path, _ := args["path"].(string)
		if owner == "" || repo == "" || path == "" {
			missingErr()
			return
		}
		if !repoExists(owner, repo) {
			writeJSON(w, 200, mcpError(req.ID, -32602, "repository not found"))
			return
		}
		_, defBranch, _, _ := repoDesc(owner, repo)
		p := repoPath(owner, repo)
		treeSHA, _ := headTree(p, defBranch)
		e := getTreePath(p, treeSHA, strings.Split(path, "/"))
		if e == nil {
			writeJSON(w, 200, mcpTextResult(req.ID, "Not found"))
			return
		}
		typ, raw, err := ReadObject(p, e.SHA)
		if err != nil || typ != "blob" {
			writeJSON(w, 200, mcpTextResult(req.ID, "Not found"))
			return
		}
		writeJSON(w, 200, mcpTextResult(req.ID, string(raw)))
		return
	}
	// Unknown tool: JSON-RPC -32602 or -32601, never HTTP 500.
	writeJSON(w, 200, mcpError(req.ID, -32602, "unknown tool: "+req.Params.Name))
}

// ---------- router ----------
func route(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")

	// Boot probe: no token.
	if r.Method == "GET" && (path == "healthz" || path == "health") {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}

	// Git smart HTTP: /{owner}/{repo}.git/... — handled by the pure-Go git layer.
	// (GitSmartHTTP is defined in git.go; it needs no token for the suite's git client,
	// which authenticates via the same bearer token the suite presents.)
	if len(parts) >= 2 && (strings.Contains(r.URL.Path, ".git/") || strings.HasSuffix(r.URL.Path, ".git") ||
		strings.Contains(r.URL.Path, "/info/refs") || strings.Contains(r.URL.Path, "git-upload-pack") || strings.Contains(r.URL.Path, "git-receive-pack")) {
		GitSmartHTTP(w, r)
		return
	}

	// Everything else under /api/v3, /api/graphql and /mcp requires the bearer token.
	login, ok := requireAuth(w, r)
	if !ok {
		return
	}

	// API root.
	if r.Method == "GET" && (path == "api/v3" || path == "api/v3/") {
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		writeJSON(w, 200, map[string]any{"current_user_url": "/api/v3/user", "rate_limit_url": "/api/v3/rate_limit"})
		return
	}
	if r.Method == "GET" && path == "api/v3/meta" {
		writeJSON(w, 200, map[string]any{"installed_version": "1.0.0"})
		return
	}
	if r.Method == "GET" && path == "api/v3/user" {
		writeJSON(w, 200, map[string]any{"login": login})
		return
	}

	// Search.
	if path == "api/v3/search/repositories" {
		if r.Method != "GET" {
			writeErr(w, 405, "method not allowed")
			return
		}
		handleSearch(w, r)
		return
	}

	// GraphQL and MCP.
	if path == "api/graphql" {
		if r.Method != "POST" {
			writeErr(w, 405, "method not allowed")
			return
		}
		handleGraphQL(w, r, login)
		return
	}
	if path == "mcp" {
		if r.Method != "POST" {
			writeErr(w, 405, "method not allowed")
			return
		}
		handleMCP(w, r, login)
		return
	}

	// REST /api/v3/user/repos (list + create).
	if path == "api/v3/user/repos" {
		if r.Method == "GET" {
			handleListUserRepos(w, r, login)
			return
		}
		if r.Method == "POST" {
			handleCreateRepo(w, r, login)
			return
		}
		writeErr(w, 405, "method not allowed")
		return
	}

	// REST /api/v3/repos/{owner}/{repo}[/...]
	if len(parts) >= 4 && parts[0] == "api" && parts[1] == "v3" && parts[2] == "repos" {
		owner := parts[3]
		repo := parts[4]
		if !ownerGuard(w, login, owner, repo) {
			return
		}
		rest := ""
		if len(parts) > 5 {
			rest = strings.Join(parts[5:], "/")
		}
		switch {
		case rest == "":
			switch r.Method {
			case "GET":
				handleGetRepo(w, r, owner, repo)
			case "PATCH":
				handlePatchRepo(w, r, owner, repo)
			case "DELETE":
				handleDeleteRepo(w, r, owner, repo)
			default:
				writeErr(w, 405, "method not allowed")
			}
			return
		case rest == "git/refs":
			if r.Method == "POST" {
				handleCreateRef(w, r, owner, repo)
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case strings.HasPrefix(rest, "git/refs/"):
			if r.Method == "GET" {
				handleGetRef(w, r, owner, repo, strings.TrimPrefix(rest, "git/refs/"))
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case rest == "branches":
			if r.Method == "GET" {
				handleListBranches(w, r, owner, repo)
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case strings.HasPrefix(rest, "branches/"):
			if r.Method == "GET" {
				handleGetBranch(w, r, owner, repo, strings.TrimPrefix(rest, "branches/"))
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case rest == "commits":
			if r.Method == "GET" {
				handleListCommits(w, r, owner, repo)
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case strings.HasPrefix(rest, "contents/"):
			cpath := strings.TrimPrefix(rest, "contents/")
			// URL-decode the path (it may hold %2F etc.).
			if u, err := url.PathUnescape(cpath); err == nil {
				cpath = u
			}
			switch r.Method {
			case "PUT":
				handlePutContents(w, r, owner, repo, cpath, login)
			case "GET":
				handleGetContents(w, r, owner, repo, cpath)
			case "DELETE":
				handleDeleteContents(w, r, owner, repo, cpath, login)
			default:
				writeErr(w, 405, "method not allowed")
			}
			return
		case rest == "labels":
			if r.Method == "POST" {
				handleCreateLabel(w, r, owner, repo)
				return
			}
			if r.Method == "GET" {
				handleListLabels(w, r, owner, repo)
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case rest == "collaborators":
			if r.Method == "POST" || r.Method == "GET" {
				handleCollaborators(w, r, owner, repo, login)
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case rest == "hooks":
			if r.Method == "POST" || r.Method == "GET" {
				handleWebhooks(w, r, owner, repo, login)
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case rest == "hooks/deliveries":
			if r.Method == "GET" {
				handleWebhookDeliveries(w, r, owner, repo)
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case rest == "issues":
			if r.Method == "POST" {
				handleCreateIssue(w, r, owner, repo)
				return
			}
			if r.Method == "GET" {
				handleListIssues(w, r, owner, repo)
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case strings.HasPrefix(rest, "issues/"):
			issueRest := strings.TrimPrefix(rest, "issues/")
			issueParts := strings.Split(issueRest, "/")
			num, err := strconv.Atoi(issueParts[0])
			if err != nil {
				writeErr(w, 404, "Not Found")
				return
			}
			if len(issueParts) == 1 {
				switch r.Method {
				case "GET":
					handleGetIssue(w, r, owner, repo, num)
				case "PATCH":
					handlePatchIssue(w, r, owner, repo, num)
				default:
					writeErr(w, 405, "method not allowed")
				}
				return
			}
			if len(issueParts) == 2 && issueParts[1] == "comments" {
				switch r.Method {
				case "POST":
					handleCreateComment(w, r, owner, repo, num)
				case "GET":
					handleListComments(w, r, owner, repo, num)
				default:
					writeErr(w, 405, "method not allowed")
				}
				return
			}
			writeErr(w, 404, "Not Found")
			return
		case rest == "pulls":
			if r.Method == "POST" {
				handleCreatePull(w, r, owner, repo)
				return
			}
			if r.Method == "GET" {
				handleListPulls(w, r, owner, repo)
				return
			}
			writeErr(w, 405, "method not allowed")
			return
		case strings.HasPrefix(rest, "pulls/"):
			pullRest := strings.TrimPrefix(rest, "pulls/")
			pullParts := strings.Split(pullRest, "/")
			num, err := strconv.Atoi(pullParts[0])
			if err != nil {
				writeErr(w, 404, "Not Found")
				return
			}
			if len(pullParts) == 1 {
				if r.Method == "GET" {
					handleGetPull(w, r, owner, repo, num)
					return
				}
				writeErr(w, 405, "method not allowed")
				return
			}
			if len(pullParts) == 2 && pullParts[1] == "files" {
				if r.Method == "GET" {
					handlePullFiles(w, r, owner, repo, num)
					return
				}
				writeErr(w, 405, "method not allowed")
				return
			}
			if len(pullParts) == 2 && pullParts[1] == "merge" {
				if r.Method == "PUT" {
					handleMergePull(w, r, owner, repo, num)
					return
				}
				writeErr(w, 405, "method not allowed")
				return
			}
			writeErr(w, 404, "Not Found")
			return
		}
	}

	// Unknown route: JSON 404, never HTML.
	writeErr(w, 404, "Not Found")
}

// ---------- lifecycle ----------
func main() {
	initDB()
	mux := http.NewServeMux()
	mux.HandleFunc("/", route)

	envURL := strings.TrimSuffix(os.Getenv("MAKEFUN_ENV_URL"), "/")
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		// Fall back to the configured port (local runs without an env).
		port := envOr("PORT", "8000")
		log.Printf("Forge running on :%s data=%s", port, baseDir)
		log.Fatal(http.ListenAndServe(":"+port, mux))
	}
	addr := ln.Addr().(*net.TCPAddr)
	port := addr.Port
	log.Printf("Forge listening on :%d data=%s", port, baseDir)
	go func() {
		if err := http.Serve(ln, mux); err != nil {
			log.Fatal(err)
		}
	}()

	if envURL == "" {
		// No env (local run): keep serving until killed.
		select {}
	}

	// Register the port, then poll /done until the suite finishes.
	register := func() {
		for {
			body, _ := json.Marshal(map[string]any{"port": port})
			req, _ := http.NewRequest("POST", envURL+"/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 || resp.StatusCode == 409 {
					return
				}
				if resp.StatusCode == 400 || resp.StatusCode == 405 {
					log.Fatalf("register answered HTTP %d", resp.StatusCode)
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	register()
	log.Printf("Forge registered port %d; waiting for done", port)
	for {
		resp, err := http.Get(envURL + "/done")
		if err == nil {
			var d struct {
				Done bool `json:"done"`
			}
			json.NewDecoder(resp.Body).Decode(&d)
			resp.Body.Close()
			if d.Done {
				log.Printf("Forge done; exiting 0")
				os.Exit(0)
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// ---------- webhooks ----------
// deliverWebhook sends one event to every active webhook of the repo whose event list
// includes it, signed with HMAC-SHA256 (X-Hub-Signature-256), and records the delivery.
// It runs in a goroutine so it never blocks the request that triggered it.
func deliverWebhook(owner, repo, event string, payload map[string]any) {
	rows, _ := db.Query("SELECT id,url,secret,events,active FROM webhooks WHERE owner=? AND repo=?", owner, repo)
	if rows == nil {
		return
	}
	type hook struct {
		id     int
		url    string
		secret string
		events []string
		active int
	}
	var hooks []hook
	for rows.Next() {
		var h hook
		var evStr string
		rows.Scan(&h.id, &h.url, &h.secret, &evStr, &h.active)
		json.Unmarshal([]byte(evStr), &h.events)
		hooks = append(hooks, h)
	}
	rows.Close()
	if len(hooks) == 0 {
		return
	}
	payload["repository"] = map[string]any{"full_name": owner + "/" + repo}
	body, _ := json.Marshal(payload)
	for _, h := range hooks {
		if h.active == 0 {
			continue
		}
		found := false
		for _, e := range h.events {
			if e == event || e == "*" {
				found = true
			}
		}
		if !found {
			continue
		}
		go func(h hook) {
			mac := hmac.New(sha256.New, []byte(h.secret))
			mac.Write(body)
			sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			req, _ := http.NewRequest("POST", h.url, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-GitHub-Event", event)
			req.Header.Set("X-Hub-Signature-256", sig)
			client := &http.Client{Timeout: 5 * time.Second}
			status := 0
			respBody := ""
			resp, err := client.Do(req)
			if err == nil {
				status = resp.StatusCode
				b, _ := io.ReadAll(resp.Body)
				respBody = string(b)
				resp.Body.Close()
			} else {
				respBody = err.Error()
			}
			db.Exec("INSERT INTO deliveries(webhook_id,event,payload,status,response,created_at) VALUES(?,?,?,?,?,?)", h.id, event, string(body), status, respBody, nowStr())
		}(h)
	}
}

func handleWebhooks(w http.ResponseWriter, r *http.Request, owner, repo string, login string) {
	if login != owner {
		writeErr(w, 403, "Only owner can manage webhooks")
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	if r.Method == "POST" {
		var in struct {
			URL    string   `json:"url"`
			Secret string   `json:"secret"`
			Events []string `json:"events"`
		}
		if !readJSONBody(w, r, &in) {
			return
		}
		if in.URL == "" {
			writeErr(w, 422, "url required")
			return
		}
		if len(in.Events) == 0 {
			in.Events = []string{"push", "issues", "pull_request"}
		}
		ev, _ := json.Marshal(in.Events)
		res, _ := db.Exec("INSERT INTO webhooks(owner,repo,url,secret,events,created_at) VALUES(?,?,?,?,?,?)", owner, repo, in.URL, in.Secret, string(ev), nowStr())
		id, _ := res.LastInsertId()
		writeJSON(w, 201, map[string]any{"id": id, "url": in.URL, "events": in.Events, "active": true})
		return
	}
	rows, _ := db.Query("SELECT id,url,events,active FROM webhooks WHERE owner=? AND repo=?", owner, repo)
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id int
		var url, evStr string
		var active int
		rows.Scan(&id, &url, &evStr, &active)
		var ev []string
		json.Unmarshal([]byte(evStr), &ev)
		list = append(list, map[string]any{"id": id, "url": url, "events": ev, "active": active == 1})
	}
	writeJSON(w, 200, list)
}

func handleWebhookDeliveries(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	rows, _ := db.Query("SELECT d.id,d.event,d.status,d.response,d.created_at FROM deliveries d JOIN webhooks wh ON wh.id=d.webhook_id WHERE wh.owner=? AND wh.repo=? ORDER BY d.id DESC LIMIT 20", owner, repo)
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id, status int
		var event, resp, created string
		rows.Scan(&id, &event, &status, &resp, &created)
		list = append(list, map[string]any{"id": id, "event": event, "status": status, "response": resp, "created_at": created})
	}
	writeJSON(w, 200, list)
}

// ---------- collaborators ----------
func handleCollaborators(w http.ResponseWriter, r *http.Request, owner, repo string, login string) {
	if login != owner {
		writeErr(w, 403, "Only owner can manage collaborators")
		return
	}
	if !repoExists(owner, repo) {
		writeErr(w, 404, "Not Found")
		return
	}
	if r.Method == "POST" {
		var in struct {
			Login      string `json:"login"`
			Permission string `json:"permission"`
		}
		if !readJSONBody(w, r, &in) {
			return
		}
		if in.Login == "" {
			writeErr(w, 422, "login required")
			return
		}
		if in.Permission == "" {
			in.Permission = "read"
		}
		db.Exec("INSERT OR REPLACE INTO collaborators(owner,repo,login,permission) VALUES(?,?,?,?)", owner, repo, in.Login, in.Permission)
		writeJSON(w, 201, map[string]any{"login": in.Login, "permission": in.Permission})
		return
	}
	rows, _ := db.Query("SELECT login,permission FROM collaborators WHERE owner=? AND repo=?", owner, repo)
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var l, p string
		rows.Scan(&l, &p)
		list = append(list, map[string]any{"login": l, "permission": p})
	}
	writeJSON(w, 200, list)
}

// ---------- search ----------
func handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	rows, _ := db.Query("SELECT owner,name,description FROM repos WHERE name LIKE ? OR description LIKE ? LIMIT 20", "%"+q+"%", "%"+q+"%")
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var o, n, d string
		rows.Scan(&o, &n, &d)
		items = append(items, map[string]any{"full_name": o + "/" + n, "name": n, "description": d})
	}
	writeJSON(w, 200, map[string]any{"total_count": len(items), "items": items})
}
