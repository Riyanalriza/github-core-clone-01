package main

// Git smart HTTP: git-upload-pack (protocol v2 and v0) and git-receive-pack
// (v0 only), plus the info/refs advertisements for both.
//
// Wire format (pkt-line): every frame is a 4-hex-digit length (including the
// 4 length bytes themselves) followed by that many-4 bytes of payload.
// 0000 = flush, 0001 = delim, 0002 = response-end. A data packet's payload
// is at most 65520-4 bytes. Side-band packets carry one band byte (1 = data,
// 2 = progress, 3 = error) as the first payload byte.
//
// This is written against the suite's git client (sdk/conformance/
// git-client.ts): v2 upload-pack advertisements and ls-refs/fetch, v0
// upload-pack want/have, and v0 receive-pack command lists with
// report-status inside side-band-64k.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ---------- pkt-line primitives ----------

type pktKind int

const (
	pktData pktKind = iota
	pktFlush
	pktDelim
	pktEnd
)

type pktLine struct {
	kind    pktKind
	payload []byte // data packets only
}

// pktFrame wraps data in one pkt-line frame.
func pktFrame(data []byte) []byte {
	n := len(data) + 4
	if n > 65520 {
		// Should never happen for our frames (callers chunk); truncate defensively.
		data = data[:65516]
		n = 65520
	}
	return append([]byte(fmt.Sprintf("%04x", n)), data...)
}

// pktText frames one text line (with its trailing newline) as a pkt-line.
func pktText(s string) []byte { return pktFrame([]byte(s)) }

var pktFlushBytes = []byte("0000")
var pktDelimBytes = []byte("0001")

// parsePktLine reads one pkt-line starting at pos in data. It returns the
// packet, the position just past it, and an error on malformed input.
func parsePktLine(data []byte, pos int) (pktLine, int, error) {
	if pos+4 > len(data) {
		return pktLine{}, pos, io.ErrUnexpectedEOF
	}
	hdr := string(data[pos : pos+4])
	n, err := strconv.ParseUint(hdr, 16, 32)
	if err != nil {
		return pktLine{}, pos, fmt.Errorf("bad pkt-line length %q", hdr)
	}
	switch n {
	case 0:
		return pktLine{kind: pktFlush}, pos + 4, nil
	case 1:
		return pktLine{kind: pktDelim}, pos + 4, nil
	case 2:
		return pktLine{kind: pktEnd}, pos + 4, nil
	}
	if n < 4 || pos+int(n) > len(data) {
		return pktLine{}, pos, fmt.Errorf("pkt-line length %d out of range", n)
	}
	return pktLine{kind: pktData, payload: data[pos+4 : pos+int(n)]}, pos + int(n), nil
}

// sidebandFrames splits data into side-band packets (band byte + chunk),
// each fitting in one pkt-line. The 65500-byte chunk keeps every frame
// safely under the 65520-byte pkt-line limit.
func sidebandFrames(band byte, data []byte) []byte {
	var out []byte
	if len(data) == 0 {
		// A zero-length pack is still sent as one (empty) band-1 packet so a
		// fetch with nothing new carries a valid empty pack, not silence.
		// (Callers that need a real empty pack pass the 32-byte pack.)
		return out
	}
	for len(data) > 0 {
		n := len(data)
		if n > 65500 {
			n = 65500
		}
		payload := make([]byte, 1+n)
		payload[0] = band
		copy(payload[1:], data[:n])
		out = append(out, pktFrame(payload)...)
		data = data[n:]
	}
	return out
}

// ---------- GitSmartHTTP: dispatch ----------

// GitSmartHTTP serves /{owner}/{repo}.git/info/refs, .../git-upload-pack and
// .../git-receive-pack. It needs no bearer token: the suite's git client
// speaks these endpoints without one. A repo whose directory does not exist
// is a 404 on every service.
func GitSmartHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(p, "/")
	if len(parts) < 2 || !strings.HasSuffix(parts[1], ".git") {
		writeErr(w, 404, "Not Found")
		return
	}
	owner := parts[0]
	repo := strings.TrimSuffix(parts[1], ".git")
	repoDir := repoPath(owner, repo)
	if repoDir == "" {
		writeErr(w, 404, "Not Found")
		return
	}
	if st, err := os.Stat(repoDir); err != nil || !st.IsDir() {
		writeErr(w, 404, "Not Found")
		return
	}
	rest := ""
	if len(parts) > 2 {
		rest = strings.Join(parts[2:], "/")
	}
	switch {
	case r.Method == "GET" && rest == "info/refs":
		handleInfoRefs(w, r, repoDir)
	case r.Method == "POST" && rest == "git-upload-pack":
		handleUploadPack(w, r, repoDir)
	case r.Method == "POST" && rest == "git-receive-pack":
		handleReceivePack(w, r, repoDir)
	default:
		writeErr(w, 404, "Not Found")
	}
}

// ---------- info/refs ----------

const gitAgent = "forge/1.0"

// uploadPackV2Caps are the v2 capabilities we advertise.
func uploadPackV2Caps() []string {
	return []string{
		"agent=" + gitAgent,
		"ls-refs=unborn",
		"fetch=shallow",
		"object-format=sha1",
	}
}

// uploadPackV0Caps are the v0 upload-pack capabilities (first ref line).
// multi_ack_detailed is required: a v0 fetch over smart HTTP is stateless,
// and git refuses stateless-rpc without it ("the option '--stateless-rpc'
// requires 'multi_ack_detailed'").
func uploadPackV0Caps(headRef string) string {
	caps := []string{"side-band-64k", "multi_ack", "multi_ack_detailed", "thin-pack", "ofs-delta", "shallow", "agent=" + gitAgent}
	if headRef != "" {
		caps = append(caps, "symref=HEAD:"+headRef)
	}
	return strings.Join(caps, " ")
}

// receivePackV0Caps are the v0 receive-pack capabilities.
func receivePackV0Caps(headRef string) string {
	caps := []string{"report-status", "side-band-64k", "delete-refs", "ofs-delta", "agent=" + gitAgent}
	if headRef != "" {
		caps = append(caps, "symref=HEAD:"+headRef)
	}
	return strings.Join(caps, " ")
}

func handleInfoRefs(w http.ResponseWriter, r *http.Request, repoDir string) {
	service := r.URL.Query().Get("service")
	if service != "git-upload-pack" && service != "git-receive-pack" {
		writeErr(w, 400, "service required")
		return
	}
	w.Header().Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	if service == "git-upload-pack" && r.Header.Get("Git-Protocol") == "version=2" {
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		var out []byte
		out = append(out, pktText("version 2\n")...)
		for _, c := range uploadPackV2Caps() {
			out = append(out, pktText(c+"\n")...)
		}
		out = append(out, pktFlushBytes...)
		_, _ = w.Write(out)
		return
	}
	// v0 advertisement, for both services.
	if service == "git-upload-pack" {
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
	} else {
		w.Header().Set("Content-Type", "application/x-git-receive-pack-advertisement")
	}
	headRef := readHeadRef(repoDir)
	headSHA, _ := ResolveRef(repoDir, "HEAD")
	refs := ListRefs(repoDir)
	names := sortedRefNames(refs)

	var out []byte
	out = append(out, pktText("# service="+service+"\n")...)
	out = append(out, pktFlushBytes...)
	caps := uploadPackV0Caps(headRef)
	if service == "git-receive-pack" {
		caps = receivePackV0Caps(headRef)
	}
	// First ref line carries the capabilities after a NUL.
	first := true
	writeRefLine := func(oid, name string) {
		line := oid + " " + name
		if first {
			line += "\x00" + caps
			first = false
		}
		out = append(out, pktText(line+"\n")...)
	}
	if headSHA != "" {
		writeRefLine(headSHA, "HEAD")
	}
	for _, name := range names {
		writeRefLine(refs[name], name)
		// Annotated tags also advertise the peeled commit (name^{}), so a
		// v0 client learns the tag target without fetching the tag object.
		if strings.HasPrefix(name, "refs/tags/") {
			if peeled := peelToCommit(repoDir, refs[name]); peeled != "" && peeled != refs[name] {
				writeRefLine(peeled, name+"^{}")
			}
		}
	}
	if first {
		// Empty repository: no refs at all. Advertise the capabilities on
		// the capabilities^{} pseudo-ref.
		out = append(out, pktText(zeroOID+" capabilities^{}\x00"+caps+"\n")...)
	}
	out = append(out, pktFlushBytes...)
	_, _ = w.Write(out)
}

// ---------- upload-pack ----------

// fetchRequest is a parsed upload-pack fetch (v0 or v2).
type fetchRequest struct {
	wants          []string
	haves          []string
	shallow        []string // the client's current shallow boundaries
	depth          int      // 0 = no depth limit
	deepenRelative bool     // "deepen-relative": depth counts from the current boundary
	deepenSince    int64
	deepenNot      []string
	thinPack       bool
	noProgress     bool
	ofsDelta       bool
	filter         string
}

// planFetch computes the objects a fetch must send, plus the shallow /
// unshallow boundary lists. wants are the tips; haves are commits the client
// already holds; clientShallow are the client's shallow boundaries (it holds
// those commits' trees/blobs but NOT their parents); depth limits the
// generations sent (0 = unlimited).
func planFetch(repoDir string, req *fetchRequest) (objs []packObject, shallow, unshallow []string, err error) {
	shallowSet := map[string]bool{}
	for _, s := range req.shallow {
		shallowSet[strings.ToLower(s)] = true
	}
	// Objects the client already holds.
	held := map[string]string{}
	for _, h := range req.haves {
		h = strings.ToLower(h)
		if h == "" || h == zeroOID {
			continue
		}
		if shallowSet[h] {
			// Shallow boundary: the commit + its tree/blobs, no parents.
			if c, e := WalkCommit(repoDir, h); e == nil {
				held[h] = "commit"
				collectTree(repoDir, c.Tree, held)
			}
			continue
		}
		// Full have: the whole closure.
		closure, _ := collectReachable(repoDir, []string{h}, -1)
		for sha, typ := range closure {
			held[sha] = typ
		}
	}
	// Effective depth for the walk. "deepen N" is an absolute total depth,
	// but "deepen N" + "deepen-relative" (what real git sends for
	// --deepen) counts N generations BEYOND the client's current shallow
	// boundary. The boundary is one generation deep (a depth-1 clone), so
	// the absolute depth is N+1 in that case.
	effDepth := req.depth
	if req.deepenRelative && req.depth > 0 {
		effDepth = req.depth + 1
	}
	// Walk from the wants, tracking commit generations (0 = the tips).
	type item struct {
		sha string
		gen int
	}
	collected := map[string]string{}
	genOf := map[string]int{}
	boundary := map[string]bool{} // commits at the depth limit
	queue := []item{}
	for _, w := range req.wants {
		w = strings.ToLower(w)
		if w == "" || w == zeroOID {
			continue
		}
		// A want may name a tag object (cloning --branch v1): include the
		// tag itself, then walk from the commit it peels to.
		if typ, _, err := ReadObject(repoDir, w); err == nil && typ == "tag" {
			collected[w] = "tag"
			if peeled := peelToCommit(repoDir, w); peeled != "" {
				w = peeled
			}
		}
		queue = append(queue, item{w, 0})
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if _, done := genOf[it.sha]; done {
			continue
		}
		c, e := WalkCommit(repoDir, it.sha)
		if e != nil {
			continue
		}
		genOf[it.sha] = it.gen
		collected[it.sha] = "commit"
		collectTree(repoDir, c.Tree, collected)
		if effDepth > 0 && it.gen >= effDepth-1 {
			boundary[it.sha] = true
			continue // do not descend past the depth limit
		}
		for _, p := range c.Parents {
			queue = append(queue, item{strings.ToLower(p), it.gen + 1})
		}
	}
	// Objects to send: collected minus what the client holds.
	send := map[string]string{}
	for sha, typ := range collected {
		if _, ok := held[sha]; !ok {
			send[sha] = typ
		}
	}
	// New shallow boundary: boundary commits (depth limit reached), unless
	// the client already holds one fully (then it is not shallow for them).
	if effDepth > 0 {
		for sha := range boundary {
			if _, fullyHeld := held[sha]; fullyHeld && !shallowSet[sha] {
				continue
			}
			shallow = append(shallow, sha)
		}
		sort.Strings(shallow)
	}
	// Unshallow: a previous shallow boundary whose parents we now send, so
	// it is no longer shallow for the client.
	for _, b := range req.shallow {
		b = strings.ToLower(b)
		if _, inCollected := collected[b]; !inCollected {
			continue
		}
		if boundary[b] {
			continue // still at the boundary
		}
		if c, e := WalkCommit(repoDir, b); e == nil {
			for _, p := range c.Parents {
				if _, ok := collected[strings.ToLower(p)]; ok {
					unshallow = append(unshallow, b)
					break
				}
			}
		}
	}
	sort.Strings(unshallow)
	// Build the pack objects in deterministic (SHA) order.
	for _, sha := range sortedKeys(send) {
		typ, raw, e := ReadObject(repoDir, sha)
		if e != nil {
			continue
		}
		objs = append(objs, packObject{Type: typ, Data: raw})
	}
	return objs, shallow, unshallow, nil
}

// lsRefsResponse builds the v2 ls-refs response lines for the repo.
func lsRefsResponse(repoDir string, prefixes []string, peel, symrefs, unborn bool) []byte {
	refs := ListRefs(repoDir)
	names := sortedRefNames(refs)
	headRef := readHeadRef(repoDir)
	headSHA, _ := ResolveRef(repoDir, "HEAD")
	keep := func(name string) bool {
		if len(prefixes) == 0 {
			return true
		}
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
		return false
	}
	var out []byte
	addLine := func(line string) {
		out = append(out, pktText(line+"\n")...)
	}
	if headSHA != "" && keep("HEAD") {
		line := headSHA + " HEAD"
		if symrefs && headRef != "" {
			line += " symref-target:" + headRef
		}
		addLine(line)
	}
	for _, name := range names {
		if !keep(name) {
			continue
		}
		sha := refs[name]
		line := sha + " " + name
		if peel && strings.HasPrefix(name, "refs/tags/") {
			if peeled := peelToCommit(repoDir, sha); peeled != "" && peeled != sha {
				line += " peeled:" + peeled
			}
		}
		addLine(line)
	}
	if len(refs) == 0 && headSHA == "" && unborn && keep("HEAD") {
		// Empty repository: HEAD is unborn.
		line := "unborn HEAD"
		if symrefs && headRef != "" {
			line += " symref-target:" + headRef
		}
		addLine(line)
	}
	out = append(out, pktFlushBytes...)
	return out
}

func handleUploadPack(w http.ResponseWriter, r *http.Request, repoDir string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, 400, "cannot read request")
		return
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	if r.Header.Get("Git-Protocol") == "version=2" {
		handleUploadPackV2(w, repoDir, body)
		return
	}
	handleUploadPackV0(w, repoDir, body)
}

// parsePktSection parses pkt-lines from data starting at pos until a flush
// (or end of data). It returns the data lines and the position past the
// flush. A malformed line is an error.
func parsePktSection(data []byte, pos int) ([]pktLine, int, error) {
	var lines []pktLine
	for pos < len(data) {
		p, next, err := parsePktLine(data, pos)
		if err != nil {
			return nil, pos, err
		}
		pos = next
		if p.kind == pktFlush {
			return lines, pos, nil
		}
		if p.kind == pktEnd {
			return lines, pos, nil
		}
		if p.kind == pktDelim {
			lines = append(lines, p)
			continue
		}
		lines = append(lines, p)
	}
	return lines, pos, nil
}

// pktLineText returns the payload of a data pkt-line as a string.
func pktLineText(p pktLine) string { return string(p.payload) }

func handleUploadPackV2(w http.ResponseWriter, repoDir string, body []byte) {
	lines, _, err := parsePktSection(body, 0)
	if err != nil {
		// Malformed request (the suite's repo-survives-errors check sends
		// one): answer 400 and stay up; do not crash.
		writeErr(w, 400, "malformed pkt-line request")
		return
	}
	if len(lines) == 0 {
		writeErr(w, 400, "empty request")
		return
	}
	cmd := strings.TrimSpace(pktLineText(lines[0]))
	if cmd != "command=ls-refs" && cmd != "command=fetch" {
		writeErr(w, 400, "unknown command")
		return
	}
	// Split the request at the delim into the header part and the argument part.
	args := []pktLine{}
	for i, l := range lines[1:] {
		if l.kind == pktDelim {
			args = lines[1+i+1:]
			break
		}
	}
	if cmd == "command=ls-refs" {
		var prefixes []string
		peel, symrefs, unborn := false, false, false
		for _, l := range args {
			if l.kind != pktData {
				continue
			}
			s := strings.TrimSpace(pktLineText(l))
			switch {
			case s == "peel":
				peel = true
			case s == "symrefs":
				symrefs = true
			case s == "unborn":
				unborn = true
			case strings.HasPrefix(s, "ref-prefix "):
				prefixes = append(prefixes, strings.TrimSpace(s[len("ref-prefix "):]))
			}
		}
		_, _ = w.Write(lsRefsResponse(repoDir, prefixes, peel, symrefs, unborn))
		return
	}
	// command=fetch
	req := &fetchRequest{}
	for _, l := range args {
		if l.kind != pktData {
			continue
		}
		s := strings.TrimSpace(pktLineText(l))
		switch {
		case s == "thin-pack":
			req.thinPack = true
		case s == "no-progress":
			req.noProgress = true
		case s == "ofs-delta":
			req.ofsDelta = true
		case strings.HasPrefix(s, "want "):
			req.wants = append(req.wants, strings.TrimSpace(s[5:]))
		case strings.HasPrefix(s, "have "):
			req.haves = append(req.haves, strings.TrimSpace(s[5:]))
		case strings.HasPrefix(s, "shallow "):
			req.shallow = append(req.shallow, strings.TrimSpace(s[8:]))
		case strings.HasPrefix(s, "deepen "):
			if n, err := strconv.Atoi(strings.TrimSpace(s[7:])); err == nil {
				req.depth = n
			}
		case s == "deepen-relative":
			req.deepenRelative = true
		case strings.HasPrefix(s, "filter "):
			req.filter = strings.TrimSpace(s[7:])
		case strings.HasPrefix(s, "deepen-not "):
			req.deepenNot = append(req.deepenNot, strings.TrimSpace(s[11:]))
		}
	}
	objs, shallow, unshallow, err := planFetch(repoDir, req)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	pack, err := WritePack(objs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var out []byte
	// The acknowledgments section is only sent when the client sent at
	// least one "have" line. A clone (no haves) expects the packfile
	// section first; sending acknowledgments there makes the client die
	// with "expected 'packfile', received 'acknowledgments'".
	// When the server holds every have, it ACKs each one and sends
	// "ready" (negotiation complete). A bare NAK here makes the client
	// expect further negotiation rounds and die with "expected no other
	// sections to be sent after no 'ready'".
	if len(req.haves) > 0 {
		out = append(out, pktText("acknowledgments\n")...)
		allHeld := true
		for _, h := range req.haves {
			if _, _, err := ReadObject(repoDir, strings.ToLower(h)); err != nil {
				allHeld = false
				break
			}
		}
		if allHeld {
			for _, h := range req.haves {
				out = append(out, pktText("ACK "+strings.ToLower(h)+"\n")...)
			}
			out = append(out, pktText("ready\n")...)
		} else {
			out = append(out, pktText("NAK\n")...)
		}
		out = append(out, pktDelimBytes...)
	}
	if len(shallow) > 0 || len(unshallow) > 0 {
		out = append(out, pktText("shallow-info\n")...)
		for _, s := range shallow {
			out = append(out, pktText("shallow "+s+"\n")...)
		}
		for _, s := range unshallow {
			out = append(out, pktText("unshallow "+s+"\n")...)
		}
		out = append(out, pktDelimBytes...)
	}
	out = append(out, pktText("packfile\n")...)
	out = append(out, sidebandFrames(1, pack)...)
	out = append(out, pktFlushBytes...)
	_, _ = w.Write(out)
}

func handleUploadPackV0(w http.ResponseWriter, repoDir string, body []byte) {
	// v0 is two sections: wants (with features on the first want line,
	// shallow/deepen lines) terminated by a flush, then haves + done
	// terminated by a second flush.
	wants, pos, err := parsePktSection(body, 0)
	if err != nil {
		writeErr(w, 400, "malformed pkt-line request")
		return
	}
	haves, _, err := parsePktSection(body, pos)
	if err != nil {
		writeErr(w, 400, "malformed pkt-line request")
		return
	}
	req := &fetchRequest{}
	for _, l := range wants {
		if l.kind != pktData {
			continue
		}
		s := strings.TrimSpace(pktLineText(l))
		switch {
		case strings.HasPrefix(s, "want "):
			// The first want line carries the feature list after the oid;
			// only the oid matters here.
			fields := strings.Fields(s[5:])
			if len(fields) > 0 {
				req.wants = append(req.wants, fields[0])
			}
		case strings.HasPrefix(s, "shallow "):
			req.shallow = append(req.shallow, strings.TrimSpace(s[8:]))
		case strings.HasPrefix(s, "deepen "):
			if n, err := strconv.Atoi(strings.TrimSpace(s[7:])); err == nil {
				req.depth = n
			}
		case s == "deepen-relative":
			req.deepenRelative = true
		}
	}
	for _, l := range haves {
		if l.kind != pktData {
			continue
		}
		s := strings.TrimSpace(pktLineText(l))
		if strings.HasPrefix(s, "have ") {
			req.haves = append(req.haves, strings.TrimSpace(s[5:]))
		}
	}
	objs, shallow, unshallow, err := planFetch(repoDir, req)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	pack, err := WritePack(objs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var out []byte
	out = append(out, pktText("NAK\n")...)
	for _, s := range shallow {
		out = append(out, pktText("shallow "+s+"\n")...)
	}
	for _, s := range unshallow {
		out = append(out, pktText("unshallow "+s+"\n")...)
	}
	out = append(out, sidebandFrames(1, pack)...)
	out = append(out, pktFlushBytes...)
	_, _ = w.Write(out)
}

// ---------- receive-pack ----------

// pushCommand is one line of a receive-pack command list.
type pushCommand struct {
	old string
	new string
	ref string
}

func handleReceivePack(w http.ResponseWriter, r *http.Request, repoDir string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, 400, "cannot read request")
		return
	}
	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")

	// Parse the command list (pkt-lines until the first flush); everything
	// after the flush is the packfile.
	var cmds []pushCommand
	pos := 0
	var packStart int
	for pos < len(body) {
		p, next, err := parsePktLine(body, pos)
		if err != nil {
			writeErr(w, 400, "malformed pkt-line request")
			return
		}
		pos = next
		if p.kind == pktFlush {
			packStart = pos
			break
		}
		if p.kind != pktData {
			continue
		}
		line := string(p.payload)
		// The first command line carries capabilities after a NUL.
		if i := strings.IndexByte(line, 0); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimRight(line, "\n")
		fields := strings.Fields(line)
		if len(fields) != 3 {
			writeErr(w, 400, "malformed push command")
			return
		}
		cmds = append(cmds, pushCommand{old: fields[0], new: fields[1], ref: fields[2]})
	}
	if len(cmds) == 0 {
		writeErr(w, 400, "no push commands")
		return
	}
	packBytes := body[packStart:]

	// Unpack first (deltas included), then update refs. A pack is present
	// whenever a command creates or updates a ref; a delete-only push has none.
	unpackOK := true
	unpackDetail := "ok"
	if len(packBytes) > 0 {
		objs, _, err := ReadPack(packBytes, func(oid string) (string, []byte, error) {
			return ReadObject(repoDir, oid)
		})
		if err != nil {
			unpackOK = false
			unpackDetail = err.Error()
		} else if _, err := storePackObjects(repoDir, objs); err != nil {
			unpackOK = false
			unpackDetail = err.Error()
		}
	}

	// Apply the commands, one report line each. A refused ref never moves;
	// an accepted one does.
	type verdict struct {
		ref    string
		ok     bool
		reason string
	}
	verdicts := make([]verdict, 0, len(cmds))
	refs := ListRefs(repoDir)
	for _, c := range cmds {
		fail := func(reason string) { verdicts = append(verdicts, verdict{c.ref, false, reason}) }
		if !isObjectID(c.old) || !isObjectID(c.new) || !strings.HasPrefix(c.ref, "refs/") {
			fail("invalid command")
			continue
		}
		if !unpackOK {
			fail("unpack failed")
			continue
		}
		current := refs[c.ref] // "" when the ref does not exist
		switch {
		case c.new == zeroOID:
			// Delete.
			if c.old == zeroOID {
				if current == "" {
					verdicts = append(verdicts, verdict{c.ref, true, ""})
				} else {
					fail("cannot delete a ref with a zero old value")
				}
				continue
			}
			if current == "" {
				fail("ref does not exist")
				continue
			}
			if c.old != current {
				fail("old value does not match")
				continue
			}
			if err := DeleteRef(repoDir, c.ref); err != nil {
				fail(err.Error())
				continue
			}
			refs[c.ref] = ""
			delete(refs, c.ref)
			verdicts = append(verdicts, verdict{c.ref, true, ""})
		case c.old == zeroOID:
			// Create.
			if current != "" {
				fail("ref already exists")
				continue
			}
			if _, _, err := ReadObject(repoDir, c.new); err != nil {
				fail("object not found")
				continue
			}
			if err := WriteRef(repoDir, c.ref, c.new); err != nil {
				fail(err.Error())
				continue
			}
			refs[c.ref] = c.new
			verdicts = append(verdicts, verdict{c.ref, true, ""})
		default:
			// Update: the old value must match, and the update must be a
			// fast-forward (old is an ancestor of new).
			if current == "" {
				fail("ref does not exist")
				continue
			}
			if c.old != current {
				fail("old value does not match")
				continue
			}
			if _, _, err := ReadObject(repoDir, c.new); err != nil {
				fail("object not found")
				continue
			}
			if !IsAncestor(repoDir, c.old, c.new) {
				fail("non-fast-forward")
				continue
			}
			if err := WriteRef(repoDir, c.ref, c.new); err != nil {
				fail(err.Error())
				continue
			}
			refs[c.ref] = c.new
			verdicts = append(verdicts, verdict{c.ref, true, ""})
		}
	}

	// Report-status, pkt-lined inside side-band band 1. The report stream
	// itself is pkt-framed, so it ends with its own flush packet INSIDE band
	// 1 (that is how a real git server sends it, and the client's report
	// parser reads the demuxed band-1 bytes until that flush). The outer
	// flush then terminates the main pkt-line stream.
	var report bytes.Buffer
	if unpackOK {
		report.Write(pktText("unpack ok\n"))
	} else {
		report.Write(pktText("unpack " + unpackDetail + "\n"))
	}
	for _, v := range verdicts {
		if v.ok {
			report.Write(pktText("ok " + v.ref + "\n"))
		} else {
			report.Write(pktText("ng " + v.ref + " " + v.reason + "\n"))
		}
	}
	report.Write(pktFlushBytes)
	var out []byte
	out = append(out, sidebandFrames(1, report.Bytes())...)
	out = append(out, pktFlushBytes...)
	_, _ = w.Write(out)
}
