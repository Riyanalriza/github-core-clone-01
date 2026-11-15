package main

// Packfile reading and writing (PACK v2).
//
// Writing is deliberately simple: plain full objects only, no deltas —
// always valid, and the suite's client accepts it (it reads v2/v3 packs with
// or without deltas). Reading must handle the full format because the
// suite's client sends delta-compressed packs on push: OBJ_COMMIT/TREE/
// BLOB/TAG, OBJ_OFS_DELTA and OBJ_REF_DELTA, with the trailing SHA-1
// checksum verified. A thin pack (a REF_DELTA whose base is not in the
// pack) resolves its base from the repo's object store via baseResolver.

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
)

const (
	packCommit   = 1
	packTree     = 2
	packBlob     = 3
	packTag      = 4
	packOfsDelta = 6
	packRefDelta = 7
)

// packObject is one object carried in (or to be written to) a packfile.
type packObject struct {
	Type string
	Data []byte
}

var packTypeNames = map[int]string{
	packCommit: "commit",
	packTree:   "tree",
	packBlob:   "blob",
	packTag:    "tag",
}

var packTypeCodes = map[string]int{
	"commit": packCommit,
	"tree":   packTree,
	"blob":   packBlob,
	"tag":    packTag,
}

// WritePack builds a PACK v2 file from plain objects (no deltas). The objects
// are written in the order given; callers should sort for determinism. The
// result ends with the SHA-1 of all preceding bytes.
func WritePack(objs []packObject) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("PACK")
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], 2) // version 2
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(objs)))
	buf.Write(hdr[:])
	for _, o := range objs {
		code, ok := packTypeCodes[o.Type]
		if !ok {
			return nil, fmt.Errorf("cannot pack object of type %q", o.Type)
		}
		buf.Write(encodePackHeader(code, len(o.Data)))
		var zb bytes.Buffer
		zw := zlib.NewWriter(&zb)
		if _, err := zw.Write(o.Data); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		buf.Write(zb.Bytes())
	}
	sum := sha1.Sum(buf.Bytes())
	buf.Write(sum[:])
	return buf.Bytes(), nil
}

// encodePackHeader encodes one pack entry header: the type in bits 4-6 of the
// first byte, the low 4 bits of the size in bits 0-3, then 7 more size bits
// per following byte; bit 7 set means "another byte follows".
func encodePackHeader(typ, size int) []byte {
	var out []byte
	b := byte((typ << 4) | (size & 0x0f))
	size >>= 4
	for size > 0 {
		out = append(out, b|0x80)
		b = byte(size & 0x7f)
		size >>= 7
	}
	out = append(out, b)
	return out
}

// ReadPack parses a packfile, verifies its trailing SHA-1, resolves all
// deltas, and returns the objects keyed by SHA plus the number of delta
// entries found. baseResolver is consulted for REF_DELTA bases that are not
// in the pack itself (thin packs); it may be nil, in which case such a base
// is an error. Every returned object's SHA is recomputed from its type and
// data and must match the id the pack implies.
func ReadPack(data []byte, baseResolver func(oid string) (string, []byte, error)) (map[string]packObject, int, error) {
	if len(data) < 12+20 {
		return nil, 0, fmt.Errorf("packfile too short (%d bytes)", len(data))
	}
	// Verify the trailing checksum first: it covers everything before it.
	want := sha1.Sum(data[:len(data)-20])
	if !bytes.Equal(want[:], data[len(data)-20:]) {
		return nil, 0, fmt.Errorf("packfile checksum mismatch: trailer %s != %s",
			hex.EncodeToString(data[len(data)-20:]), hex.EncodeToString(want[:]))
	}
	if string(data[:4]) != "PACK" {
		return nil, 0, fmt.Errorf("packfile has bad magic %q", string(data[:4]))
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version != 2 && version != 3 {
		return nil, 0, fmt.Errorf("packfile version %d unsupported", version)
	}
	count := int(binary.BigEndian.Uint32(data[8:12]))
	body := data[12 : len(data)-20]

	type rawEntry struct {
		offset int    // byte offset of the entry inside body
		typ    int    // object type code (or ofs/ref delta)
		size   int    // declared inflated size
		data   []byte // inflated data (delta bytes for delta entries)
		base   string // REF_DELTA base sha ("" otherwise)
		baseOf int    // OFS_DELTA base offset inside body (-1 otherwise)
	}
	entries := make([]rawEntry, 0, count)
	pos := 0
	deltaCount := 0
	for i := 0; i < count; i++ {
		if pos >= len(body) {
			return nil, 0, fmt.Errorf("packfile truncated at entry %d", i)
		}
		start := pos
		// Entry header: type + size varint.
		b := body[pos]
		pos++
		typ := int((b >> 4) & 0x07)
		size := int(b & 0x0f)
		shift := uint(4)
		for b&0x80 != 0 {
			if pos >= len(body) {
				return nil, 0, fmt.Errorf("packfile truncated in entry header %d", i)
			}
			b = body[pos]
			pos++
			size |= int(b&0x7f) << shift
			shift += 7
		}
		e := rawEntry{offset: start, typ: typ, size: size, baseOf: -1}
		switch typ {
		case packOfsDelta:
			deltaCount++
			// Offset varint: each byte contributes 7 bits; the running value
			// is incremented by one before each shift (git's encoding).
			if pos >= len(body) {
				return nil, 0, fmt.Errorf("packfile truncated in ofs-delta %d", i)
			}
			b = body[pos]
			pos++
			off := int(b & 0x7f)
			for b&0x80 != 0 {
				if pos >= len(body) {
					return nil, 0, fmt.Errorf("packfile truncated in ofs-delta %d", i)
				}
				b = body[pos]
				pos++
				off = ((off + 1) << 7) | int(b&0x7f)
			}
			e.baseOf = start - off
		case packRefDelta:
			deltaCount++
			if pos+20 > len(body) {
				return nil, 0, fmt.Errorf("packfile truncated in ref-delta %d", i)
			}
			e.base = hex.EncodeToString(body[pos : pos+20])
			pos += 20
		}
		// Zlib stream: inflate it once through a counting reader. The
		// counting reader implements io.ByteReader, so the flate decoder
		// reads exactly the stream's bytes (no over-read into the next
		// entry), and cr.n is the compressed length.
		cr := &countReader{r: bytes.NewReader(body[pos:])}
		zr, err := zlib.NewReader(cr)
		if err != nil {
			return nil, 0, fmt.Errorf("packfile entry %d: bad zlib stream: %w", i, err)
		}
		inflated, err := io.ReadAll(zr)
		if err != nil {
			return nil, 0, fmt.Errorf("packfile entry %d: inflate failed: %w", i, err)
		}
		zr.Close()
		if len(inflated) != size {
			return nil, 0, fmt.Errorf("packfile entry %d: inflated %d bytes, header says %d", i, len(inflated), size)
		}
		e.data = inflated
		pos += cr.n
		entries = append(entries, e)
	}

	// Resolve entries to full objects. Delta chains are resolved depth-first
	// with memoisation; a delta base is either an earlier entry in this pack
	// (by offset for OFS, by sha for REF once resolved) or, for a thin pack,
	// an object already in the repo (via baseResolver).
	byOffset := map[int]int{}
	for i, e := range entries {
		byOffset[e.offset] = i
	}
	resolved := make([]*packObject, len(entries))
	var resolve func(i int, depth int) (*packObject, error)
	resolve = func(i int, depth int) (*packObject, error) {
		if depth > 1000 {
			return nil, fmt.Errorf("delta chain too deep at entry %d", i)
		}
		if resolved[i] != nil {
			return resolved[i], nil
		}
		e := entries[i]
		switch e.typ {
		case packCommit, packTree, packBlob, packTag:
			o := &packObject{Type: packTypeNames[e.typ], Data: e.data}
			resolved[i] = o
			return o, nil
		case packOfsDelta, packRefDelta:
			var base *packObject
			if e.typ == packOfsDelta {
				j, ok := byOffset[e.baseOf]
				if !ok {
					return nil, fmt.Errorf("ofs-delta at entry %d references unknown offset %d", i, e.baseOf)
				}
				var err error
				base, err = resolve(j, depth+1)
				if err != nil {
					return nil, err
				}
			} else {
				// REF_DELTA: the base may be an earlier entry in this pack
				// (find it by its recomputed sha) or a repo object.
				for j := range entries {
					if entries[j].typ != packOfsDelta && entries[j].typ != packRefDelta {
						if objectSHA(packTypeNames[entries[j].typ], entries[j].data) == e.base {
							var err error
							base, err = resolve(j, depth+1)
							if err != nil {
								return nil, err
							}
							break
						}
					}
				}
				if base == nil && baseResolver != nil {
					btyp, bdata, err := baseResolver(e.base)
					if err != nil {
						return nil, fmt.Errorf("ref-delta base %s not available: %w", e.base, err)
					}
					base = &packObject{Type: btyp, Data: bdata}
				}
				if base == nil {
					return nil, fmt.Errorf("ref-delta base %s not in pack and no resolver", e.base)
				}
			}
			data, err := applyDelta(base.Data, e.data)
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", i, err)
			}
			o := &packObject{Type: base.Type, Data: data}
			resolved[i] = o
			return o, nil
		default:
			return nil, fmt.Errorf("packfile entry %d: unknown type %d", i, e.typ)
		}
	}

	out := make(map[string]packObject, len(entries))
	for i := range entries {
		o, err := resolve(i, 0)
		if err != nil {
			return nil, 0, err
		}
		sha := objectSHA(o.Type, o.Data)
		out[sha] = *o
	}
	_ = sort.Strings // keep sort imported for future deterministic use
	return out, deltaCount, nil
}

// countReader counts the bytes read from its underlying reader. It
// implements io.ByteReader so a zlib/flate decoder reading through it
// consumes exactly the stream's bytes and never reads ahead into the next
// pack entry.
type countReader struct {
	r *bytes.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func (c *countReader) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.n++
	}
	return b, err
}

// applyDelta applies a git delta to a base object and returns the result.
// Delta format: source-size varint, target-size varint, then ops. A copy op
// has bit 7 set and its low bits name the offset/size bytes that follow;
// an insert op has bit 7 clear and its low 7 bits are the literal length.
func applyDelta(base, delta []byte) ([]byte, error) {
	pos := 0
	readVarint := func() (int, error) {
		v := 0
		shift := uint(0)
		for {
			if pos >= len(delta) {
				return 0, fmt.Errorf("delta truncated in varint")
			}
			b := delta[pos]
			pos++
			v |= int(b&0x7f) << shift
			shift += 7
			if b&0x80 == 0 {
				return v, nil
			}
		}
	}
	srcSize, err := readVarint()
	if err != nil {
		return nil, err
	}
	if srcSize != len(base) {
		return nil, fmt.Errorf("delta source size %d != base size %d", srcSize, len(base))
	}
	tgtSize, err := readVarint()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for pos < len(delta) {
		op := delta[pos]
		pos++
		if op&0x80 != 0 {
			// Copy from base.
			off, size := 0, 0
			if op&0x01 != 0 {
				if pos >= len(delta) {
					return nil, fmt.Errorf("delta truncated in copy offset")
				}
				off = int(delta[pos])
				pos++
			}
			if op&0x02 != 0 {
				if pos >= len(delta) {
					return nil, fmt.Errorf("delta truncated in copy offset")
				}
				off |= int(delta[pos]) << 8
				pos++
			}
			if op&0x04 != 0 {
				if pos >= len(delta) {
					return nil, fmt.Errorf("delta truncated in copy offset")
				}
				off |= int(delta[pos]) << 16
				pos++
			}
			if op&0x08 != 0 {
				if pos >= len(delta) {
					return nil, fmt.Errorf("delta truncated in copy offset")
				}
				off |= int(delta[pos]) << 24
				pos++
			}
			if op&0x10 != 0 {
				if pos >= len(delta) {
					return nil, fmt.Errorf("delta truncated in copy size")
				}
				size = int(delta[pos])
				pos++
			}
			if op&0x20 != 0 {
				if pos >= len(delta) {
					return nil, fmt.Errorf("delta truncated in copy size")
				}
				size |= int(delta[pos]) << 8
				pos++
			}
			if op&0x40 != 0 {
				if pos >= len(delta) {
					return nil, fmt.Errorf("delta truncated in copy size")
				}
				size |= int(delta[pos]) << 16
				pos++
			}
			if size == 0 {
				size = 0x10000
			}
			if off+size > len(base) {
				return nil, fmt.Errorf("delta copy out of range (off %d size %d, base %d)", off, size, len(base))
			}
			out.Write(base[off : off+size])
			continue
		}
		// Insert literal bytes.
		if op == 0 {
			return nil, fmt.Errorf("delta has a zero insert opcode")
		}
		n := int(op)
		if pos+n > len(delta) {
			return nil, fmt.Errorf("delta truncated in insert (%d bytes)", n)
		}
		out.Write(delta[pos : pos+n])
		pos += n
	}
	if out.Len() != tgtSize {
		return nil, fmt.Errorf("delta produced %d bytes, target size %d", out.Len(), tgtSize)
	}
	return out.Bytes(), nil
}

// storePackObjects writes every object from a parsed pack into the repo's
// loose object store. Returns the SHAs written.
func storePackObjects(repoDir string, objs map[string]packObject) ([]string, error) {
	shas := make([]string, 0, len(objs))
	for sha, o := range objs {
		if _, err := WriteObject(repoDir, o.Type, o.Data); err != nil {
			return nil, err
		}
		shas = append(shas, sha)
	}
	sort.Strings(shas)
	return shas, nil
}
