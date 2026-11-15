# github-core-clone-01 — a standalone GitHub-compatible git forge

A single-process, GitHub-compatible git forge: git smart HTTP (upload-pack protocol v2,
receive-pack v0), the REST v3 API under `/api/v3`, GraphQL v4 at `/api/graphql`, and a
Model Context Protocol endpoint at `/mcp`. It serves from its own store (SQLite metadata
plus loose git objects and refs on disk), with no UI, no outside service, no proxy, and
no git binary — the git protocol (objects, packfiles, deltas, refs, smart HTTP) is
implemented in pure Go.

Built for the [make.fun bounty](https://make.fun/bounty/github-core-clone-01)
"Build a GitHub-compatible git forge". It also runs as a self-hosted GitHub
replacement (see Docker below).

## Features

- **Git smart HTTP** — clone, fetch, push over `/{owner}/{repo}.git`; protocol v2
  upload-pack, v0 receive-pack, fast-forward enforcement (`ng <ref> non-fast-forward`),
  tag deletion.
- **REST v3** — repositories, branches, commits, contents, issues, comments, labels,
  pull requests (with a real 3-way merge and conflict detection), collaborators, search.
- **GraphQL v4** — viewer, repository, issues, pull requests, introspection, mutations.
- **MCP** — `create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request` (plus `list_repos`, `get_file`).
- **Auth + permissions** — owner, collaborator (read/write/admin), public/private repos.
- **Webhooks** — CRUD, HMAC-SHA256 signatures, delivery log, events
  `push` / `issues` / `pull_request`.
- **Search** — `GET /api/v3/search/repositories?q=...`.

## Layout

- `main.ts` — the entrypoint the grader runs (`node /bot/main.ts`). A thin launcher: it
  spawns `./forge` and waits for it. The Go program owns the lifecycle (bind an ephemeral
  port, register it with the env, poll for done, exit 0) and the whole HTTP surface.
- `forge` — the statically linked Linux amd64 binary of the Go program (vendored).
- `main.go` — the Go source: HTTP server, REST v3, GraphQL v4, MCP, webhooks, and the
  wire lifecycle. The git protocol lives in `git.go` (objects, packfiles, refs, smart
  HTTP), written in pure Go with no `git` binary.
- `go.mod`, `go.sum` — the Go module (only dependency: `modernc.org/sqlite`).
- `Dockerfile`, `docker-compose.yml` — self-hosted run (FROM scratch, ~15 MB image).
- `test.sh` — end-to-end test (uses the local git CLI only as a client).
- `.makefun/owner.json` — the claim file naming the entry wallet.

## Run it locally

```sh
# Build the binary (Go 1.23+, no CGO so it is static).
CGO_ENABLED=0 go build -o forge .

# Serve on :8000 with data in ./data.
./forge

# Or set the port and data dir.
PORT=8001 FORGE_DATA=/tmp/forge-data ./forge
```

The forge binds an ephemeral port and registers with the suite only when
`MAKEFUN_ENV_URL` is set; otherwise it serves on `$PORT` (default 8000) until killed.
Every API call takes `Authorization: Bearer $MAKEFUN_SHOP_TOKEN` (a request without it
is 401); `/healthz` is the boot probe and takes none.

## What it serves

| Route | What it is |
| --- | --- |
| `GET /healthz` | 200 `{"ok":true}` |
| `GET /api/v3/` | 200, `X-OAuth-Scopes: repo, read:org` |
| `GET /api/v3/meta` | 200, `{"installed_version": "1.0.0"}` |
| `/api/v3/...` | GitHub REST v3: repositories, branches, commits, contents, issues, comments, labels, pull requests, files, merges |
| `POST /api/graphql` | GitHub GraphQL v4: viewer, repository, issues, pull requests, introspection, mutations |
| `POST /mcp` | Model Context Protocol over streamable HTTP: initialize / server/discover, tools/list, tools/call |
| `/<owner>/<repo>.git/...` | git smart HTTP: `info/refs`, `git-upload-pack`, `git-receive-pack` |
| anything else | 404 `{"message":"Not Found"}` |

## Notes

- Repositories are created through REST (`POST /api/v3/user/repos`); a push cannot
  invent one. A repository belongs to the login the bearer token names; the same name
  under another owner is 404, never 403.
- Pushes must fast-forward: a non-fast-forward push is refused per ref with
  `ng <ref> non-fast-forward` and the ref does not move.
- Pull requests merge by squash onto the base branch.

## License

MIT. See `LICENSE`.
