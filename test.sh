#!/bin/bash
# End-to-end test for the forge (pure Go, no git binary on the server side).
# The forge itself never shells out to git; this script uses the local git CLI
# only as a *client* (clone/push) to prove protocol compatibility.
set -e
BASE=${BASE:-http://localhost:8000}
TOKEN="Bearer token-admin-123"

echo "=== 1. Health ==="
curl -s $BASE/healthz | head -c 200; echo

echo "=== 2. Create repo ==="
curl -s -X POST $BASE/api/v3/user/repos -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d '{"name":"demo","description":"demo forge"}'; echo

echo "=== 3. Clone + push main ==="
rm -rf /tmp/demo && git clone -q $BASE/admin/demo.git /tmp/demo
cd /tmp/demo
git config user.email "a@a.com"; git config user.name "admin"
echo "# demo" > README.md
git add . && git commit -qm "init" && git branch -M main && git push -q origin main

echo "=== 4. Branch feature + PR ==="
git checkout -qb feature
echo "fitur baru" > fitur.txt
git add . && git commit -qm "add fitur" && git push -q origin feature
git checkout -q main

curl -s -X POST $BASE/api/v3/repos/admin/demo/pulls -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d '{"title":"Tambah fitur","head":"feature","base":"main"}'; echo

echo "=== 5. Merge PR #1 (3-way) ==="
curl -s -X PUT $BASE/api/v3/repos/admin/demo/pulls/1/merge -H "Authorization: $TOKEN"; echo

echo "=== 6. File hasil merge ==="
curl -s "$BASE/api/v3/repos/admin/demo/contents/fitur.txt" -H "Authorization: $TOKEN" | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['content']).decode())"

echo "=== 7. Issue + comment ==="
curl -s -X POST $BASE/api/v3/repos/admin/demo/issues -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d '{"title":"bug"}'; echo
curl -s -X POST $BASE/api/v3/repos/admin/demo/issues/1/comments -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d '{"body":"sudah diperbaiki"}'; echo

echo "=== 8. Webhook ==="
curl -s -X POST $BASE/api/v3/repos/admin/demo/hooks -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d '{"url":"https://webhook.site/test","secret":"s3cr3t","events":["push","pull_request"]}'; echo

echo "=== 9. GraphQL ==="
curl -s -X POST $BASE/api/graphql -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d '{"query":"{ repository(owner:\"admin\", name:\"demo\"){ fullName description } }"}'; echo

echo "=== 10. MCP ==="
curl -s -X POST $BASE/mcp -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'; echo

echo "=== 11. Search ==="
curl -s "$BASE/api/v3/search/repositories?q=demo" -H "Authorization: $TOKEN"; echo

echo "=== 12. Collaborator ==="
curl -s -X POST $BASE/api/v3/repos/admin/demo/collaborators -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d '{"login":"dev","permission":"write"}'; echo

echo "ALL DONE"
