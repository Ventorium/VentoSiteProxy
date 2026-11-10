#!/usr/bin/env bash
# P2c E2E：站点 901（DSH, egt-dsh.aihualing.com）认证闭环验证
# 依赖：/tmp/e2e.jar（vsp_test_ldap 的有效会话）
set -u
H='Host: egt-dsh.aihualing.com'
B=http://127.0.0.1
PASS=0; FAIL=0
ck() {
  if [ "$2" = "$3" ]; then echo "PASS  $1 -> $3"; PASS=$((PASS+1)); else echo "FAIL  $1 expected=$2 got=$3"; FAIL=$((FAIL+1)); fi
}

set_users() {
python3 - "$1" <<'PYEOF'
import sys
users = sys.argv[1]  # 逗号分隔；"EMPTY" 表示空列表
p = "/opt/ventositeproxy/sites.yaml"
t = open(p, encoding="utf-8").read()
if users == "EMPTY":
    repl = "    allowed_users: []\n"
else:
    repl = "    allowed_users:\n" + "".join("    - " + u + "\n" for u in users.split(","))
import re
new, n = re.subn(r"(?m)^    allowed_users:(?: \[[^\]]*\])?(?:\n    - [^\n]*)*\n", repl, t, count=1)
assert n == 1, "allowed_users block not found"
open(p, "w", encoding="utf-8").write(new)
import yaml
d = yaml.safe_load(open(p, encoding="utf-8"))
sites = d if isinstance(d, list) else d.get("sites", [])
print("901 auth =", [s for s in sites if s.get("id") == 901][0].get("auth"))
PYEOF
}

echo "== A. 错误密码（期望 401）=="
r=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" -X POST -d '{"username":"vsp_test_ldap","password":"wrong"}' "$B/__auth/login")
ck "wrong-pw 401" 401 "$r"

echo "== B. /me（期望 source=ldap + VSP_TEST）=="
r=$(curl -s -b /tmp/e2e.jar -H "$H" "$B/__auth/me")
echo "$r"
echo "$r" | grep -q '"source":"ldap"' && { echo "PASS /me source"; PASS=$((PASS+1)); } || { echo "FAIL /me source"; FAIL=$((FAIL+1)); }
echo "$r" | grep -q 'VSP_TEST' && { echo "PASS /me groups"; PASS=$((PASS+1)); } || { echo "FAIL /me groups"; FAIL=$((FAIL+1)); }

echo "== C. 空名单 = 谁都不允许（期望 403 + list_empty=true）=="
set_users EMPTY
sleep 4
r=$(curl -s -b /tmp/e2e.jar -o /tmp/rC.json -w "%{http_code}" -H "$H" "$B/")
ck "empty-list 403" 403 "$r"
grep -q 'list_empty=true' /tmp/rC.json || tail -1 /opt/ventositeproxy/logs/auth.jsonl | grep -q 'list_empty=true' \
  && { echo "PASS audit list_empty=true"; PASS=$((PASS+1)); } || { echo "FAIL audit list_empty=true"; FAIL=$((FAIL+1)); }

echo "== D. 恢复名单 [erguotou]，vsp_test_ldap 再次被拒（期望 403 + list_empty=false）=="
set_users erguotou
sleep 4
r=$(curl -s -b /tmp/e2e.jar -o /dev/null -w "%{http_code}" -H "$H" "$B/")
ck "restored deny 403" 403 "$r"
tail -1 /opt/ventositeproxy/logs/auth.jsonl | grep -q 'list_empty=false' \
  && { echo "PASS audit list_empty=false"; PASS=$((PASS+1)); } || { echo "FAIL audit list_empty=false"; FAIL=$((FAIL+1)); }

echo ""
echo "== P2C RESULT: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
