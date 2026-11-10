#!/usr/bin/env bash
# P2 E2E Part 2：站点 ACL 热切换验证（依赖 /tmp/p2_jar）
set -u
H='Host: p2demo.ainanjing.org.cn'
B=http://127.0.0.1
PASS=0; FAIL=0
ck() {
  if [ "$2" = "$3" ]; then echo "PASS  $1 -> $3"; PASS=$((PASS+1)); else echo "FAIL  $1 expected=$2 got=$3"; FAIL=$((FAIL+1)); fi
}

set_groups() {
python3 - "$1" <<'PYEOF'
import sys
groups = sys.argv[1].split(',')
p = "/opt/ventositeproxy/sites.yaml"
t = open(p, encoding="utf-8").read()
marker = "  auth:\n    enabled: true"
start = t.index(marker)
end = t.index("streams:")
block = t[start:end]
lines = ["allowed_groups:"]
for g in groups:
    lines.append("    - " + g)
new_block = "\n".join(lines) + "\n"
import re
new = re.sub(r"allowed_groups:\n(?:    - [^\n]*\n)+", new_block, block, count=1)
open(p, "w", encoding="utf-8").write(t[:start] + new + t[end:])
print("allowed_groups ->", groups)
PYEOF
}

echo "== 7. ACL=[NOSUCHGRP]：会话有效但组不匹配（期望 403）=="
set_groups NOSUCHGRP
sleep 4
r=$(curl -s -b /tmp/p2_jar -o /tmp/p2_r7.json -w "%{http_code}" -H "$H" "$B/")
ck "ACL deny 403" 403 "$r"
cat /tmp/p2_r7.json; echo

echo "== 8. 恢复 ACL=[Turing, VSP_TEST]（期望 200）=="
set_groups Turing,VSP_TEST
sleep 4
r=$(curl -s -b /tmp/p2_jar -o /dev/null -w "%{http_code}" -H "$H" "$B/")
ck "ACL allow 200" 200 "$r"

echo ""
echo "== PART2 RESULT: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
