#!/usr/bin/env bash
# P2 E2E Part 1：登录 + 访问 + /me（在主机 bbb 上执行）
set -u
H='Host: p2demo.ainanjing.org.cn'
B=http://127.0.0.1
PASS=0; FAIL=0
ck() {
  if [ "$2" = "$3" ]; then echo "PASS  $1 -> $3"; PASS=$((PASS+1)); else echo "FAIL  $1 expected=$2 got=$3"; FAIL=$((FAIL+1)); fi
}

echo "== 1. 未认证 GET /（期望 401 JSON + login_url）=="
r=$(curl -s -o /tmp/p2_r1.json -w "%{http_code}" -H "$H" "$B/")
ck "no-auth 401" 401 "$r"
cat /tmp/p2_r1.json; echo
grep -q '"ok":false' /tmp/p2_r1.json && { echo "PASS  body ok:false"; PASS=$((PASS+1)); } || { echo "FAIL  body ok:false"; FAIL=$((FAIL+1)); }
grep -q '__auth/login' /tmp/p2_r1.json && { echo "PASS  body login_url"; PASS=$((PASS+1)); } || { echo "FAIL  body login_url"; FAIL=$((FAIL+1)); }

echo "== 2. 错误密码（期望 401）=="
r=$(curl -s -o /tmp/p2_r2.json -w "%{http_code}" -H "$H" -X POST -d '{"username":"vsp_test_ldap","password":"wrong-pass"}' "$B/__auth/login")
ck "wrong-pw 401" 401 "$r"
cat /tmp/p2_r2.json; echo

echo "== 3. 未知用户（期望 401）=="
r=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" -X POST -d '{"username":"no_such_user_zz","password":"x"}' "$B/__auth/login")
ck "unknown-user 401" 401 "$r"

echo "== 4. LDAP 登录（期望 200 + cookie + source=ldap + VSP_TEST）=="
rm -f /tmp/p2_jar
r=$(curl -s -c /tmp/p2_jar -o /tmp/p2_r4.json -w "%{http_code}" -H "$H" -X POST -d '{"username":"vsp_test_ldap","password":"VspTest@2026"}' "$B/__auth/login")
ck "ldap-login 200" 200 "$r"
cat /tmp/p2_r4.json; echo
grep -q '"ok":true' /tmp/p2_r4.json && { echo "PASS  ok:true"; PASS=$((PASS+1)); } || { echo "FAIL  ok:true"; FAIL=$((FAIL+1)); }
grep -q '"source":"ldap"' /tmp/p2_r4.json && { echo "PASS  source=ldap"; PASS=$((PASS+1)); } || { echo "FAIL  source=ldap"; FAIL=$((FAIL+1)); }
grep -q 'VSP_TEST' /tmp/p2_r4.json && { echo "PASS  groups VSP_TEST"; PASS=$((PASS+1)); } || { echo "FAIL  groups VSP_TEST"; FAIL=$((FAIL+1)); }
grep -q 'vsp_session' /tmp/p2_jar && { echo "PASS  cookie vsp_session"; PASS=$((PASS+1)); } || { echo "FAIL  cookie vsp_session"; FAIL=$((FAIL+1)); }

echo "== 5. 带会话 GET /（期望 200 演示页）=="
r=$(curl -s -b /tmp/p2_jar -o /tmp/p2_r5.html -w "%{http_code}" -H "$H" "$B/")
ck "auth GET / 200" 200 "$r"
grep -q "P2" /tmp/p2_r5.html && { echo "PASS  demo page body"; PASS=$((PASS+1)); } || { echo "FAIL  demo page body"; FAIL=$((FAIL+1)); }

echo "== 6. /me（期望 source=ldap + VSP_TEST）=="
r=$(curl -s -b /tmp/p2_jar -H "$H" "$B/__auth/me")
echo "$r"
echo "$r" | grep -q '"source":"ldap"' && { echo "PASS  /me source=ldap"; PASS=$((PASS+1)); } || { echo "FAIL  /me source"; FAIL=$((FAIL+1)); }
echo "$r" | grep -q 'VSP_TEST' && { echo "PASS  /me groups VSP_TEST"; PASS=$((PASS+1)); } || { echo "FAIL  /me groups"; FAIL=$((FAIL+1)); }

echo ""
echo "== PART1 RESULT: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
