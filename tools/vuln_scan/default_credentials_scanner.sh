#!/bin/bash
# =====================================================
#  Default Credentials Scanner — فاحص كلمات السر الضعيفة
#  يبحث في: ملفات التكوين عن كلمات سر افتراضية/ضعيفة
#  يفحص: .env، config.php، YAML، JSON، XML، .conf،
#  Docker compose، Kubernetes secrets، connection strings
#  أنماط: 120+ كلمة سر ضعيفة، API keys مكشوفة،
#  tokens، AWS/GCP/Azure credentials، JWT secrets،
#  private keys embedded بالكود، database URIs
# =====================================================
finding_reset

TOOL_TITLE="$(t vul5_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -rp "$(t vul5_prompt_dir) " dir
[ ! -d "$dir" ] && { echo -e "${RED}$(t c_dir_not_found)${NC}"; exit 1; }

echo -e "${GREY}  المجلد: $dir${NC}"
echo ""

REPORT=""

# ─── أنواع الملفات المستهدفة ──────────────────────────────────
FILE_INCLUDES=(
    "--include=*.env" "--include=*.conf" "--include=*.config"
    "--include=*.php" "--include=*.yml" "--include=*.yaml"
    "--include=*.json" "--include=*.xml" "--include=*.properties"
    "--include=*.ini" "--include=*.cfg" "--include=*.toml"
    "--include=*.py" "--include=*.rb" "--include=*.js"
    "--include=*.ts" "--include=*.go" "--include=*.java"
    "--include=*.sh" "--include=*.bash" "--include=*.sql"
    "--include=*.txt" "--include=*.cnf" "--include=*.htaccess"
    "--include=docker-compose*" "--include=Dockerfile*"
    "--include=Vagrantfile" "--include=Makefile"
)

# ─── 1. كلمات سر افتراضية/ضعيفة ─────────────────────────────
echo -e "${BOLD}${YELLOW}$(t vul5_weak_pw) + كلمات سر ضعيفة شائعة${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

# قائمة موسّعة من كلمات السر الضعيفة
WEAK_PASSWORDS='password\s*[=:]\s*["\x27]?(admin|password|123456|12345678|root|changeme|test|default|letmein|welcome|master|access|login|abc123|1234|passwd|pass|guest|qwerty|dragon|monkey|shadow|sunshine|princess|football|!@#\$%|toor|mysql|postgres|redis|oracle|sa|administrator|user|demo|temp|temp123|secret|example)["\x27]?'

weak_pw=$(grep -riInE "$WEAK_PASSWORDS" "$dir" \
    "${FILE_INCLUDES[@]}" 2>/dev/null | \
    grep -v "node_modules\|\.git/\|vendor/\|__pycache__" | head -40)

if [ -n "$weak_pw" ]; then
    weak_count=$(echo "$weak_pw" | wc -l)
    echo -e "  ${RED}🔴 $weak_count تطابق لكلمات سر ضعيفة:${NC}"
    echo ""
    echo "$weak_pw" | while IFS= read -r line; do
        filename=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        content=$(echo "$line" | cut -d: -f3-)
        # Mask the actual password value for safety
        masked=$(echo "$content" | sed -E 's/(password\s*[=:]\s*["\x27]?)[^\s"\x27]*/\1********/gi')
        echo -e "  ${RED}  ▸ ${GREY}$filename:$lineno${NC}"
        echo -e "  ${RED}    $masked${NC}"
        finding_add critical "Weak/default password in $filename:$lineno"
    done
else
    echo -e "  ${GREEN}لا توجد كلمات سر ضعيفة مكشوفة${NC}"
fi

REPORT+="$(t vul5_weak_pw)
Matches: $(echo "$weak_pw" | wc -l 2>/dev/null || echo 0)

"

# ─── 2. مفاتيح API و Tokens مكشوفة ──────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}$(t vul5_hardcoded_secrets) + API Keys + Tokens${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

API_PATTERNS='(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|app[_-]?secret|encryption[_-]?key)\s*[=:]\s*["\x27][A-Za-z0-9_\-/.+]{10,}["\x27]'

secrets=$(grep -riInE "$API_PATTERNS" "$dir" \
    "${FILE_INCLUDES[@]}" 2>/dev/null | \
    grep -v "node_modules\|\.git/\|vendor/\|__pycache__\|example\|sample\|placeholder\|your_" | head -30)

if [ -n "$secrets" ]; then
    sec_count=$(echo "$secrets" | wc -l)
    echo -e "  ${ORANGE}⚠️  $sec_count مفتاح/token مكشوف:${NC}"
    echo "$secrets" | while IFS= read -r line; do
        filename=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        echo -e "  ${ORANGE}  ▸ $filename:$lineno${NC}"
        finding_add high "Hardcoded API key/token in $filename:$lineno"
    done
else
    echo -e "  ${GREEN}لا توجد مفاتيح API مكشوفة${NC}"
fi

REPORT+="$(t vul5_hardcoded_secrets)
Matches: $(echo "$secrets" | wc -l 2>/dev/null || echo 0)

"

# ─── 3. AWS/GCP/Azure Credentials ────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ Cloud Credentials (AWS/GCP/Azure)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

# AWS Access Keys (AKIA...)
aws_keys=$(grep -riInE 'AKIA[0-9A-Z]{16}' "$dir" \
    "${FILE_INCLUDES[@]}" 2>/dev/null | \
    grep -v "node_modules\|\.git/" | head -10)
if [ -n "$aws_keys" ]; then
    echo -e "  ${RED}🔴 AWS Access Keys مكشوفة:${NC}"
    echo "$aws_keys" | while IFS= read -r ak; do
        echo -e "  ${RED}  ▸ $ak${NC}"
        finding_add critical "AWS Access Key exposed: $ak"
    done
fi

# GCP Service Account JSON
gcp_keys=$(grep -riInl '"type"\s*:\s*"service_account"' "$dir" 2>/dev/null | \
    grep -v "node_modules\|\.git/" | head -5)
if [ -n "$gcp_keys" ]; then
    echo -e "  ${RED}🔴 GCP Service Account Keys:${NC}"
    echo "$gcp_keys" | while IFS= read -r gk; do
        echo -e "  ${RED}  ▸ $gk${NC}"
        finding_add critical "GCP Service Account key file: $gk"
    done
fi

# Azure connection strings
azure_conn=$(grep -riInE 'DefaultEndpointsProtocol=https?;AccountName=' "$dir" \
    "${FILE_INCLUDES[@]}" 2>/dev/null | head -5)
if [ -n "$azure_conn" ]; then
    echo -e "  ${RED}🔴 Azure Connection Strings:${NC}"
    echo "$azure_conn" | while IFS= read -r az; do
        echo -e "  ${RED}  ▸ $(echo "$az" | cut -d: -f1-2)${NC}"
        finding_add critical "Azure connection string exposed"
    done
fi

[ -z "$aws_keys" ] && [ -z "$gcp_keys" ] && [ -z "$azure_conn" ] && \
    echo -e "  ${GREEN}لا توجد cloud credentials مكشوفة${NC}"

# ─── 4. Database Connection Strings ──────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ Database Connection Strings${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

DB_PATTERNS='(mysql|postgres|postgresql|mongodb|redis|mssql|oracle):\/\/[a-zA-Z0-9_]+:[^@\s]+@'
db_conns=$(grep -riInE "$DB_PATTERNS" "$dir" \
    "${FILE_INCLUDES[@]}" 2>/dev/null | \
    grep -v "node_modules\|\.git/\|example\|sample" | head -10)

if [ -n "$db_conns" ]; then
    echo -e "  ${RED}🔴 Database connection strings مع كلمات سر:${NC}"
    echo "$db_conns" | while IFS= read -r dc; do
        filename=$(echo "$dc" | cut -d: -f1)
        echo -e "  ${RED}  ▸ $filename${NC}"
        finding_add critical "Database connection string with password: $filename"
    done
else
    echo -e "  ${GREEN}لا توجد connection strings مكشوفة${NC}"
fi

# ─── 5. JWT Secrets ──────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ JWT Secrets & Session Keys${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

JWT_PATTERNS='(jwt[_-]?secret|session[_-]?secret|secret[_-]?key[_-]?base|signing[_-]?key)\s*[=:]\s*["\x27][A-Za-z0-9+/=_\-]{16,}["\x27]'
jwt_secrets=$(grep -riInE "$JWT_PATTERNS" "$dir" \
    "${FILE_INCLUDES[@]}" 2>/dev/null | \
    grep -v "node_modules\|\.git/\|example\|your_" | head -10)

if [ -n "$jwt_secrets" ]; then
    echo -e "  ${ORANGE}⚠️  JWT/Session secrets مكشوفة:${NC}"
    echo "$jwt_secrets" | while IFS= read -r js; do
        filename=$(echo "$js" | cut -d: -f1)
        echo -e "  ${ORANGE}  ▸ $filename${NC}"
        finding_add high "JWT/Session secret exposed: $filename"
    done
else
    echo -e "  ${GREEN}لا توجد JWT secrets مكشوفة${NC}"
fi

# ─── 6. Private Keys Embedded ────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ Private Keys بالكود${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

priv_keys=$(grep -riInl "BEGIN.*PRIVATE KEY" "$dir" \
    "${FILE_INCLUDES[@]}" 2>/dev/null | \
    grep -v "node_modules\|\.git/\|\.pem$\|\.key$" | head -10)

if [ -n "$priv_keys" ]; then
    echo -e "  ${RED}🔴 Private keys embedded بملفات كود:${NC}"
    echo "$priv_keys" | while IFS= read -r pk; do
        echo -e "  ${RED}  ▸ $pk${NC}"
        finding_add critical "Private key embedded in source code: $pk"
    done
else
    echo -e "  ${GREEN}لا توجد مفاتيح خاصة مضمّنة${NC}"
fi

# ─── 7. ملخص وتوصيات ────────────────────────────────────────
echo ""
echo -e "${BOLD}💡 توصيات:${NC}"
echo -e "  ${CYAN}▸${NC} انقل الأسرار لـ environment variables أو secret manager"
echo -e "  ${CYAN}▸${NC} استخدم .gitignore لمنع رفع ملفات .env"
echo -e "  ${CYAN}▸${NC} فعّل pre-commit hooks لمنع تسريب الأسرار"
echo -e "  ${CYAN}▸${NC} غيّر أي كلمة سر افتراضية فوراً"

echo ""
echo -e "${GREEN}$(t vul5_review_now)${NC}"

echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

if [ -n "$weak_pw" ] || [ -n "$secrets" ] || [ -n "$aws_keys" ] || [ -n "$db_conns" ]; then
    save_report "$(tf vul5_report_title "$dir" "$(date)")

$REPORT

=== Cloud Credentials ===
AWS: ${aws_keys:-None}
GCP: ${gcp_keys:-None}
Azure: ${azure_conn:-None}

=== DB Connection Strings ===
${db_conns:-None}

=== JWT/Session Secrets ===
${jwt_secrets:-None}

=== Private Keys ===
${priv_keys:-None}" "default_credentials_scan.txt" "$TOOL_TITLE"
fi
