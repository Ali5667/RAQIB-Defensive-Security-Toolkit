#!/bin/bash
# =====================================================
#  Weak Permission Scanner — فاحص الصلاحيات الضعيفة
#  يفحص: 777/666 files، مفاتيح SSH مكشوفة، ملفات
#  config مقروءة للكل، .env files، ملفات DB مكشوفة،
#  certificates بصلاحيات واسعة، scripts مقروءة بكلمات
#  سر، Docker/K8s secrets مكشوفة، backup files
# =====================================================
finding_reset

TOOL_TITLE="$(t vul3_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -rp "$(t vul3_prompt_dir)  [افتراضي: /]: " dir
dir="${dir:-/}"
[ ! -d "$dir" ] && { echo -e "${RED}$(t c_dir_not_found)${NC}"; exit 1; }

REPORT=""

# ─── 1. ملفات 777/666 ────────────────────────────────────────
echo -e "${BOLD}${YELLOW}$(t vul3_wide_open) (perms: 777 أو 666)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

run_with_spinner "  البحث... " -- bash -c "
find \"$dir\" -xdev -type f \\( -perm 0777 -o -perm 0666 \\) \
    ! -path '*/proc/*' ! -path '*/sys/*' ! -path '*/dev/*' \
    2>/dev/null | head -40 > /tmp/.raqib_wide_open
"
wide_open=$(cat /tmp/.raqib_wide_open 2>/dev/null)
rm -f /tmp/.raqib_wide_open

if [ -n "$wide_open" ]; then
    wo_count=$(echo "$wide_open" | wc -l)
    echo -e "  ${RED}$wo_count ملف بصلاحيات مفتوحة بالكامل:${NC}"
    echo "$wide_open" | while IFS= read -r f; do
        perm=$(raqib_stat_perm "$f" 2>/dev/null || echo "?")
        owner=$(stat -c '%U:%G' "$f" 2>/dev/null || stat -f '%Su:%Sg' "$f" 2>/dev/null || echo "?")
        echo -e "  ${RED}  🔴 $f  ${GREY}(perms: $perm, owner: $owner)${NC}"
        finding_add critical "Wide-open file (perms: $perm): $f"
    done
else
    echo -e "  ${GREEN}لا توجد ملفات 777/666${NC}"
fi

REPORT+="=== 777/666 Files ===
${wide_open:-None}

"

# ─── 2. مفاتيح SSH وشهادات TLS ──────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}$(t vul3_ssh_keys) + شهادات TLS${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

key_files=$(find "$dir" -xdev -type f \( \
    -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o \
    -name "id_dsa" -o -name "*.pem" -o -name "*.key" -o \
    -name "*.p12" -o -name "*.pfx" -o -name "*.jks" -o \
    -name "*.keystore" \
    \) ! -path '*/proc/*' ! -path '*/sys/*' 2>/dev/null | head -30)

if [ -n "$key_files" ]; then
    echo "$key_files" | while IFS= read -r f; do
        perm=$(raqib_stat_perm "$f" 2>/dev/null || echo "?")
        if [ "$perm" = "600" ] || [ "$perm" = "0600" ] || [ "$perm" = "400" ] || [ "$perm" = "0400" ]; then
            echo -e "  ${GREEN}  ✓ $f  ${GREY}(perms: $perm — آمن)${NC}"
        else
            echo -e "  ${RED}  🔴 $f  ${GREY}(perms: $perm — خطر! يجب 600 أو 400)${NC}"
            finding_add high "SSH/TLS key with weak permissions ($perm): $f"
        fi
    done
else
    echo -e "  ${GREEN}لا توجد مفاتيح مكشوفة${NC}"
fi

REPORT+="=== SSH/TLS Keys ===
${key_files:-None}

"

# ─── 3. ملفات .env وملفات التكوين ─────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}$(t vul3_config_secrets) (.env, config.php, *.conf)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

config_files=$(find "$dir" -xdev -type f \( \
    -name ".env" -o -name ".env.local" -o -name ".env.production" -o \
    -name "config.php" -o -name "wp-config.php" -o \
    -name "settings.py" -o -name "application.yml" -o \
    -name "application.properties" -o -name "database.yml" -o \
    -name "credentials.json" -o -name "service-account*.json" -o \
    -name ".htpasswd" -o -name ".pgpass" -o -name ".my.cnf" -o \
    -name ".netrc" \
    \) ! -path '*/node_modules/*' ! -path '*/vendor/*' \
    ! -path '*/proc/*' ! -path '*/sys/*' 2>/dev/null | head -30)

if [ -n "$config_files" ]; then
    echo "$config_files" | while IFS= read -r f; do
        perm=$(raqib_stat_perm "$f" 2>/dev/null || echo "?")
        # هل هو مقروء للكل (world-readable)?
        if [[ "$perm" =~ [0-7][0-7][4-7] ]] || [ -r "$f" ] 2>/dev/null; then
            # فحص: هل يحتوي أسرار فعلية؟
            has_secrets=0
            if grep -qiE 'password|secret|api.key|token|db_pass' "$f" 2>/dev/null; then
                has_secrets=1
            fi

            if [ "$has_secrets" -eq 1 ]; then
                echo -e "  ${RED}  🔴 $f  ${GREY}(perms: $perm — يحتوي أسرار!)${NC}"
                finding_add critical "Config file with secrets is world-readable ($perm): $f"
            else
                echo -e "  ${ORANGE}  ⚠️  $f  ${GREY}(perms: $perm)${NC}"
                finding_add medium "Config file world-readable ($perm): $f"
            fi
        else
            echo -e "  ${GREEN}  ✓ $f  ${GREY}(perms: $perm)${NC}"
        fi
    done
else
    echo -e "  ${GREEN}لا توجد ملفات تكوين مكشوفة${NC}"
fi

REPORT+="=== Config Files ===
${config_files:-None}

"

# ─── 4. ملفات قاعدة بيانات مكشوفة ────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ ملفات قاعدة بيانات مكشوفة${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

db_files=$(find "$dir" -xdev -type f \( \
    -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.db" -o \
    -name "*.sql" -o -name "*.dump" -o -name "*.bak" \
    \) -perm -0004 \
    ! -path '*/proc/*' ! -path '*/sys/*' 2>/dev/null | head -20)

if [ -n "$db_files" ]; then
    echo "$db_files" | while IFS= read -r f; do
        fsize=$(raqib_stat_size "$f" 2>/dev/null || echo "?")
        echo -e "  ${RED}  🔴 $f  ${GREY}(size: $fsize B — مقروء للكل!)${NC}"
        finding_add high "Database file world-readable: $f"
    done
else
    echo -e "  ${GREEN}لا توجد ملفات DB مكشوفة${NC}"
fi

# ─── 5. ملفات Backup مكشوفة ──────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ ملفات Backup مكشوفة في مجلدات الويب${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

web_dirs=("/var/www" "/srv/http" "/var/www/html" "/usr/share/nginx/html")
backup_found=0
for wd in "${web_dirs[@]}"; do
    [ -d "$wd" ] || continue
    backups=$(find "$wd" -type f \( \
        -name "*.bak" -o -name "*.old" -o -name "*.orig" -o \
        -name "*.save" -o -name "*.swp" -o -name "*~" -o \
        -name "*.sql" -o -name "*.tar.gz" -o -name "*.zip" -o \
        -name ".git" -o -name ".svn" -o -name ".env" \
        \) 2>/dev/null | head -15)
    if [ -n "$backups" ]; then
        echo -e "  ${ORANGE}في $wd:${NC}"
        echo "$backups" | while IFS= read -r bf; do
            echo -e "  ${ORANGE}  ⚠️  $bf${NC}"
            finding_add high "Backup/sensitive file in web root: $bf"
        done
        backup_found=1
    fi
done
[ "$backup_found" -eq 0 ] && echo -e "  ${GREEN}لا توجد ملفات backup مكشوفة بالويب${NC}"

# ─── 6. Docker/Kubernetes secrets ────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ Docker/K8s/Cloud secrets مكشوفة${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

cloud_secrets=$(find "$dir" -xdev -type f \( \
    -name "docker-compose*.yml" -o \
    -name "Dockerfile" -o \
    -name "kubeconfig" -o -name ".kube/config" -o \
    -name "terraform.tfvars" -o -name "*.tfstate" -o \
    -name "aws_credentials" -o -name ".boto" \
    \) -perm -0004 \
    ! -path '*/proc/*' 2>/dev/null | head -10)

if [ -n "$cloud_secrets" ]; then
    echo "$cloud_secrets" | while IFS= read -r cs; do
        echo -e "  ${RED}  🔴 $cs — مقروء للكل!${NC}"
        finding_add high "Cloud/container config world-readable: $cs"
    done
else
    echo -e "  ${GREEN}لا توجد ملفات cloud/container مكشوفة${NC}"
fi

# ─── 7. ملخص ─────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "Weak Permission Scan — $(date)
Directory: $dir

$REPORT" "weak_permission_scan.txt" "$TOOL_TITLE"
