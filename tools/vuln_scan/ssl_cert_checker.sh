#!/bin/bash
# =====================================================
#  SSL/TLS Certificate Checker — فاحص شهادات SSL
#  يفحص: صلاحية الشهادة، تاريخ الانتهاء، السلسلة،
#  مستوى التشفير، OCSP stapling، HSTS header،
#  cipher suites المدعومة، ثغرات معروفة (POODLE/BEAST)،
#  Subject Alternative Names، self-signed detection
# =====================================================
finding_reset

TOOL_TITLE="$(t vul4_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -rp "$(t vul4_prompt_domain) " domain
[ -z "$domain" ] && { echo -e "${RED}$(t mon5_need_domain)${NC}"; exit 1; }
# إزالة https:// لو موجودة
domain=$(echo "$domain" | sed 's|https\?://||; s|/.*||')

read -rp "$(t vul4_prompt_port) [افتراضي: 443]: " port
port=${port:-443}
if ! is_valid_port "$port"; then
    echo -e "${RED}$(t mon1_invalid_port_range)${NC}"; exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo -e "${RED}$(t vul4_openssl_missing)${NC}"; exit 1
fi

echo -e "${GREY}  الهدف: $domain:$port${NC}"
echo ""

REPORT=""

# ─── 1. جلب الشهادة ──────────────────────────────────────────
echo -e "${YELLOW}◉ جلب معلومات الشهادة...${NC}"

cert_raw=$(run_with_spinner "$(tf vul4_connecting "$domain" "$port") " -- \
    bash -c 'echo | openssl s_client -connect "$1:$2" -servername "$1" 2>/dev/null' _ "$domain" "$port")

cert_info=$(echo "$cert_raw" | openssl x509 -noout \
    -dates -subject -issuer -serial -fingerprint -ext subjectAltName 2>/dev/null)

if [ -z "$cert_info" ]; then
    echo -e "${RED}$(t vul4_fetch_failed)${NC}"
    finding_add critical "Cannot retrieve SSL certificate from $domain:$port"
    exit 1
fi

echo -e "${GREEN}  ✓ تم جلب الشهادة بنجاح${NC}"
echo ""

# ─── 2. معلومات الشهادة الأساسية ─────────────────────────────
echo -e "${BOLD}${CYAN}━━ معلومات الشهادة ━━${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

# Subject
subject=$(echo "$cert_info" | grep "subject=" | sed 's/subject=//')
echo -e "  ${BOLD}Subject:${NC} $subject"

# Issuer
issuer=$(echo "$cert_info" | grep "issuer=" | sed 's/issuer=//')
echo -e "  ${BOLD}Issuer:${NC}  $issuer"

# Self-signed check
if echo "$subject" | grep -qi "$(echo "$issuer" | grep -oE 'CN\s*=\s*[^,]+' | head -1)"; then
    echo -e "  ${RED}  ⚠️  شهادة Self-Signed! ليست من CA معترف بها${NC}"
    finding_add high "Self-signed certificate on $domain"
fi

# Serial
serial=$(echo "$cert_info" | grep "serial=" | sed 's/serial=//')
echo -e "  ${GREY}Serial:  $serial${NC}"

# Fingerprint
fingerprint=$(echo "$cert_info" | grep "Fingerprint=" | head -1)
echo -e "  ${GREY}$fingerprint${NC}"

# SANs
sans=$(echo "$cert_info" | grep -A1 "Subject Alternative Name" | tail -1)
if [ -n "$sans" ]; then
    echo -e "  ${BOLD}SANs:${NC} $sans"
fi

REPORT+="=== Certificate Info ===
Subject: $subject
Issuer: $issuer
Serial: $serial
$fingerprint
SANs: $sans

"

# ─── 3. صلاحية وتاريخ الانتهاء ──────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ صلاحية الشهادة ━━${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

not_before=$(echo "$cert_info" | grep "notBefore=" | cut -d= -f2)
not_after=$(echo "$cert_info" | grep "notAfter=" | cut -d= -f2)

echo -e "  صالحة من:  ${CYAN}$not_before${NC}"
echo -e "  صالحة حتى: ${CYAN}$not_after${NC}"

expiry_epoch=$(raqib_date_epoch "$not_after")
if [ -z "$expiry_epoch" ]; then
    echo -e "  ${YELLOW}$(t vul4_cant_calc_days)${NC}"
else
    now_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

    echo ""
    if [ "$days_left" -lt 0 ]; then
        echo -e "  ${RED}[CRITICAL] $(t vul4_expired) — منتهية منذ $((-days_left)) يوم!${NC}"
        finding_add critical "SSL certificate EXPIRED on $domain (expired $((- days_left)) days ago)"
    elif [ "$days_left" -lt 7 ]; then
        echo -e "  ${RED}[CRITICAL] $(tf vul4_expiring_soon "$days_left") — أقل من أسبوع!${NC}"
        finding_add critical "SSL certificate expiring in $days_left days on $domain"
    elif [ "$days_left" -lt 15 ]; then
        echo -e "  ${ORANGE}[HIGH] $(tf vul4_expiring_soon "$days_left")${NC}"
        finding_add high "SSL certificate expiring in $days_left days on $domain"
    elif [ "$days_left" -lt 30 ]; then
        echo -e "  ${YELLOW}[MEDIUM] $(tf vul4_expiring_soon "$days_left")${NC}"
        finding_add medium "SSL certificate expiring in $days_left days on $domain"
    else
        echo -e "  ${GREEN}[OK] $(tf vul4_valid "$days_left") ✅${NC}"
    fi
fi

REPORT+="=== Validity ===
Not Before: $not_before
Not After: $not_after
Days Left: ${days_left:-unknown}

"

# ─── 4. قوة المفتاح ──────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ قوة التشفير ━━${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

key_info=$(echo "$cert_raw" | openssl x509 -noout -text 2>/dev/null | \
    grep -A1 "Public Key Algorithm\|Public-Key:" | head -4)

key_algo=$(echo "$key_info" | grep "Public Key Algorithm" | sed 's/.*: //')
key_size=$(echo "$key_info" | grep "Public-Key:" | grep -oE '[0-9]+')

echo -e "  Algorithm: ${BOLD}$key_algo${NC}"
echo -e "  Key Size:  ${BOLD}${key_size:-?} bit${NC}"

if [ -n "$key_size" ]; then
    if echo "$key_algo" | grep -qi "rsa"; then
        if [ "$key_size" -lt 2048 ]; then
            echo -e "  ${RED}[CRITICAL] RSA key < 2048 bit — ضعيف جداً!${NC}"
            finding_add critical "Weak RSA key ($key_size bit) on $domain"
        elif [ "$key_size" -lt 4096 ]; then
            echo -e "  ${GREEN}[OK] RSA $key_size bit — مقبول${NC}"
        else
            echo -e "  ${GREEN}[STRONG] RSA $key_size bit — ممتاز${NC}"
        fi
    elif echo "$key_algo" | grep -qi "ec\|ecdsa"; then
        if [ "$key_size" -lt 256 ]; then
            echo -e "  ${RED}[HIGH] ECDSA key < 256 bit — ضعيف${NC}"
            finding_add high "Weak ECDSA key ($key_size bit) on $domain"
        else
            echo -e "  ${GREEN}[OK] ECDSA $key_size bit — ممتاز${NC}"
        fi
    fi
fi

# Signature Algorithm
sig_algo=$(echo "$cert_raw" | openssl x509 -noout -text 2>/dev/null | \
    grep "Signature Algorithm:" | head -1 | sed 's/.*: //')
echo -e "  Signature: ${BOLD}$sig_algo${NC}"

if echo "$sig_algo" | grep -qi "sha1\|md5"; then
    echo -e "  ${RED}[HIGH] خوارزمية التوقيع ضعيفة: $sig_algo${NC}"
    finding_add high "Weak signature algorithm ($sig_algo) on $domain"
fi

# ─── 5. فحص Protocol و Cipher ────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ فحص البروتوكولات ━━${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

# فحص SSL 2.0 / 3.0 (يجب أن يكون معطّل)
for proto in ssl2 ssl3; do
    result=$(echo | timeout 5 openssl s_client -connect "$domain:$port" \
        -"$proto" 2>&1)
    if echo "$result" | grep -q "BEGIN CERTIFICATE\|Cipher is"; then
        proto_upper=$(echo "$proto" | tr 'a-z' 'A-Z' | sed 's/SSL/SSLv/')
        echo -e "  ${RED}[CRITICAL] $proto_upper مُفعّل — ثغرة POODLE/DROWN!${NC}"
        finding_add critical "$proto_upper enabled on $domain — vulnerable to POODLE/DROWN"
    else
        echo -e "  ${GREEN}[✓] $proto معطّل ✅${NC}"
    fi
done

# فحص TLS 1.0 / 1.1 (يجب أن يكون معطّل)
for proto in tls1 tls1_1; do
    result=$(echo | timeout 5 openssl s_client -connect "$domain:$port" \
        -"$proto" 2>&1)
    pretty=$(echo "$proto" | sed 's/tls1$/TLSv1.0/; s/tls1_1/TLSv1.1/')
    if echo "$result" | grep -q "BEGIN CERTIFICATE\|Cipher is"; then
        echo -e "  ${ORANGE}[HIGH] $pretty مُفعّل — قديم وغير آمن${NC}"
        finding_add high "$pretty still enabled on $domain — should be disabled"
    else
        echo -e "  ${GREEN}[✓] $pretty معطّل ✅${NC}"
    fi
done

# فحص TLS 1.2 / 1.3
for proto in tls1_2 tls1_3; do
    result=$(echo | timeout 5 openssl s_client -connect "$domain:$port" \
        -"$proto" 2>&1)
    pretty=$(echo "$proto" | sed 's/tls1_2/TLSv1.2/; s/tls1_3/TLSv1.3/')
    if echo "$result" | grep -q "BEGIN CERTIFICATE\|Cipher is"; then
        cipher=$(echo "$result" | grep "Cipher is" | sed 's/.*Cipher is //')
        echo -e "  ${GREEN}[✓] $pretty مدعوم — Cipher: $cipher${NC}"
    else
        echo -e "  ${YELLOW}[?] $pretty غير مدعوم${NC}"
    fi
done

# ─── 6. Certificate Chain ────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ سلسلة الشهادات (Certificate Chain) ━━${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

chain=$(echo "$cert_raw" | grep -E "^\s*[0-9]+ s:" | head -5)
if [ -n "$chain" ]; then
    echo "$chain" | while IFS= read -r cl; do
        echo -e "  ${CYAN}$cl${NC}"
    done
else
    echo -e "  ${GREY}(غير متوفر)${NC}"
fi

verify=$(echo "$cert_raw" | grep "Verify return code:")
if [ -n "$verify" ]; then
    if echo "$verify" | grep -q "0 (ok)"; then
        echo -e "  ${GREEN}[✓] $verify${NC}"
    else
        echo -e "  ${RED}[!] $verify${NC}"
        finding_add high "Certificate chain verification failed: $verify"
    fi
fi

# ─── 7. ملخص ────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "SSL/TLS Certificate Audit — $(date)
Target: $domain:$port

$REPORT

=== Key Info ===
Algorithm: $key_algo
Key Size: ${key_size:-?} bit
Signature: $sig_algo

=== Verification ===
$verify" "ssl_cert_check_${domain}.txt" "$TOOL_TITLE"
