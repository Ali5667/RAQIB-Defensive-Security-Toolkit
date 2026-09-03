#!/bin/bash
# run_accuracy_eval.sh
# يقيس دقة الكاشفات الاستدلالية الثلاثة (webshell / cron / tmpexec) فعلياً،
# عبر تشغيل نفس دوال/أنماط الإنتاج الموجودة بـ tools/malware/malware_heuristics.sh
# على مجموعة اختبار مُصنَّفة يدوياً (benign/malicious) داخل tests/corpus/.
# يطبع Precision / Recall / F1 / Accuracy لكل كاشف ولمجموعهم.
#
# Measures the real accuracy of the three heuristic detectors by running the
# exact same production functions/patterns from
# tools/malware/malware_heuristics.sh against a manually labeled benign/
# malicious corpus in tests/corpus/. Prints Precision/Recall/F1/Accuracy per
# detector and overall. This is a static/local test — it does not touch the
# live filesystem outside tests/corpus/.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CORPUS_DIR="$SCRIPT_DIR/corpus"

# أرشيفات zip/git لا تحفظ بت setuid بشكل موثوق عند الفك — نعيد ضبطه هنا لعينة
# الاختبار setuid_shell قبل التشغيل، وإلا كاشف SUID/SGID ما راح يُختبر فعلياً.
# zip/git archives don't reliably preserve the setuid bit on extraction — we
# restore it here for the setuid_shell fixture before running, otherwise the
# SUID/SGID signal never actually gets exercised by this test.
if [ -f "$CORPUS_DIR/tmpexec/malicious/setuid_shell" ]; then
    chmod 4755 "$CORPUS_DIR/tmpexec/malicious/setuid_shell" 2>/dev/null
fi

# shellcheck source=../tools/malware/malware_heuristics.sh
source "$ROOT_DIR/modules/common.sh" 2>/dev/null
source "$ROOT_DIR/tools/malware/malware_heuristics.sh"

TOTAL_TP=0 TOTAL_FP=0 TOTAL_TN=0 TOTAL_FN=0

report_detector() {
    local name="$1" tp="$2" fp="$3" tn="$4" fn="$5"
    local total=$((tp + fp + tn + fn))
    local precision="n/a" recall="n/a" f1="n/a" acc="n/a"
    if [ "$((tp + fp))" -gt 0 ]; then
        precision=$(awk -v t="$tp" -v f="$fp" 'BEGIN{printf "%.1f", (t/(t+f))*100}')
    fi
    if [ "$((tp + fn))" -gt 0 ]; then
        recall=$(awk -v t="$tp" -v f="$fn" 'BEGIN{printf "%.1f", (t/(t+f))*100}')
    fi
    if [ "$total" -gt 0 ]; then
        acc=$(awk -v t="$tp" -v n="$tn" -v tot="$total" 'BEGIN{printf "%.1f", ((t+n)/tot)*100}')
    fi
    if [ "$precision" != "n/a" ] && [ "$recall" != "n/a" ]; then
        f1=$(awk -v p="$precision" -v r="$recall" 'BEGIN{ if ((p+r)>0) printf "%.1f", 2*p*r/(p+r); else printf "0.0" }')
    fi
    echo ""
    echo "== $name =="
    echo "  TP=$tp  FP=$fp  TN=$tn  FN=$fn  (total=$total)"
    echo "  Precision=${precision}%  Recall=${recall}%  F1=${f1}  Accuracy=${acc}%"
}

echo "RAQIB heuristic detector accuracy evaluation"
echo "=============================================="

# ---------------------------------------------------------------------------
# Webshell detector
# ---------------------------------------------------------------------------
ws_tp=0; ws_fp=0; ws_tn=0; ws_fn=0
for f in "$CORPUS_DIR"/webshell/malicious/*; do
    [ -f "$f" ] || continue
    if raqib_is_webshell_hit "$f"; then ws_tp=$((ws_tp+1)); else ws_fn=$((ws_fn+1)); echo "  [FN][webshell] $f"; fi
done
for f in "$CORPUS_DIR"/webshell/benign/*; do
    [ -f "$f" ] || continue
    if raqib_is_webshell_hit "$f"; then ws_fp=$((ws_fp+1)); echo "  [FP][webshell] $f"; else ws_tn=$((ws_tn+1)); fi
done
report_detector "Web Shell Detector" "$ws_tp" "$ws_fp" "$ws_tn" "$ws_fn"

# ---------------------------------------------------------------------------
# YARA-lite content rule engine (obfuscation-resistant layer, same webshell corpus)
# ---------------------------------------------------------------------------
yl_tp=0; yl_fp=0; yl_tn=0; yl_fn=0
for f in "$CORPUS_DIR"/webshell/malicious/*; do
    [ -f "$f" ] || continue
    result="$(raqib_yara_lite_scan "$f")"; score="${result%%|*}"
    if [ "$score" -ge "$RAQIB_YARA_LITE_THRESHOLD" ]; then yl_tp=$((yl_tp+1)); else yl_fn=$((yl_fn+1)); echo "  [FN][yara-lite] $f (score=$score)"; fi
done
for f in "$CORPUS_DIR"/webshell/benign/*; do
    [ -f "$f" ] || continue
    result="$(raqib_yara_lite_scan "$f")"; score="${result%%|*}"
    if [ "$score" -ge "$RAQIB_YARA_LITE_THRESHOLD" ]; then yl_fp=$((yl_fp+1)); echo "  [FP][yara-lite] $f (score=$score, rules=${result#*|})"; else yl_tn=$((yl_tn+1)); fi
done
report_detector "YARA-lite Content Rule Engine" "$yl_tp" "$yl_fp" "$yl_tn" "$yl_fn"

# ---------------------------------------------------------------------------
# Combined webshell verdict: classic pattern OR yara-lite (either one flags = flag)
# This is the logic auto_malware_cleaner.sh actually uses in practice, and it
# is what feeds the OVERALL totals below (not the classic-only row above),
# since that's the real detection surface a user sees.
# ---------------------------------------------------------------------------
cb_tp=0; cb_fp=0; cb_tn=0; cb_fn=0
for f in "$CORPUS_DIR"/webshell/malicious/*; do
    [ -f "$f" ] || continue
    result="$(raqib_yara_lite_scan "$f")"; score="${result%%|*}"
    hit=1
    raqib_is_webshell_hit "$f" && hit=0
    [ "$score" -ge "$RAQIB_YARA_LITE_THRESHOLD" ] && hit=0
    if [ "$hit" -eq 0 ]; then cb_tp=$((cb_tp+1)); else cb_fn=$((cb_fn+1)); echo "  [FN][combined] $f"; fi
done
for f in "$CORPUS_DIR"/webshell/benign/*; do
    [ -f "$f" ] || continue
    result="$(raqib_yara_lite_scan "$f")"; score="${result%%|*}"
    hit=1
    raqib_is_webshell_hit "$f" && hit=0
    [ "$score" -ge "$RAQIB_YARA_LITE_THRESHOLD" ] && hit=0
    if [ "$hit" -eq 0 ]; then cb_fp=$((cb_fp+1)); echo "  [FP][combined] $f"; else cb_tn=$((cb_tn+1)); fi
done
report_detector "Combined Web Shell Verdict (classic OR yara-lite)" "$cb_tp" "$cb_fp" "$cb_tn" "$cb_fn"
TOTAL_TP=$((TOTAL_TP+cb_tp)); TOTAL_FP=$((TOTAL_FP+cb_fp)); TOTAL_TN=$((TOTAL_TN+cb_tn)); TOTAL_FN=$((TOTAL_FN+cb_fn))

# ---------------------------------------------------------------------------
# Cron detector
# ---------------------------------------------------------------------------
cr_tp=0; cr_fp=0; cr_tn=0; cr_fn=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    if raqib_is_cron_hit "$line"; then cr_tp=$((cr_tp+1)); else cr_fn=$((cr_fn+1)); echo "  [FN][cron] $line"; fi
done < "$CORPUS_DIR/cron/malicious/lines.txt"
while IFS= read -r line; do
    [ -z "$line" ] && continue
    if raqib_is_cron_hit "$line"; then cr_fp=$((cr_fp+1)); echo "  [FP][cron] $line"; else cr_tn=$((cr_tn+1)); fi
done < "$CORPUS_DIR/cron/benign/lines.txt"
report_detector "Cron Detector" "$cr_tp" "$cr_fp" "$cr_tn" "$cr_fn"
TOTAL_TP=$((TOTAL_TP+cr_tp)); TOTAL_FP=$((TOTAL_FP+cr_fp)); TOTAL_TN=$((TOTAL_TN+cr_tn)); TOTAL_FN=$((TOTAL_FN+cr_fn))

# ---------------------------------------------------------------------------
# /tmp executable scoring detector
# ---------------------------------------------------------------------------
tm_tp=0; tm_fp=0; tm_tn=0; tm_fn=0
for f in "$CORPUS_DIR"/tmpexec/malicious/*; do
    [ -f "$f" ] || continue
    result="$(raqib_score_tmpexec_file "$f")"
    score="${result%%|*}"
    if [ "$score" -ge "$RAQIB_TMPEXEC_QUARANTINE_THRESHOLD" ]; then
        tm_tp=$((tm_tp+1))
    else
        tm_fn=$((tm_fn+1)); echo "  [FN][tmpexec] $f (score=$score, signals=${result#*|})"
    fi
done
for f in "$CORPUS_DIR"/tmpexec/benign/*; do
    [ -f "$f" ] || continue
    result="$(raqib_score_tmpexec_file "$f")"
    score="${result%%|*}"
    if [ "$score" -ge "$RAQIB_TMPEXEC_QUARANTINE_THRESHOLD" ]; then
        tm_fp=$((tm_fp+1)); echo "  [FP][tmpexec] $f (score=$score, signals=${result#*|})"
    else
        tm_tn=$((tm_tn+1))
    fi
done
report_detector "/tmp Executable Scorer" "$tm_tp" "$tm_fp" "$tm_tn" "$tm_fn"
TOTAL_TP=$((TOTAL_TP+tm_tp)); TOTAL_FP=$((TOTAL_FP+tm_fp)); TOTAL_TN=$((TOTAL_TN+tm_tn)); TOTAL_FN=$((TOTAL_FN+tm_fn))

# ---------------------------------------------------------------------------
# Overall
# ---------------------------------------------------------------------------
report_detector "OVERALL (all three detectors combined)" "$TOTAL_TP" "$TOTAL_FP" "$TOTAL_TN" "$TOTAL_FN"
echo ""
echo "Note: this measures accuracy against this repo's own labeled test"
echo "corpus (tests/corpus/) — a convenience benchmark for regression-testing"
echo "changes to the heuristics, not a universal ground truth. A determined"
echo "attacker can still evade static pattern/signal detection; this harness"
echo "does not claim otherwise."
