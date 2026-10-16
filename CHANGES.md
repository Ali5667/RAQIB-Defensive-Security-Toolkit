# RAQIB v2 — Patches from testing session

هذه نسخ معدّلة فقط من الملفات التالية (باقي المشروع كما هو، لم يتغيّر).
انسخها إلى نفس المسارات داخل raqib2/ لتطبيق الإصلاحات.

## 1) tools/monitoring/dns_lookup_tool.sh — إصلاح أمني (حقن كود)
المسار الاحتياطي (fallback) لاستعلام DNS التقدمي (لما `getent` غير موجود) كان
يمرر مدخلات المستخدم مباشرة داخل نص بايثون (`python3 -c "...('$domain')..."`)،
مما يسمح بحقن كود بايثون تعسفي عبر اسم نطاق مصمم خصيصاً. تم تأكيد الاستغلال
عملياً أثناء الاختبار. الإصلاح: تمرير القيمة عبر `sys.argv` بدل التضمين
المباشر بالنص.

## 2) tools/monitoring/ping_sweep.sh — إصلاح تحقق
كان يتحقق من صيغة الشبكة الفرعية بعدد الأرقام فقط (1-3 خانات) بدون التحقق
من أن كل octet بين 0-255، فيقبل قيم مثل "999.999.999". أضفنا فحص مدى لكل
octet بعد فحص الصيغة.

## 3) tools/monitoring/arp_watch.sh — إصلاح إنذار كاذب
المقارنة بين النسخة الأساسية (baseline) والحالة الحالية كانت تستخدم `echo`
لطباعة القيمة الحالية، و`echo` يضيف سطر جديد حتى لو كانت القيمة فارغة، بينما
ملف baseline فارغ فعلاً (0 بايت) لو جدول ARP فارغ — هذا التفاوت كان يسبب
إنذار "تم رصد تغييرات (ARP Spoofing)" كاذب حتى لو ما تغير شي. تم تطبيع طرفي
المقارنة بنفس الطريقة (`printf '%s'` على الطرفين) لإزالة هذا التفاوت.

## 4) tests/run_accuracy_eval.sh + modules/common.sh + tools/malware/malware_heuristics.sh + tools/malware/rules_updater.sh — إصلاح سكربت القياس
`run_accuracy_eval.sh` كان يسوّر `malware_heuristics.sh` مباشرة بدون تسوير
`modules/common.sh` أولاً، فتفشل دالة `raqib_pcre_ok` (غير معرّفة) وتُعطَّل
طبقة "YARA-lite" بصمت بكل تشغيل — هذا كان ينزّل الاسترجاع (Recall) الظاهري
لكاشف الويب شيل من 100% إلى 57.9% رغم أن الكود الفعلي بالإنتاج
(auto_malware_cleaner.sh) سليم تماماً وغير متأثر. بعد تسوير common.sh، ظهر
خلل إضافي: `_RAQIB_PCRE_CHECKED`/`_RAQIB_PCRE_WARNED` غير مهيّأة، وبسبب
`set -u` بسكربت القياس تنكسر العملية. تم إصلاح الاثنين باستخدام
`${VAR:-}` الآمن بدل `$VAR` المباشر.

**النتيجة بعد الإصلاح:** الاسترجاع (Recall) الإجمالي للكاشفات الثلاثة ارتفع
من 72.7% (F1=84.2) إلى 97.0% (F1=98.5) — أي أن الأداة الحقيقية أدق بكثير
مما كان سكربت القياس (المعطوب) يطبعه.

## 5) tools/vuln_scan/ssl_cert_checker.sh — إصلاح أمني (حقن أوامر)
كان يمرر `$domain`/`$port` مباشرة داخل نص `bash -c "..."` بعلامات اقتباس
مفردة بدون أي تحقق من الصيغة — أخطر من ثغرة dns_lookup_tool.sh لأنها
تعمل دائماً (مو مشروطة بغياب أداة معينة). تم تأكيد الاستغلال عملياً. الإصلاح:
تمرير `$domain`/`$port` كـ argv منفصلة لـ `bash -c 'script' _ "$domain" "$port"`
بدل تضمينها بالنص.

## 6) ميزة جديدة: التحقق من التحديثات (raqib.sh + modules/lang.sh + update_source.txt)
أضفنا خيار جديد بالقائمة الرئيسية (11) للتحقق من وجود إصدار أحدث من RAQIB.
نفس فلسفة الأمان المتّبعة بـ rules_updater.sh بالضبط:
- معطّلة افتراضياً (enabled=0) بملف `update_source.txt` بجذر المشروع — لازم
  المستخدم يحطها على رابط يتحكم فيه هو (مستودعه الخاص مثلاً) ويفعّلها بنفسه.
- الفحص يقارن رقم الإصدار بس (لا يوجد تنزيل أو تنفيذ تلقائي لأي كود من
  الإنترنت — يعرض رابط للمستخدم يفتحه يدوياً لو فيه تحديث).
- ما يقترح "تراجع" (downgrade) لو الرقم البعيد أقدم من المثبّت.
- اختُبرت الحالات الأربع (معطّل، إصدار أحدث متوفر، نفس الإصدار، إصدار أقدم)
  + حالة فشل الاتصال، كلها تعمل صح.

## 7) v2.1 — توسيع اللغات إلى 20 + ميزات جديدة (raqib.sh + modules/lang.sh + modules/common.sh + modules/auto_translate.sh + assets/eagle_cry.wav + VERSION + update_source.txt)
- **20 لغة مكتملة 100%** (505 نص لكل وحدة): أضفنا الأوردو، البرتغالية، الإندونيسية،
  الإيطالية، اليابانية، الهندية، الهولندية، الكورية، الأوكرانية، والبولندية فوق
  العشرة الأصليين (عربي، إنجليزي، فرنسي، إسباني، ألماني، تركي، فارسي، روسي، كردي، صيني).
- **ملف جديد `modules/auto_translate.sh`**: ترجمة آلية حية اختيارية عبر LibreTranslate
  لأي نص ناقص مستقبلاً بأي لغة، مع حفظ النتيجة بكاش محلي (`modules/lang_cache/`) عشان
  ما تحتاج تترجم مرتين.
- **`save_report()` بملف `modules/common.sh`**: صارت تسأل عن مسار حفظ مخصص (تنشئ
  المجلد تلقائياً لو مو موجود) بدل الاعتماد الدائم على المجلد الحالي.
- **صوت نسر حقيقي عند التشغيل** (`assets/eagle_cry.wav`)، يشتغل عبر
  `paplay`/`aplay`/`ffplay` مع مقدمة النسر بالـ ASCII.
- **التقويم الهجري جنب الميلادي** بالبانر، بدالة `raqib_hijri_date()` جديدة بـ
  `raqib.sh` — تحويل جدول يوليوسي قياسي محلي بدون أي اعتماد على إنترنت.
- **فاحص تحديث ذاتي مفعّل**: `VERSION` ارتفع لـ 2.1 مع رابط مستودع GitHub الفعلي،
  و`update_source.txt` مربوط ومفعّل (`enabled=1`) على نفس المستودع.
- **إصلاح خلل ترميز حرج**: دالة `type_line()` بـ `raqib.sh` كانت تقص النص حرف
  حرف بدون فرض UTF-8، فتخرّب الأحرف متعددة البايتات (عربي، فارسي، روسي، صيني...)
  على أنظمة ما عندها UTF-8 locale مضبوط بالبيئة — تم فرض `LC_ALL=C.UTF-8` (أو
  `en_US.UTF-8` كبديل) تلقائياً ببداية السكربت.
- **ملفات مشروع جديدة**: `LICENSE` (MIT)، `SECURITY.md`، `CONTRIBUTING.md`،
  و`README.md`/`README.ar.md` بشكل احترافي منسّق لـGitHub (badges، طي أقسام
  الأدوات، جدول "ليش RAQIB مختلف").
# RAQIB v2 — Patches from testing session

هذه نسخ معدّلة فقط من الملفات التالية (باقي المشروع كما هو، لم يتغيّر).
انسخها إلى نفس المسارات داخل raqib2/ لتطبيق الإصلاحات.

## 1) tools/monitoring/dns_lookup_tool.sh — إصلاح أمني (حقن كود)
المسار الاحتياطي (fallback) لاستعلام DNS التقدمي (لما `getent` غير موجود) كان
يمرر مدخلات المستخدم مباشرة داخل نص بايثون (`python3 -c "...('$domain')..."`)،
مما يسمح بحقن كود بايثون تعسفي عبر اسم نطاق مصمم خصيصاً. تم تأكيد الاستغلال
عملياً أثناء الاختبار. الإصلاح: تمرير القيمة عبر `sys.argv` بدل التضمين
المباشر بالنص.

## 2) tools/monitoring/ping_sweep.sh — إصلاح تحقق
كان يتحقق من صيغة الشبكة الفرعية بعدد الأرقام فقط (1-3 خانات) بدون التحقق
من أن كل octet بين 0-255، فيقبل قيم مثل "999.999.999". أضفنا فحص مدى لكل
octet بعد فحص الصيغة.

## 3) tools/monitoring/arp_watch.sh — إصلاح إنذار كاذب
المقارنة بين النسخة الأساسية (baseline) والحالة الحالية كانت تستخدم `echo`
لطباعة القيمة الحالية، و`echo` يضيف سطر جديد حتى لو كانت القيمة فارغة، بينما
ملف baseline فارغ فعلاً (0 بايت) لو جدول ARP فارغ — هذا التفاوت كان يسبب
إنذار "تم رصد تغييرات (ARP Spoofing)" كاذب حتى لو ما تغير شي. تم تطبيع طرفي
المقارنة بنفس الطريقة (`printf '%s'` على الطرفين) لإزالة هذا التفاوت.

## 4) tests/run_accuracy_eval.sh + modules/common.sh + tools/malware/malware_heuristics.sh + tools/malware/rules_updater.sh — إصلاح سكربت القياس
`run_accuracy_eval.sh` كان يسوّر `malware_heuristics.sh` مباشرة بدون تسوير
`modules/common.sh` أولاً، فتفشل دالة `raqib_pcre_ok` (غير معرّفة) وتُعطَّل
طبقة "YARA-lite" بصمت بكل تشغيل — هذا كان ينزّل الاسترجاع (Recall) الظاهري
لكاشف الويب شيل من 100% إلى 57.9% رغم أن الكود الفعلي بالإنتاج
(auto_malware_cleaner.sh) سليم تماماً وغير متأثر. بعد تسوير common.sh، ظهر
خلل إضافي: `_RAQIB_PCRE_CHECKED`/`_RAQIB_PCRE_WARNED` غير مهيّأة، وبسبب
`set -u` بسكربت القياس تنكسر العملية. تم إصلاح الاثنين باستخدام
`${VAR:-}` الآمن بدل `$VAR` المباشر.

**النتيجة بعد الإصلاح:** الاسترجاع (Recall) الإجمالي للكاشفات الثلاثة ارتفع
من 72.7% (F1=84.2) إلى 97.0% (F1=98.5) — أي أن الأداة الحقيقية أدق بكثير
مما كان سكربت القياس (المعطوب) يطبعه.

## 5) tools/vuln_scan/ssl_cert_checker.sh — إصلاح أمني (حقن أوامر)
كان يمرر `$domain`/`$port` مباشرة داخل نص `bash -c "..."` بعلامات اقتباس
مفردة بدون أي تحقق من الصيغة — أخطر من ثغرة dns_lookup_tool.sh لأنها
تعمل دائماً (مو مشروطة بغياب أداة معينة). تم تأكيد الاستغلال عملياً. الإصلاح:
تمرير `$domain`/`$port` كـ argv منفصلة لـ `bash -c 'script' _ "$domain" "$port"`
بدل تضمينها بالنص.

## 6) ميزة جديدة: التحقق من التحديثات (raqib.sh + modules/lang.sh + update_source.txt)
أضفنا خيار جديد بالقائمة الرئيسية (11) للتحقق من وجود إصدار أحدث من RAQIB.
نفس فلسفة الأمان المتّبعة بـ rules_updater.sh بالضبط:
- معطّلة افتراضياً (enabled=0) بملف `update_source.txt` بجذر المشروع — لازم
  المستخدم يحطها على رابط يتحكم فيه هو (مستودعه الخاص مثلاً) ويفعّلها بنفسه.
- الفحص يقارن رقم الإصدار بس (لا يوجد تنزيل أو تنفيذ تلقائي لأي كود من
  الإنترنت — يعرض رابط للمستخدم يفتحه يدوياً لو فيه تحديث).
- ما يقترح "تراجع" (downgrade) لو الرقم البعيد أقدم من المثبّت.
- اختُبرت الحالات الأربع (معطّل، إصدار أحدث متوفر، نفس الإصدار، إصدار أقدم)
  + حالة فشل الاتصال، كلها تعمل صح.

## 6) New tools — Rootkit Detector + Email Header Analyzer (roadmap items 1 & 2)

### tools/malware/rootkit_detector.sh (+ rootkit_detector.md)
Read-only rootkit check (Bash, zero external dependencies):
- Hidden processes: every PID in /proc vs `ps -e` (plus ghost PIDs from ps itself,
  and /proc/<pid>/status unreadable as root = kernel-level hiding).
- Suspicious kernel modules: known LKM-rootkit name blocklist (diamorphine/reptile/
  suterusu...) + loaded modules with no .ko file on disk.
- ld.so.preload / LD_PRELOAD: the file, live variable, and persistent settings in
  /etc/environment and /etc/profile*.
- Package checksum verification (dpkg --verify / rpm -Va) — optional, clear message
  when the package manager is missing.
- NEW: eBPF checks (kprobe/tracepoint hooks via optional bpftool, pinned objects in
  /sys/fs/bpf, kernel.unprivileged_bpf_disabled) — a modern blind spot.
- CLI: --help, --json (NDJSON), exit codes 0/1/2; all findings go through finding_add
  (structured JSON event log + critical Telegram alert).

### tools/forensics/email_header_analyzer.py (+ email_header_analyzer.md)
Defensive phishing/spoofing email-header triage (Python stdlib only, no network, no DNS):
- SPF/DKIM/DMARC verdicts from Authentication-Results/Received-SPF as already
  evaluated by the receiving MTA.
- Received chain: missing/long chains, missing, unparseable or out-of-order
  timestamps, private-IP first hop.
- Identity mismatches: From vs Return-Path vs Reply-To (reply_to_mismatch is critical
  with free mailers), display-name spoofing, free-mailer sender.
- CLI: --help, --json, stdin (-), exit codes 0/1/2; events written to
  .raqib_events.jsonl using the exact raqib_emit_event schema.
- Tested against a fake phishing email (6 findings incl. critical dmarc_fail +
  reply_to_mismatch, exit 1), a clean email (exit 0), --help, missing file (exit 2).

README.md updated: Malware table (13), Forensics table (6), tool count 60.

## 7) Logic enhancement round — Rootkit Detector + Email Header Analyzer

### tools/malware/rootkit_detector.sh — new checks
- /proc/<pid>/exe anomaly scan (root): running_deleted_binary ("(deleted)" exe),
  memfd_execution (fileless, no disk artifact), executable_from_temp (/tmp, /dev/shm,
  /var/tmp binaries), empty_cmdline (wiped argv on a userland process).
- hidden_kernel_module: /sys/module/*/sections present but the module is filtered
  out of /proc/modules — module-hiding detection that lsmod cannot lie around
  (lsmod reads /proc/modules).
- unowned_preload_lib: dpkg -S / rpm -qf ownership check on every library listed in
  /etc/ld.so.preload — an unowned library is the rootkit's hook itself.
- hidden_temp_executable: executable dotfiles in /tmp, /dev/shm, /var/tmp.

### tools/forensics/email_header_analyzer.py — new checks
- Proper per-mechanism verdict parsing: spf fail(high)/softfail/permerror/temperror(medium),
  spf_missing/dkim_none/dmarc_none (low), pass verdicts now print as [+] lines.
- message_id_mismatch (medium): Message-ID domain vs From domain.
- date_received_skew (low): Date header vs last Received time, > 24h.
- forged_localhost_hop (medium): fake topmost Received claiming localhost origin.
- null_return_path (low): envelope <> with normal content.
- social_engineering_subject (low): >= 2 lure keywords in Subject.

Tests: fake phishing email now yields 9 findings (incl. critical dmarc_fail +
reply_to_mismatch) exit 1; clean email prints SPF/DKIM/DMARC pass, exit 0;
bash -n syntax OK for the rootkit script.

## 8) User-extensible resource lists (any file extension) — both new tools

No more editing code to add detection entries. Both tools now load detection
lists from plain-text resource files; ANY file extension works because the
file's NAME selects the list (lkm_modules.txt / lkm_modules.dat / lkm_modules
all extend the same list). Format: one entry per line, '#' = comment.
Entries MERGE with the built-in defaults (never replace) and deduplicate
case-insensitively. Built-ins remain as fallback so the tools still run with
no resource files at all.

- tools/malware/rootkit_detector.sh: resources/rootkit/lkm_modules.*
  (module blocklist), resources/rootkit/temp_scan_dirs.* (scan dirs);
  new --rules <file|dir> CLI option; rk_merge_list loader (Bash 4+ namerefs).
- tools/forensics/email_header_analyzer.py: resources/email/free_mailers.*,
  resources/email/lure_keywords.*; new --rules <file|dir> option;
  .py files in resource dirs are never touched (data only, nothing imported).
- Shipped starter files (with format comments): lkm_modules.txt,
  temp_scan_dirs.txt, free_mailers.txt, lure_keywords.txt.
- Bug fixed by the new tests: _ip_is_private passed bytes to socket.ntohl
  (crash on private-IP Received hops) — now int.from_bytes.
- Verified: --rules with .dat/.conf files loads entries (merge+dedup),
  regressions green (fake phish exit 1, clean email exit 0).

## 9) v2.2 — Complete i18n Suite, Dynamic Visual Effects & Cross-Platform Audio

### 1. Translation Engine & 100% i18n Coverage (modules/update_translations.py + modules/lang.sh + modules/auto_translate.sh)
- **Built `modules/update_translations.py`**: High-performance Python translation synchronization utility using Google Translate web endpoint:
  - Format placeholder preservation (`%s`, `%d`, `%1$s` masked into tokens `__VARn__` to prevent translator corruption).
  - Escaped characters validation and Bash syntax verification.
  - Generates atomic `.bak` backup before writing.
  - Supports `--status` (coverage report), `--lang <code>`, `--all`, `--cache-only`, and `--single-key`.
- **100.0% Translation Completion across all 20 Languages**:
  - Automatically translated 2,900 missing strings across Spanish, French, German, Turkish, Persian, Russian, Kurdish, Chinese, Urdu, Portuguese, Indonesian, Italian, Japanese, Hindi, Dutch, Korean, Ukrainian, and Polish.
  - Every single one of the 20 supported languages now has 100.0% coverage (667 keys each = 13,340 strings total).
- **Updated `modules/auto_translate.sh`**: Bridged live translation fallback into `update_translations.py`.

### 2. Modern Cyber Visual Indicators & Terminal UI (modules/common.sh)
- **`run_with_spinner`**:
  - Supports 5 customizable spinner styles: `braille` (default: ⠋⠙⠹...), `radar` (◐◓◑◒), `pulse` (▉▊▋▌...), `dots` (⣾⣽⣻...), and `arrows` (←↖↑↗...).
  - Live execution timer displaying elapsed time in tenths of a second (`1.4s`).
  - Persistent completion badges (`✔` in bold green upon success, `✘` in bold red upon error).
  - `--style=<name>` flag and `RAQIB_SPINNER_STYLE` environment variable configuration.
  - Clean signal handling (`SIGINT`, `SIGTERM`, `EXIT`) with cursor restoration (`\e[?25h`).
- **`draw_progress_bar`**:
  - Replaced rough full blocks with smooth 1/8th Unicode fractional sub-blocks (`▏▎▍▌▋▊▉█`).
  - Dynamic gradient transition (cyan during progress, bold green on 100% completion).
  - Zero subshell overhead with pure Bash arithmetic.
- **`draw_scan_line`**:
  - Single-line streaming status indicator with carriage return (`\r`) for in-place target updates.
- **`cyber_flicker`**:
  - Rapid hex cyber flicker animation for initialization and engine warmups.

### 3. Universal Cross-Platform Eagle Startup Sound (modules/common.sh + raqib.sh)
- **`raqib_play_sound`**:
  - Created a robust universal sound player supporting:
    - **macOS**: Native `afplay`
    - **Modern Linux**: PipeWire (`pw-play`), PulseAudio (`paplay`), ALSA (`aplay`), FFmpeg (`ffplay`)
    - **Windows / WSL / Git Bash**: PowerShell `System.Media.SoundPlayer` using Base64-encoded UTF-8 script execution to reliably handle usernames with single quotes (e.g. `Ali'`) without quoting errors.
    - **Python Fallback**: `winsound` on native Windows.
  - Dispatches playback in the background (`&`) with output suppression to avoid blocking or cluttering the terminal.

### 4. Accuracy & Robustness Verification
- Tested and verified under `set -u` strict mode (fixed unbound variables in `modules/common.sh` including `TOOLS_DIR` and `SCRIPT_DIR`).
- Verified all accuracy benchmarks in `tests/run_accuracy_eval.sh` (100% pass, Accuracy: 85.5%, Exit code: 0).
- Passed Bash syntax checks (`bash -n`) across all shell scripts.

### 5. Advanced Python Toolkit Updater & Integrity Manager (modules/raqib_updater.py)
- **Built `modules/raqib_updater.py`**: Zero-dependency automated update engine using Python stdlib:
  - **Remote Discovery**: Queries GitHub Releases API, commit logs, and raw mirrors (`update_source.txt`).
  - **Version Intelligence**: Performs semantic version comparisons and commit delta evaluations.
  - **Pre-Update Atomic Snapshots**: Automatically backs up project files into `.raqib_backups/` before any file write.
  - **Dual-Mode Updating**:
    - **Git Clone Mode**: Safely stashes local changes, fetches origin, fast-forwards updates, and restores executable permissions.
    - **Standalone / Tarball Mode**: Downloads latest archive, unpacks core files, and preserves local user configurations (`.raqib_lang`, `.raqib_telegram.conf`, `.raqib_events.jsonl`).
  - **Rollback System**: Instant recovery via `--rollback` flag.
  - **Post-Update Integrity Verification**: Validates syntax of Bash scripts (`bash -n`) and Python files (`py_compile`) before finalizing.
  - **Seamless Integration with `raqib.sh`**: Option 12 in the main menu now directly leverages `raqib_updater.py` when Python is available.


