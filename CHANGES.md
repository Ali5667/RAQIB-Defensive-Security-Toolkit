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

## 10) دعم ويندوز الأصلي + macOS — طبقة المنصات (Cross-Platform Layer)

> أحدث تغيير: RAQIB صار يعمل أصلياً على ويندوز (Git Bash / MSYS2) وعلى macOS،
> مع بقاء سلوك لينكس كما هو 100% (كل التغييرات مشروطة بغياب أمر أو اختلافه).
> عدد الأدوات: 96 → 97 (حزمة دفاع ويندوز).

### ملف جديد: `modules/platform.sh` — طبقة المنصات المركزية
- **كشف النظام**: `RAQIB_OS` = `linux | wsl | darwin | msys | cygwin | unknown`
  عبر `uname -s -r` + فحص `WSL_DISTRO_NAME` لتمييز WSL2.
- **اختبارات رخيصة**: `raqib_is_windows/_macos/_linux/_wsl` + `raqib_has_windows_bridge`
  — بدون أوامر خارجية.
- **جسر PowerShell**: `raqib_win_ps` ينفّذ سطر PowerShell بأمان مع
  `-NoProfile -NonInteractive -ExecutionPolicy Bypass` وترميز UTF-8، ويشتغل
  من Git Bash مباشرة ومن WSL2 عبر `powershell.exe`.
- **ترجمة فورية ثنائية اللغة**: `raqib_tr "عربي" "English"` تعيد النص حسب
  `LANG_CODE` — بدون إضافة مفاتيح لملفات الـ 20 لغة (نفس عرف المشروع).
- **حرس المنصة**: `raqib_linux_only` / `raqib_windows_only` يخرجان برسالة
  واضحة ثنائية اللغة بأماكن البدائل (حزمة دفاع ويندوز / WSL2 / أدوات macOS).
- **Shims شرطية** (تُعرَّف كدوال Bash فقط عندما الأمر الأصلي غائب، فلا يتغير
  أي سلوك على لينكس): `sha256sum`, `md5sum`, `tac`, `readlink -f`, `shred`,
  `timeout` (بنية perl بـ alarm)، `sed -i`، `stat -c`، و`ss` بمخرجات مطابقة
  لـ ss الحقيقي (من PowerShell على ويندوز، ومن `lsof` على macOS).

### أداة جديدة: `tools/hardening/windows_defense.sh` — حزمة دفاع ويندوز (97)
7 فحوص بالأدوات الأصلية لويندوز حصراً (PowerShell / Event Log / مجدول المهام / Defender):
1. **جدار الحماية**: `Get-NetFirewallProfile` بحالة الملفات الثلاثة + اكتشاف
   `inbound = ALLOW` (اكتشاف حرج).
2. **الاتصالات ↔ العملية**: `Get-NetTCPConnection` مربوطة بـ `Get-Process`
   مع رصد الاتصالات القائمة بعناوين خارج LAN لمراجعتها بذكاء التهديدات.
3. **فرز 4625**: تسجيلات الدخول الفاشلة لآخر 48 ساعة — ترتيب عناوين
   المهاجمين والحسابات المستهدفة، والحدود 20/100/500 → متوسط/عالي/حرج.
4. **استمرارية المهام المجدولة**: إجراءات تنفّذ من TEMP/مسارات مستخدم-قابلة
   للكتابة أو LOLBins (`-enc`, `mshta`, `regsvr32`, `.vbs`, `wscript`...).
5. **Defender**: حالة مضاد الفيروسات + الحماية اللحظية + عمر التوقيعات +
   آخر 10 تهديدات من `Get-MpThreatDetection`.
6. **Autoruns**: مفاتيح Run/RunOnce (5 خلايا) + مجلدات Startup + مسارات
   خدمات تلقائية (temp/AppData = مشبوه) مع سطر إجماليات دائماً بالتقرير.
7. **ملف hosts**: إدخالات DNS الثابتة (مشبوهة عند > 3 أسطر غير تعليقية).

كل الاكتشافات عبر `finding_add` الموحد (أحداث SIEM/تيليجرام) + تقرير
`windows_defense_scan.txt`. على لينكس/macOS تخرج الحزمة برسالة توضيحية
ثنائية اللغة بدل الانهيار.

### تحديث الأدوات الموجودة (السلوك على لينكس كما هو حرفياً)
- `persistence_scanner.sh`: فحص ويندوز أصلي (Run/RunOnce + Startup + مهام
  مجدولة + خدمات Auto) يُستدعى تلقائياً على ويندوز.
- `login_history_report.sh`: فرع ويندوز يقرأ معلومات Security.evtx (الحجم/
  آخر كتابة) ويعرض إرشاداً لسطر PowerShell الكامل للتحليل بـ `Get-WinEvent`.
- `firewall_status_checker.sh`: يعرض ملفات جدار ويندوز الثلاثة على ويندوز،
  وحالة PF على macOS، إضافة لمسارات لينكس الحالية.
- `outdated_packages_checker.sh`: فرع `winget upgrade` (فلتر عمود Available
  مصحح) على ويندوز؛ فرع `apk` أعيد после خطأ تعويض سابق حذفه.
- `ssh_config_auditor.sh`: يستهلاف `/c/ProgramData/ssh/sshd_config`
  الافتراضي على ويندوز مع ملاحظة أن فحوص المجموعات أقل تطبيقاً هناك.
- أدوات لينكس-حصراً تخرج بلوثيقة واضحة بدل الانهيار على ويندوز/macOS:
  `rootkit_detector` (LKM/eBPF/ld.so.preload)، `advanced_forensics`
  (/proc + auditd)، `service_lister` (systemd/SysV)،
  `password_policy_checker` (login.defs/PAM/shadow)، `cron_auditor`
  (النظام الأصلي على ويندوز هو Scheduled Tasks)، `permission_auditor` +
  `weak_permission_scanner` (دلالات يونكس؛ الصلاحيات على ويندوز عبر ACL).
- `tls_fingerprint_detector`: python3 → `_raqib_py` + رسالة tcpdump خاصة
  بكل نظام + إصلاح `finding_add` بالمنافذ المشبوهة.

### إصلاحات
- **shim `ss` (حرج)**: وسائط `awk -v` كانت توضع *بعد* نص البرنامج — الـ
  gawk يعتبرها أسماء ملفات، يفشل بصمت (stderr مقنّع بـ `2>/dev/null`) ويطبع
  الترويسة فقط. الحالة كانت تكسر الـ shim على ويندوز وماك. الصواب:
  `awk -F'|' -v FILTER=.. -v PFLAG=.. -v WANTU=.. 'PROG'` (قبل البرنامج).
- **`rootkit_detector.sh` bootstrap (حرج — يكسر الأداة حتى على لينكس)**:
  `declare -p finding_add` يرجع rc=1 للدوال؛ الصحيح `declare -F finding_add`.
- **shim `timeout` (بناء perl)**: `goto &main_exec` خارج sub خطأ فادح
  يؤخذ بـ `eval` فينفذ الأمر *بدون* timeout أصلاً. أُعيدت كتابته بـ
  `$SIG{ALRM} = sub { exit 124 }; alarm($secs) if $secs > 0; exec @ARGV`.
- **`raqib.bat`**: أُعيد كتابته نظيفاً (النسخة السابقة تحتوي مخلفات ترجمة
  آلية بينها كلمات صينية وجمل مكسّرة) مع خطوات WSL2 صحيحة ومنطق خروج مبسّط.

### التحقق (على آلة ويندوز حقيقية بمحتوى Git Bash)
- 23 ملفاً معدّلاً كلها مرت بـ `bash -n` بلا أخطاء.
- تشغيل حقيقي: جسر PowerShell (`1+2` → 3)، `Get-NetFirewallProfile`
  (3 ملفات شخصية [OK])، `Get-NetTCPConnection` (121 صفاً)، `ss -tulnp` /
  `-tn state established` / `-tunap state established` بمخرجات مطابقة
  للـ ss الحقيقي `users:(("name",pid=N,fd=1))`، `timeout 1 sleep 3` → rc=124.
- تحقق الأدوات فعلياً: `windows_defense` (قائمة 1→6→0 + حفظ تقرير)،
  `login_history_report` (قراءة Security.evtx بحجم 20.9MB)،
  `persistence_scanner` (رصد LM Studio/Edge/CleanupTemporaryState)،
  `firewall_status_checker`، `outdated_packages_checker` (winget)، وكل
  الأدوات المحروسة خرجت بلوثيقتها.

---

## 11) جولة الدقة والقوائم — 2026-10-31

### إصلاح جوهري: طبقة PCRE محمولة
- GNU grep 3.0 على Git Bash يرفض `grep -P` بدون لوكيل UTF-8 صالح، فكان محرك
  YARA-lite يُتخطّى بصمت وتهبط دقة Web Shell المدمجة إلى 76.5%.
- `modules/common.sh`: `raqib_pcre_probe` يجرّب `grep -P` كما هو، ثم
  `LC_ALL=C.UTF-8 / C.utf8 / en_US.UTF-8 / en_US.utf8`، ثم Perl (`-0777`)،
  ويخزّن النتيجة بـ `_RAQIB_PCRE_MODE` (grep / grep:<locale> / perl / none).
- `raqib_pcre_match` و`raqib_pcre_valid`: واجهة موحّدة — 0 تطابق/صالح،
  1 لا تطابق/غير صالح، 2 خطأ. كلاهما يستخدم الملف ككتلة واحدة (multiline).
- `malware_heuristics.sh` و`rules_updater.sh` يستخدمان الطبقة بدل
  `grep -Pzo` المباشر. على لينكس ينجح `grep -P` أول مرة → صفر تغيير سلوكي.

### إصلاح بايثون على Git Bash
- `_raqib_py` يفحص التشغيل الفعلي لا وجود الاسم فقط (python3 في Git Bash هو
  Windows Store stub فاشل)، ويكشف `py -3`، ويخزّن النتيجة السالبة.
- shim `python3` يُعرَّف فقط إذا فشل التنفيذ الحقيقي؛ على لينكس/ماك لا يُعرَّف.
- `run_tool` يدعم أدوات `.py` (وتمرير الوسائط) بدل `source` الذي يفشل مع
  بايثون، و`credential_leak_checker.sh` صار يستخدم `_raqib_py`.

### توازن القوائم (أعداد فعلية)
- الملفات المشبوهة: + `rootkit_detector` → 13.
- التحقيقات: + `advanced_forensics` + `email_header_analyzer` → 7 (مع سؤال
  عن مسار ملف البريد قبل التشغيل).
- الثغرات: + `credential_leak_checker` → 6.
- التحصين: العدد الصحيح 9 (كان معنوناً 8).
- CTF: إضافة `cipher_solver.py` و`http_request_builder.py` → 23 أداة.
- القائمة الرئيسية و`README.md` / `README.ar.md` حُدّثت بالأعداد نفسها.

### قاعدة كشف جديدة
- `NESTED_DECODE_INTO_EXEC|3` تلتقط `eval(gzinflate(base64_decode(...)))`
  والتفكيك المتداخل المشابه (gzinflate/gzuncompress/str_rot13/convert_uudecode).

### نتائج القياس الفعلية (Git Bash على ويندوز)
| الكاشف | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|
| Web Shell — كلاسيكي فقط | 100.0% | 52.9% | 69.2 | 76.5% |
| Web Shell — YARA-lite فقط | 100.0% | 100.0% | 100.0 | 100.0% |
| Web Shell — المدمج | 100.0% | 100.0% | 100.0 | 100.0% |
| Cron الخبيث | 100.0% | 100.0% | 100.0 | 100.0% |
| /tmp (ويندوز) | 100.0% | 60.0% | 75.0 | 81.8% |
| **الإجمالي** | **100.0%** | **93.5%** | **96.6** | **97.1%** |

- قبل الإصلاح: الإجمالي 85.5% دقة / 80.7 F1 (YARA-lite معطّل).
- `setuid_shell` لا يمكن اختباره على NTFS (بت setuid غير مدعوم)، و
  `static_dropper` ملف ELF ساكن بلا إشارات — الربط الساكن وحده لا يُحتسب عمداً.
- `bash -n`: 124 ملفاً، 0 أخطاء. اختبار اللغات: 20/20 سليمة.

---

## 12) شعار جديد ومؤثرات بصرية متعددة المستويات — 2026-11-01

### الشعار الجديد (`raqib.sh`)
- كلمة `RAQIB` مبنية حرفاً حرفاً، وكل حرف بلون مستقل:
  R سماوي، A أزرق فاتح، Q أزرق، I بنفسجي، B بنفسجي غامق.
- أشرطة بيانات جانبية `░▒▓█ … █▓▒░` تحيط بالاسم، وعرض ثابت 50 عموداً
  (كل الأسطر متساوية، بدون انكسار في الطرفيات الضيقة نسبياً).
- خط مسح رأسي: صف إضاءة أبيض يتحرك فوق الحروف (strong/cinematic).
- بديل ASCII كامل عند غياب UTF-8، وسطر توقيع:
  `◢◤ رقيب · RAQIB · أداة أمن دفاعي ◥◣ v2.2`.

### محرك المؤثرات (`modules/common.sh`)
- `raqib_fx_ok` + `raqib_fx_level_cache` + `raqib_fx_level`:
  المستويات `light` / `strong` (افتراضي) / `cinematic`، مع تخزين النتيجة
  بدون subshell (مهم على Git Bash).
- `fx_status_line`: رادار متحرك `▰▰▰▱▱` في strong/cinematic، ونبضة بسيطة في light.
- `fx_tool_launch`: وميض تحميل بعدد لقطات يتبع المستوى.
- `fx_matrix_rain`: مطر Matrix خفيف (cinematic فقط).
- `fx_glitch_line`: سطر Glitch قصير لتسلسل الإقلاع (cinematic).
- `raqib_clear`: تنظيف الشاشة بتسلسل ANSI مدمج بدل spawn لأمر `clear`.
- بديل ASCII تلقائي إذا كانت الطرفية لا تدعم UTF-8، وتوافق كامل مع Bash 3.2.

### نقاط الربط
- `raqib.sh`: `raqib_logo_animated` للشعار، `raqib_boot_sequence` بعد شعار
  النسر، سطر الحالة أسفل البنر، خط مسح عند كل `show_banner`، وقوائم
  القائمة الرئيسية تظهر على دفعات.
- `modules/common.sh`: `show_tool_list` متحرك، و`run_tool` يعرض وميض التحميل.
- `show_eagle_intro` يتجاوز الأنترو بالكامل عند إطفاء المؤثرات/التشغيل غير التفاعلي.

### تحسين الاستجابة على Git Bash
- كل spawn لأمر خارجي يكلّف ~80–140ms، فتم تقليل النبضات وتجميعها.
- البانر: كاش تواريخ اليوم/اللغة، `printf %(...)T` بدل `date`، و`${path##*/}`
  بدل `basename`، وتنظيف شاشة مدمج — الرجوع المتكرر للقائمة صار أسرع بوضوح.
- قياس فعلي: `off` ~0.29s، `light` ~0.52s، `strong` ~0.74s، `cinematic` ~1.25s
  لرسم البانر على Git Bash (strong يضيف ~0.45s فقط عن off).

### الأمان والاختبارات
- لا تأثير على المخرجات الموجّهة: الاختبارات والأنابيب تبقى فورية ونظيفة.
- `bash -n` واختبارات الدقة/اللغات أُعيد تشغيلها بعد الإضافة — كلها سليمة.

### لقطات الشاشة
- `assets/raqib_strong.png` و`assets/raqib_cinematic.png`: لقطتان للشكل النهائي
  للبانر في الوضعين، مضمّنتان في `README.md` و`README.ar.md`.

## 13) مزامنة نصوص المنصات مع الـ20 لغة — 2026-11-01

### المشكلة
- نصوص دعم ويندوز/ماك الجديدة كانت تمرّ عبر `raqib_tr` الثنائية (عربي/إنجليزي)،
  فعند اختيار كوري أو ياباني أو أي لغة أخرى تظهر تلك العبارات بالإنجليزية
  وسط واجهة مترجمة بالكامل — 18 عبارة شاذة.

### الحل
- إضافة 18 مفتاحاً جديداً ببادئة `pt_` إلى **كل** ملفات اللغات الـ20
  (`modules/languages/*.sh`): رسائل الخطأ، عناوين الأدوات الجديدة، ورسائل
  المنصات (Linux-only / Windows-only / macOS / WSL2 / Git for Windows).
- كل ملف صار **692 مفتاحاً** بدل 674 (20 × 692 = 13,840 نص)، ومجموعات
  المفاتيح متطابقة حرفياً بين اللغات العشرين.
- `raqib_tr` صارت تأخذ المفتاح: `raqib_tr pt_key "عربي احتياطي" "English fallback"`،
  وتقرأ من ملف اللغة النشِط، مع بقاء العربي/الإنجليزي احتياطاً فقط.
- المتغيّرات والرموز محفوظة: مسار الملف يُمرَّر عبر `{file}` (مثل `$eml` سابقاً)
  كي لا يتمدد داخل ملف الترجمة، والأسهم `→` والرموز `⚠️ 🪟 ➤` كما هي.

### الأداء
- `t` كانت تُشغّل `echo | tr` مع كل نص لتحويل رمز اللغة إلى أحرف كبيرة:
  ~95ms لكل استدعاء على Git Bash. صار الاسم يُحسب مرة واحدة عند تحميل اللغة
  ويُخزَّن في `_RAQIB_LANG_UPPER`، فانخفض إلى ~10ms.
- قياس: 10 استدعاءات لـ `t` بالكورية هبطت من **959ms** إلى **98ms**،
  و6 نداءات `raqib_tr` من **715ms** إلى **204ms**. العربية/الإنجليزية
  بلا أي استدعاء إضافي (مسار سريع).

### الاختبارات
- `tests/test_languages.sh`: 20/20 ملفاً سليماً.
- تساوي المفاتيح بين اللغات: 692/692 في العشرين.
- `bash -n` لكل الملفات المعدّلة + حزمة الدقة واللغات الكاملة.

## 14) واجهة موحّدة اللغة، بانر مُطار، ومؤثرات عمليات Matrix/Radar — 2026-11-02

### الهدف
- جعل تجربة ويندوز (Git Bash + WSL2) وماك بجودة لينكس: بانر أنظف، مؤثرات أقوى،
  وكل الأسماء/العناوين تتبع اللغة المختارة بدل خلط العربي/الإنجليزي.

### البانر (`raqib.sh`)
- إطار تاج/قاعدة بعرض 50 عموداً بالضبط مع معيّن مركزي وفاصل متدرّج،
  وبديل ASCII كامل عند غياب UTF-8.
- تسمية وسوم البانر (المنصة/التاريخ/الهجري/SIEM/المشغّل/المؤلف/آخر تحديث/
  الحالة/الوسم) من مفاتيح `lbl_*`، مع كاش لكل لغة.
- حذف صف «تاريخ الإنشاء» غير الضروري وتوحيد الفواصل إلى `|` في وضع ASCII.

### القائمة الرئيسية (`raqib.sh`)
- الأسماء الـ14 (`cat1`–`cat13` + `menu_exit`) تُقرأ من اللغة النشطة وتُخزَّن
  مرة واحدة لكل لغة؛ الوصف التقني الإنجليزي يبقى كبيانات رمادية بعد `┃`.
- رسالة الاختيار `[0-13]` صارت مترجمة (`menu_choice_range`).
- تبديل اللغة يعيد بناء كاش الأسماء تلقائياً.

### محرك المؤثرات (`modules/common.sh`)
- `fx_matrix_burst`: صف واحد (light) / صفان (strong) / ثلاثة صفوف ×3 إطارات
  (cinematic)، عرض 54 عموداً، وكل صف يُرسم دفعة واحدة ليبقى سريعاً على Git Bash.
- `fx_radar_ping`: مؤشر دوّار وشريط يمتلئ ثم `[LOCK]`، بتسمية مترجمة.
- `fx_ops_header` / `fx_ops_footer`: تُحيط كل تنفيذ أداة بـ Matrix + رادار +
  سطر إطلاق، ثم قفل رادار بالاسم والزمن ورمز الخروج (أخضر للنجاح/برتقالي للفشل).
- `run_tool` يجمع كود الخروج والزمن ويعيده كما هو (نجاح/فشل/بايثون).
- `fx_status_line` و`fx_scanline` صارا 1/2/4 إطارات حسب المستوى.

### بوابة العرض النظيف
- الألوان والمؤثرات تُعطَّل تلقائياً عند إعادة التوجيه/الأنابيب، `TERM=dumb`،
  أو `NO_COLOR` — بلا ANSI أو تحريك مؤشر أو تأخير.
- `RAQIB_COLOR=always` يفرض العرض البصري عمداً (عروض/`less -R`)، و
  `RAQIB_FX=off` يبقى مفعّلاً حتى معه.
- `raqib_clear` لا يرسل أكواد مسح إلا على طرفية حقيقية.

### اللغات
- 20 مفتاحاً جديداً في كل لغة (`cat8`–`cat13`، `menu_exit`، `menu_choice_range`،
  `lbl_*`، `fx_op_*`) ← **712 مفتاحاً** لكل لغة، **20 × 712 = 14,240 نص**.
- مجموعات المفاتيح متطابقة 100% بين اللغات العشرين.

### الأداء (Git Bash، بانر دافئ)
- `off` ~0.17ث، `light` ~0.35ث، `strong` ~0.71ث، `cinematic` ~1.32ث.
- البانر والقائمة بلا spawn لـ`clear`/`date`/`tr` في المسار الساخن.

### التوثيق
- لقطات جديدة: `assets/raqib_menu.png` (قائمة إنجليزية) و`assets/raqib_menu_ar.png`
  (قائمة عربية) بالبانر الجديد، مع تحديث `raqib_strong.png` و`raqib_cinematic.png`.

### الاختبارات
- `run_tool`: نجاح 0، فشل 3، بايثون 0 — في light/strong/cinematic.
- الأنابيب/`NO_COLOR`/`TERM=dumb`/`RAQIB_FX=off`: خرج نظيف فوري.
- ASCII fallback بعرض 50 عموداً، وإطار UTF-8 بعرض 50.
- الدقة 97.1% (TP=29/FP=0/TN=38/FN=2)، 20/20 لغة، 124 ملف `bash -n` بلا أخطاء.

