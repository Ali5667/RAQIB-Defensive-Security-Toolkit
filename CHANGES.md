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
