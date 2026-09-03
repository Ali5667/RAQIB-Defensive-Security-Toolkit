# RAQIB (رقيب) v2.0
### Defensive Security Toolkit — أدوات مستقلة مبنية من الصفر

```
  ____      _    ___ ___ ____
 |  _ \    / \  / _ \_ _| __ )
 | |_) |  / _ \| | | | ||  _ \
 |  _ <  / ___ \ |_| | || |_) |
 |_| \_\/_/   \_\__\_\___|____/
```

**Author:** Ali Alnuaimi
**GitHub:** https://github.com/Ali5667
**Twitter (X):** @ali_cys45

---

## 📖 نظرة عامة

RAQIB v2 نسخة معاد بناؤها بالكامل: **كل أداة داخل القوائم هي سكربت مستقل مكتوب بالكامل بـ Bash/Python**، ما تعتمد على تحميل أو استدعاء أي أداة خارجية معروفة (لا Nmap ولا Wireshark ولا غيرها) — كل شي يشتغل بأدوات النظام الأساسية (`ss`, `find`, `awk`, `grep`, `openssl`...) بمنطق كتبته الأداة نفسها.

يحتوي البرنامج على أنيميشن ترحيبي (نسر ASCII) عند الإقلاع، ثم بانر بتأثير الآلة الكاتبة، ثم القائمة الرئيسية.

---

## ✨ ليش RAQIB مختلف

- **صفر اعتماد على أدوات خارجية معروفة** — كل الـ43 أداة مكتوبة من الصفر بـ Bash/Python وتشتغل بأدوات النظام الأساسية فقط (`ss`, `find`, `awk`, `grep`, `openssl`, `/dev/tcp`...)؛ ما فيه استدعاء لـ Nmap أو Wireshark أو أي أداة معروفة، فتشتغل حتى على سيرفر minimal بدون تثبيت أي حزمة إضافية.
- **كشف مركّب مو توقيع واحد** — محرك "YARA-lite" (`webshell_lite.rules`) يجمع نقاط من عدة إشارات ضعيفة (تجميع أسماء دوال، `chr()`، hex escapes، `strrev`، صور تحوي كود PHP) بدل الاعتماد على نمط حرفي واحد، ويعمل تلقائياً كطبقة إضافية فوق ثنائي `yara` الحقيقي لو كان مثبّتاً.
- **تحديث قواعد حي، لكن آمن بالتصميم** — `rules_updater.sh` يسحب قواعد من مصدر تحدده أنت، معطّل افتراضياً لحد ما تتحقق وتفعّله بنفسك، يتحقق من صيغة كل سطر فعلياً قبل القبول، ياخذ نسخة احتياطية تلقائية، ويحافظ على أي قاعدة محلية خاصة بيك.
- **قياس دقة داخلي حقيقي مو رقم تسويقي** — `run_accuracy_eval.sh` يستورد نفس كود الإنتاج ويحسب Precision/Recall/F1 على كورپس مصنَّف يدوياً فيه عيّنات مموّهة عمداً وعيّنات "نظيفة بس تبان مشبوهة".
- **شفافية بالحدود بدل المبالغة** — قسم "حدود معروفة" واضح وصريح (Static-only، ما فيه سلوك حي، حالات معروفة ما تنكشف) بدل تسويق الأداة كحل شامل.
- **دعم كامل لـ10 لغات** — مو بس القائمة الرئيسية؛ كل رسائل الأدوات والتقارير وشاشات المساعدة والأخطاء مترجمة بالكامل (عربي، إنجليزي، فرنسي، إسباني، ألماني، تركي، فارسي، روسي، كردي، صيني).
- **مصممة كـIncident Response متكامل مو أدوات منفصلة** — قرنطنة وإزالة كاملة، منظّف تلقائي شامل يفحص عدة مصادر تهديد دفعة وحدة، وربط مباشر بين الأدوات (حساب hash → فحص سمعة فوراً بنفس الملف) بدل ما تكون كل أداة معزولة.

---

## ⚙️ التشغيل

```bash
chmod +x raqib.sh
./raqib.sh
```

**المتطلبات:** Bash 4+, Python3 (لأداة الإنتروبيا فقط), أدوات Linux الأساسية (find, awk, grep, ss, openssl).

---

## 🗂️ هيكل المشروع

```
raqib/
├── raqib.sh
├── README.md
├── modules/          # ملفات القوائم (تربط الأدوات)
├── samples/          # بيانات تجريبية (لوجات + ملف ثنائي) لاختبار الأدوات فوراً
├── tests/            # كورپس اختبار مصنَّف يدوياً (benign/malicious) + سكربت قياس الدقة
└── tools/
    ├── monitoring/   # 6 أدوات
    ├── logs/         # 5 أدوات
    ├── ids_ips/      # 6 أدوات
    ├── malware/      # 10 أدوات (+ rules/ لقواعد YARA-lite القابلة للتحديث والتحديث الحيّ)
    ├── forensics/    # 5 أدوات
    ├── hardening/    # 6 أدوات
    └── vuln_scan/    # 5 أدوات
```

---

## 📋 الأدوات (43 أداة مستقلة)

### 🛰️ مراقبة الشبكة
1. **فاحص المنافذ** — يفحص مدى منافذ TCP على مضيف عبر `/dev/tcp`
2. **الاتصالات النشطة** — يعرض كل اتصالات الشبكة الحالية عبر `ss`
3. **مراقب الباندويث** — يحسب معدل الرفع/التنزيل الفعلي من `/sys/class/net`
4. **مراقب ARP** — يأخذ baseline لجدول ARP ويقارنه لكشف تزوير ARP
5. **استعلام DNS** — تقدمي وعكسي عبر Python socket
6. **Ping Sweep** — يفحص شبكة فرعية كاملة لإيجاد الأجهزة الحية

### 📋 تحليل السجلات
1. **تقرير SSH الفاشل** — يحلل auth.log ويرتب أكثر IP محاولة
2. **بحث كلمة مفتاحية** — بحث بالسياق داخل أي ملف لوج
3. **أكثر السطور تكراراً** — يكشف أنماط أخطاء متكررة
4. **Timeline** — يقص جزء زمني محدد من اللوج
5. **محلل Access Log** — أكثر IP، أكواد الحالة، الصفحات المطلوبة

### 🚨 كشف التسلل والتهديدات
1. **كاشف Brute Force** — يحسب محاولات فاشلة لكل IP ويقارن بحد تنبيه
2. **مدقق المنافذ المستمعة** — يربط كل منفذ مفتوح بالعملية المسؤولة
3. **مراقب سلامة الملفات** — baseline بـ SHA256 لكل ملفات مجلد + كشف تغييرات
4. **فاحص Cron** — يجمع كل مهام cron (نظام+مستخدمين) ويحدد المعدّل حديثاً
5. **مراقب معدل الاتصالات** — لقطتين متتاليتين لكشف ارتفاع مفاجئ بالاتصالات

### 🦠 تحليل الملفات المشبوهة (Static Analysis)
1. **حاسبة Hash** — MD5/SHA1/SHA256 (+ عرض تلقائي لفحص السمعة بعدها)
2. **محدد نوع الملف** — يقارن الامتداد بالـ Magic Bytes الحقيقية
3. **مستخرج النصوص المشبوهة** — IP، روابط، Base64 طويل، أوامر خطرة
4. **حاسبة الإنتروبيا** — تحسب إنتروبيا شانون لكشف ملفات مشفّرة/محزومة
5. **فاحص الثبات (Persistence)** — يفحص systemd, cron, rc.local, LD_PRELOAD
6. **قرنطنة وإزالة كاملة** — يتتبّع نسخ مطابقة بالبصمة + مراجع الثبات، shred آمن
7. **منظّف تلقائي شامل** — يفحص webshells + cron + LD_PRELOAD + tmpexec دفعة وحدة، مع خيارات تنظيف متدرجة
8. **فحص سمعة الـ Hash** — VirusTotal API v3 + MalwareBazaar (abuse.ch)، قاعدة تهديدات محدّثة يومياً
9. **فحص قواعد YARA-lite** — محرك قواعد (اسم\|وزن\|regex) قابل للتحديث بدون تعديل كود، يمسك نسخاً مموّهة من webshells (تجميع نصوص، `chr()`، hex escapes، صور تحوي PHP...)؛ يستخدم ثنائي `yara` الحقيقي تلقائياً كطبقة إضافية لو كان مثبّتاً
10. **تحديث القواعد الحيّة** — يسحب قواعد جديدة (lite أو .yar حقيقية) من مصادر خارجية تحددها انت بملف `sources.txt`، مع تحقق من الصيغة، نسخة احتياطية تلقائية، ودمج يحافظ على أي قاعدة محلية خاصة بيك

### 🔍 الطب الشرعي الرقمي
1. **تقرير تسجيلات الدخول** — last / lastb / lastlog
2. **مراجعة Bash History** — يبحث عن أوامر مشبوهة بسجل كل المستخدمين
3. **Timeline للملفات** — ترتيب زمني حسب mtime/ctime
4. **لقطة استخدام القرص** — مقارنة حجم المجلدات بين وقتين
5. **مراجعة سجل Sudo** — كل أوامر sudo المنفذة + المحاولات الفاشلة

### 🛡️ تقوية الأنظمة
1. **مدقق الصلاحيات** — World-writable, SUID, SGID
2. **مدقق SSH** — يقارن sshd_config بأفضل الممارسات (PermitRootLogin...)
3. **قائمة الخدمات** — الخدمات المفعّلة + تنبيه للخدمات الخطرة (telnet, ftp...)
4. **فاحص سياسة كلمات المرور** — login.defs + PAM + حسابات بلا كلمة مرور
5. **فاحص الجدار الناري** — حالة UFW/firewalld/iptables والسياسة الافتراضية

### 🎯 فحص الثغرات والصلاحيات (لأنظمتك فقط)
1. **منافذ مقابل خدمات** — يربط المنفذ بالعملية ويحذّر من منافذ خطرة معروفة
2. **فاحص الحزم القديمة** — apt/yum/pip outdated
3. **فاحص الصلاحيات الضعيفة** — ملفات 777/666، مفاتيح SSH بصلاحيات خاطئة
4. **فاحص شهادة SSL** — تاريخ الانتهاء وتفاصيل الشهادة لأي دومين
5. **فاحص بيانات الاعتماد الافتراضية** — كلمات مرور ضعيفة/مفاتيح API مكشوفة بالكود

---

## 🎯 قياس الدقة (Accuracy Testing)

مجلد `tests/corpus/` فيه عيّنات مصنَّفة يدوياً (benign/malicious) لثلاث كاشفات استدلالية
(webshell، cron، تنفيذيات `/tmp`)، تشمل عيّنات مموّهة عمداً (تجميع نصوص، `chr()`،
hex escapes، `strrev`، صور تحوي PHP...) وعيّنات "نظيفة لكن تبان مشبوهة" لضبط الإيجابيات
الكاذبة. شغّل:

```bash
bash tests/run_accuracy_eval.sh
```

يطبع Precision/Recall/F1/Accuracy لكل كاشف + قائمة كل False Positive/Negative بالاسم —
هذا يقيس منطق الأداة الحقيقي نفسه (يستورد `tools/malware/malware_heuristics.sh` مباشرة)،
مو نسخة موازية منه. **مهم:** هذا معيار داخلي لقياس التراجع (regression) عند تعديل
القواعد، وليس "ضمان دقة 100%" — ما فيه أداة كشف تهديدات (تجارية أو غيرها) توصل 100%،
خصوصاً أمام zero-day أو ثنائيات ساكنة بدون أي نص/سلوك شبكي ظاهر بالتحليل الساكن؛ هذي
الحالات تحتاج مراقبة سلوكية حية، مو تحليل ساكن.

لزيادة الدقة لاحقاً بدون تعديل كود: أضف أسطر جديدة بصيغة `اسم|وزن|regex` بملف
`tools/malware/rules/webshell_lite.rules`، وزد عينات موزونة (خبيث + نظيف) بمجلد
`tests/corpus/`، وشغّل السكربت لترى أثر كل تعديل بالتفصيل (مو رقم نهائي بس).

---

## 🕘 آخر التحديثات

- **تحديث القواعد الحيّة** (`tools/malware/rules_updater.sh` + `tools/malware/rules/sources.txt`):
  أداة جديدة تسحب قواعد كشف محدّثة من مصادر خارجية *انت تحددها وتفعّلها بنفسك*
  (ما فيه سيرفر رسمي لـ RAQIB). نوعين مدعومين: تحديث `webshell_lite.rules`
  (يُتحقق من صيغة كل سطر والـ regex فعلياً قبل القبول، وأي قاعدة محلية خاصة
  بيك تُحافظ عليها حتى لو مو موجودة بالمصدر البعيد)، أو ملفات `.yar` حقيقية
  تُحفظ بمجلد `rules/` ليستخدمها ثنائي `yara` تلقائياً لو مثبّت. كل تحديث يأخذ
  نسخة احتياطية تلقائية (`rules/backups/`) ويُسجَّل بـ `rules/.rules_meta`.
  **مهم:** المصادر الافتراضية بملف `sources.txt` معطّلة (`enabled=0`) عن قصد —
  لازم تراجعها وتحدد مصادر تثق فيها بنفسك قبل التفعيل.
- **محرك قواعد "YARA-lite"** (`tools/malware/rules/webshell_lite.rules`): طبقة كشف
  إضافية بمحتوى الملف (مب hash فقط) تجمع نقاط عدة إشارات ضعيفة بدل الاعتماد على
  توقيع واحد قوي — تمسك نسخ webshells مموّهة (بناء اسم دالة من مقاطع، `chr()`،
  hex escapes، `strrev`، صور GIF/PNG تحوي كود PHP فعلي...) ما تطابق النمط الحرفي
  القديم. تُستخدم تلقائياً داخل `auto_malware_cleaner.sh` (القرار = الكاشف الكلاسيكي
  OR القواعد الجديدة)، ومتوفرة أيضاً كأداة مستقلة بالقائمة (**فحص قواعد YARA-lite**).
  لو ثنائي `yara` حقيقي مثبّت بالنظام ومعه ملفات `.yar` فعلية بنفس المجلد، يشتغل
  كطبقة إضافية فوق القواعد الخفيفة تلقائياً.
- توسيع `tests/corpus/` بعيّنات مموّهة إضافية وعيّنات "نظيفة لكن تبان مشبوهة" (كورپس
  متوازن)، وتوسيع `tests/run_accuracy_eval.sh` ليقيس الكاشف الكلاسيكي والقواعد
  الجديدة والقرار المدمج بينهم كل على حدة.
- تحسين نمط كشف الـ cron وتنفيذيات `/tmp` ليغطيا reverse shells بلغات غير bash
  (بايثون/بيرل)، ومصادر تنزيل-وتنفيذ عبر مفسّرات غير `sh`/`bash`.
- ربط `hash_calculator.sh` بفحص السمعة (VirusTotal + MalwareBazaar): بعد حساب
  الـ hash يُعرض عليك تشغيل الفحص مباشرة بنفس الملف بدون إعادة إدخال المسار.
- إزالة شاشة الدخول بكلمة السر: `raqib.sh` يفتح الآن مباشرة على القائمة الرئيسية بدون أي طلب كلمة مرور.
- تحسين أداة `auto_malware_cleaner.sh`: فحص `/tmp` و`/var/tmp` و`/dev/shm` صار يعتمد على عدة إشارات مجتمعة (ملف مخفي، غير تابع لمدير حزم، نمط شبكي/reverse-shell داخل المحتوى، محاكاة اسم ثنائي نظامي، صلاحية SUID/SGID) بدل تصنيف أي ملف قابل للتنفيذ كمشبوه فوراً — هذا يقلل النتائج الإيجابية الكاذبة على سكربتات التثبيت العادية، لكنه يبقى أداة استدلالية (heuristic) وليس محرك توقيعات فيروسات حقيقي، فراجع أي نتيجة قبل الحذف.
- استبدال مقدمة التشغيل (الدرع/النسر/العلم المتحركة) برسمة نسر واحدة تفصيلية (ASCII art) تظهر عند بدء تشغيل السكربت، تحتها مباشرة اسم RAQIB والوصف ومعلومات المؤلف — كلهن يطلعون سوا بدون تكرار.
- إضافة **تاريخ الإنشاء** بالبانر، وهو يتغير صيغته تلقائياً حسب اللغة المختارة بالسكربت (عربي، إنكليزي، فرنسي، إسباني، ألماني، تركي، فارسي، روسي، كردي، صيني).
- حذف سطر "آخر تحديث" من البانر.
- تحديث اسم المؤلف الظاهر بالبانر وبهذا الملف إلى **Ali Alnuaimi**.

---

## ⚠️ حدود معروفة (Known Limitations)

- **لا يوجد كشف سلوكي حي (Behavior-based) فعلي بعد** — كل الأداة حالياً static analysis
  فقط (فحص محتوى/hash/entropy/YARA-lite). مراقبة العملية وقت التشغيل الفعلي (اتصالات
  شبكية لحظية، سلوك مشبوه أثناء التنفيذ) غير مبنية بعد.
- **مصادر القواعد الحيّة (`rules_updater.sh` + `sources.txt`) غير مُتحقق منها بمصدر
  حقيقي** — الآلية (تحقق من الصيغة، نسخ احتياطي، دمج) جاهزة ومختبرة بمصادر تجريبية،
  لكنها معطّلة افتراضياً (`enabled=0`) لأنه ما تم التحقق من أي رابط مصدر حي فعلي (بيئة
  التطوير بلا إنترنت خارجي).
- **`raqib.sh` نفسه ما جُرّب طرف-لطرف على جهاز حقيقي** — كل الاختبارات الحالية عبر
  محاكاة (stub functions) داخل بيئة التطوير، مو تشغيل فعلي كامل للسكربت.
- **حالة `static_dropper` بكورپس الاختبار معروفة ومتروكة عمداً** — ثنائي ساكن بدون
  نص أو سلوك ظاهر بالتحليل الساكن، وبالتالي لا ينكشف حالياً؛ هذا حد متوقع لأي أداة
  static-only (يحتاج طبقة سلوكية حية لسده، مو تحسين قواعد ساكنة).
- **صفر قواعد `.yar` حقيقية بالمشروع حالياً** — الدعم التقني لتحميل واستخدام ملفات
  `.yar` من ثنائي `yara` الحقيقي موجود وجاهز، لكن ما فيه قواعد فعلية إلا لو مصدر
  خارجي يجيب وحدة.
- **لم يُختبر على أنظمة تشغيل غير بيئة التطوير الحالية** — لا اختبار على macOS ولا
  على توزيعات Linux مختلفة بعد.

---

## ⚠️ إخلاء مسؤولية

الأدوات المتعلقة بالفحص (منافذ، ثغرات، صلاحيات) مخصصة **حصراً لفحص أنظمتك وشبكاتك الخاصة** أو أنظمة تملك تصريحاً رسمياً للعمل عليها. المستخدم مسؤول بالكامل عن الالتزام بالقوانين المحلية.

---

## 📩 تواصل
- GitHub: [Ali5667](https://github.com/Ali5667)
- Twitter (X): [@ali_cys45](https://twitter.com/ali_cys45)











# RAQIB (رقيب) v2.0
### Defensive Security Toolkit — Standalone Tools Built From Scratch

```
  ____      _    ___ ___ ____
 |  _ \    / \  / _ \_ _| __ )
 | |_) |  / _ \| | | | ||  _ \
 |  _ <  / ___ \ |_| | || |_) |
 |_| \_\/_/   \_\__\_\___|____/
```

**Author:** Ali Alnuaimi
**GitHub:** https://github.com/Ali5667
**Twitter (X):** @ali_cys45

---

## 📖 Overview

RAQIB v2 is a fully rebuilt version: **every tool inside the menus is a standalone script written entirely in Bash/Python**, with no dependency on downloading or calling any well-known external tool (no Nmap, no Wireshark, nothing else) — everything runs on core system utilities (`ss`, `find`, `awk`, `grep`, `openssl`...) using logic written from scratch for this tool.

The program has a welcome animation (ASCII eagle) on startup, followed by a typewriter-effect banner, then the main menu.

---

## ✨ What Makes RAQIB Different

- **Zero dependency on well-known external tools** — all 43 tools are written from scratch in Bash/Python and run purely on core system utilities (`ss`, `find`, `awk`, `grep`, `openssl`, `/dev/tcp`...); there's no call to Nmap, Wireshark, or any well-known tool, so it runs even on a minimal server with no extra packages installed.
- **Composite detection, not a single signature** — the "YARA-lite" engine (`webshell_lite.rules`) scores multiple weak signals together (function-name concatenation, `chr()`, hex escapes, `strrev`, images containing PHP code) instead of relying on one literal pattern, and automatically layers on top of a real `yara` binary if one is installed.
- **Live rule updates, but safe by design** — `rules_updater.sh` pulls rules from a source you specify yourself, disabled by default until you verify and enable it, actually validates every line's format and regex before accepting it, takes an automatic backup, and preserves any of your own local-only rules.
- **A real internal accuracy benchmark, not a marketing number** — `run_accuracy_eval.sh` imports the actual production code and computes Precision/Recall/F1 on a manually-labeled corpus that includes deliberately obfuscated samples and "clean but suspicious-looking" samples.
- **Transparency about limitations instead of overselling** — a clear, explicit "Known Limitations" section (static-only, no live behavioral detection, known cases that go undetected) instead of marketing the tool as a complete solution.
- **Full support for 10 languages** — not just the main menu; every tool message, report, help screen, and error is fully translated (Arabic, English, French, Spanish, German, Turkish, Persian, Russian, Kurdish, Chinese).
- **Built as an integrated Incident Response workflow, not isolated tools** — full quarantine-and-eradicate, a comprehensive auto-cleaner that checks multiple threat sources in one pass, and direct hand-offs between tools (compute a hash → run a reputation check immediately on the same file) instead of each tool standing alone.

---

## ⚙️ Running It

```bash
chmod +x raqib.sh
./raqib.sh
```

**Requirements:** Bash 4+, Python3 (for the entropy tool only), core Linux utilities (find, awk, grep, ss, openssl).

---

## 🗂️ Project Structure

```
raqib/
├── raqib.sh
├── README.md
├── modules/          # Menu files (wire up the tools)
├── samples/          # Sample data (logs + a binary file) to test tools immediately
├── tests/            # Manually-labeled test corpus (benign/malicious) + accuracy-measurement script
└── tools/
    ├── monitoring/   # 6 tools
    ├── logs/         # 5 tools
    ├── ids_ips/      # 6 tools
    ├── malware/      # 10 tools (+ rules/ for updatable, live-updating YARA-lite rules)
    ├── forensics/    # 5 tools
    ├── hardening/    # 6 tools
    └── vuln_scan/    # 5 tools
```

---

## 📋 The Tools (43 standalone tools)

### 🛰️ Network Monitoring
1. **Port Scanner** — scans a range of TCP ports on a host via `/dev/tcp`
2. **Active Connections** — shows all current network connections via `ss`
3. **Bandwidth Monitor** — computes real upload/download rate from `/sys/class/net`
4. **ARP Watch** — takes a baseline of the ARP table and compares it to detect ARP spoofing
5. **DNS Lookup** — forward and reverse, via Python sockets
6. **Ping Sweep** — scans an entire subnet to find live hosts

### 📋 Log Analysis
1. **Failed SSH Report** — analyzes auth.log and ranks the most frequent attacking IPs
2. **Keyword Search** — context-aware search inside any log file
3. **Top Repeated Lines** — surfaces recurring error patterns
4. **Timeline** — extracts a specific time window from a log
5. **Access Log Analyzer** — top IPs, status codes, requested pages

### 🚨 Intrusion & Threat Detection
1. **Brute Force Detector** — counts failed attempts per IP and compares against an alert threshold
2. **Listening Ports Auditor** — maps every open port to its owning process
3. **File Integrity Monitor** — SHA256 baseline of every file in a folder + change detection
4. **Cron Auditor** — collects every cron job (system + all users) and flags recently modified ones
5. **Connection Rate Watcher** — two consecutive snapshots to catch a sudden spike in connections

### 🦠 Suspicious File Analysis (Static Analysis)
1. **Hash Calculator** — MD5/SHA1/SHA256 (+ auto-offers a reputation check right after)
2. **File Type Identifier** — compares the extension against the real magic bytes
3. **Suspicious Strings Extractor** — IPs, URLs, long Base64 blobs, dangerous commands
4. **Entropy Calculator** — computes Shannon entropy to spot encrypted/packed files
5. **Persistence Scanner** — checks systemd, cron, rc.local, LD_PRELOAD
6. **Full Quarantine & Eradication** — tracks hash-identical copies + persistence references, safe shred
7. **Comprehensive Auto Cleaner** — scans webshells + cron + LD_PRELOAD + tmpexec in one pass, with graduated cleanup options
8. **Hash Reputation Check** — VirusTotal API v3 + MalwareBazaar (abuse.ch), a daily-updated threat feed
9. **YARA-lite Rules Scan** — an updatable rule engine (name\|weight\|regex) that requires no code changes, catches obfuscated webshell variants (string concatenation, `chr()`, hex escapes, images embedding real PHP code...); automatically uses a real `yara` binary as an extra layer if installed
10. **Live Rules Update** — pulls new rules (lite or real .yar) from external sources you define in `sources.txt`, with format validation, automatic backup, and a merge that preserves your own local rules

### 🔍 Digital Forensics
1. **Login History Report** — last / lastb / lastlog
2. **Bash History Review** — searches every user's history for suspicious commands
3. **File Timeline** — chronological ordering by mtime/ctime
4. **Disk Usage Snapshot** — compares folder sizes between two points in time
5. **Sudo Log Review** — every executed sudo command + failed attempts

### 🛡️ System Hardening
1. **Permission Auditor** — world-writable files, SUID, SGID
2. **SSH Auditor** — compares sshd_config against best practices (PermitRootLogin...)
3. **Service Lister** — enabled services + alerts for risky ones (telnet, ftp...)
4. **Password Policy Checker** — login.defs + PAM + accounts with no password
5. **Firewall Status Checker** — UFW/firewalld/iptables status and default policy

### 🎯 Vulnerability & Permission Scan (your own systems only)
1. **Ports vs Services** — maps a port to its process and warns about known-risky ports
2. **Outdated Packages Checker** — apt/yum/pip outdated
3. **Weak Permissions Checker** — 777/666 files, SSH keys with wrong permissions
4. **SSL Certificate Checker** — expiry date and certificate details for any domain
5. **Default Credentials Checker** — weak passwords / API keys hardcoded in source

---

## 🎯 Accuracy Testing

The `tests/corpus/` folder contains manually-labeled samples (benign/malicious) for three heuristic detectors (webshell, cron, `/tmp` executables), including deliberately obfuscated samples (string concatenation, `chr()`, hex escapes, `strrev`, images embedding PHP...) and "clean but suspicious-looking" samples to keep false positives in check. Run:

```bash
bash tests/run_accuracy_eval.sh
```

It prints Precision/Recall/F1/Accuracy for each detector plus a named list of every False Positive/Negative — this measures the tool's actual production logic (it imports `tools/malware/malware_heuristics.sh` directly), not a parallel copy of it. **Important:** this is an internal regression benchmark for when you tweak the rules, not a "100% accuracy guarantee" — no threat-detection tool (commercial or otherwise) hits 100%, especially against zero-days or static binaries with no visible strings/network behavior under static analysis; those cases need live behavioral monitoring, not static analysis.

To improve accuracy later without touching code: add new lines in the `name|weight|regex` format to `tools/malware/rules/webshell_lite.rules`, add weighted samples (malicious + clean) to `tests/corpus/`, and run the script to see the detailed effect of each change (not just a final number).

---

## 🕘 Latest Updates

- **Live Rules Update** (`tools/malware/rules_updater.sh` + `tools/malware/rules/sources.txt`): a new tool that pulls updated detection rules from external sources *that you define and enable yourself* (there is no official RAQIB server). Two supported types: updating `webshell_lite.rules` (every line's format and regex is actually validated before acceptance, and any of your own local-only rules are preserved even if absent from the remote source), or real `.yar` files saved into `rules/` for a real `yara` binary to pick up automatically if installed. Every update takes an automatic backup (`rules/backups/`) and is logged to `rules/.rules_meta`. **Important:** the default sources in `sources.txt` are disabled (`enabled=0`) on purpose — you need to review them and pick sources you trust before enabling.
- **"YARA-lite" rules engine** (`tools/malware/rules/webshell_lite.rules`): an additional content-based detection layer (not just hashes) that scores multiple weak signals instead of relying on one strong signature — it catches obfuscated webshell variants (function names built from fragments, `chr()`, hex escapes, `strrev`, GIF/PNG images containing real PHP code...) that don't match the old literal pattern. Used automatically inside `auto_malware_cleaner.sh` (decision = classic detector OR the new rules), and also available as a standalone tool in the menu (**YARA-lite Rules Scan**). If a real `yara` binary is installed on the system along with actual `.yar` files in the same folder, it runs automatically as an additional layer on top of the lite rules.
- Expanded `tests/corpus/` with additional obfuscated samples and "clean but suspicious-looking" samples (a balanced corpus), and expanded `tests/run_accuracy_eval.sh` to measure the classic detector, the new rules, and the combined decision, each on its own.
- Improved cron and `/tmp`-executable detection patterns to cover reverse shells in non-bash languages (Python/Perl), and download-and-execute sources via interpreters other than `sh`/`bash`.
- Wired `hash_calculator.sh` into the reputation check (VirusTotal + MalwareBazaar): after computing a hash, you're offered to run the check immediately on the same file without re-entering the path.
- Removed the password login screen: `raqib.sh` now opens straight to the main menu with no password prompt.
- Improved `auto_malware_cleaner.sh`: scanning `/tmp`, `/var/tmp`, and `/dev/shm` now relies on multiple combined signals (hidden file, not owned by a package manager, network/reverse-shell pattern in the content, mimicking a system binary's name, SUID/SGID permission) instead of flagging any executable file as suspicious immediately — this reduces false positives on ordinary install scripts, but it remains a heuristic tool, not a real virus-signature engine, so review any result before deleting.
- Replaced the animated startup intro (shield/eagle/flag) with a single detailed ASCII-art eagle shown at script startup, directly followed by the RAQIB name, description, and author info — all shown together without repetition.
- Added a **creation date** to the banner, which is automatically formatted according to the script's currently selected language (Arabic, English, French, Spanish, German, Turkish, Persian, Russian, Kurdish, Chinese).
- Removed the "last updated" line from the banner.
- Updated the author name shown in the banner and this file to **Ali Alnuaimi**.

---

## ⚠️ Known Limitations

- **No real behavior-based detection yet** — the entire tool is currently static analysis only (content/hash/entropy/YARA-lite checks). Live runtime process monitoring (real-time network connections, suspicious behavior during execution) is not built yet.
- **Live rule sources (`rules_updater.sh` + `sources.txt`) are unverified against a real source** — the mechanism (format validation, backup, merge) is built and tested with mock sources, but disabled by default (`enabled=0`) because no real live source URL has been verified (the dev environment has no outside internet access).
- **`raqib.sh` itself has not been end-to-end tested on a real machine** — all current tests use stub functions inside the dev environment, not a full real run of the script.
- **The `static_dropper` case in the test corpus is a known, deliberately-left gap** — a static binary with no visible strings/behavior under static analysis, so it currently goes undetected; this is an expected limit of any static-only tool (needs a live behavioral layer to close, not better static rules).
- **Zero real `.yar` rules ship with the project right now** — technical support for loading and using `.yar` files with a real `yara` binary exists and is ready, but there are no actual rule files unless an external source provides one.
- **Not tested on any OS besides the current development environment** — no testing on macOS or on other Linux distributions yet.

---

## ⚠️ Disclaimer

The scanning-related tools (ports, vulnerabilities, permissions) are intended **exclusively for scanning your own systems and networks**, or systems you have explicit authorization to work on. The user is fully responsible for complying with local laws.

---

## 📩 Contact
- GitHub: [Ali5667](https://github.com/Ali5667)
- Twitter (X): [@ali_cys45](https://twitter.com/ali_cys45)
