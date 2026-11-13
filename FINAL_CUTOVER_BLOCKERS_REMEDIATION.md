# AI Gateway V1 — Final Cutover Blockers Remediation Report

**التاريخ:** 13 نوفمبر 2026  
**الفرع الخاضع للمراجعة:** `audit/2026-11-13-c1`  
**الالتزام الأساسي:** `f98c189`  
**القرار النهائي:** `READY FOR OWNER CUTOVER APPROVAL` (نافذة الصيانة والتبديل معلقة بانتظار موافقة المالك)

---

## 1. ملخص معالجة الموانع الستة (F1 – F6)

| المعرّف | المانع المكتشف | الإجراء المتخذ | النتيجة |
| :---: | :--- | :--- | :---: |
| **F1** | احتمال نجاح زائف لبروتوكول Pepper وغياب `pipefail` | إعادة كتابة البروتوكول بالكامل بـ `set -Eeuo pipefail`، والكتابة لملف مؤقت محمي، وفحص الحجم و`sha256` المستقل، واشتراط عدم التجزئة الفارغة، ونقل ذري بـ `mv` | **PASS** |
| **F2** | خطأ خيار `-T` في `docker exec` وحفظ النسخة داخل Volume | إزالة `-T` من `docker exec`، ونقل النسخة الاحتياطية بتدفق مباشر (`cat > $DEST`) لدعم بيئات `--tmpfs` إلى المضيف خارج الـ Volume، وفحص سلامة المضيف بـ `PRAGMA integrity_check` | **PASS** |
| **F3** | تعارض التوثيق وسكربت التهيئة مع نظام أسرار الإنتاج | توحيد الإنتاج حصراً على `*_FILE`، وتحديث `scripts/init_env.sh --production` للمجلد `/etc/ai-gateway/secrets`، وحصر `.env` للتطوير المحلي فقط | **PASS** |
| **F4** | فجوة SSRF في نطاق Shared Address Space (`100.64.0.0/10`) | حظر صريح وشامل لنطاق CGNAT `100.64.0.0/10` وكافة عناوين IPv4 و IPv6 غير القابلة للتوجيه عالمياً (`not ip.is_global`) | **PASS** |
| **F5** | اختبار توافق SQLite لم يستخدم كود الالتزام التاريخي الفعلي | تعديل الاختبار ليحمّل فئة `Database` التاريخية الفعلية مباشرة من الالتزام الأساسي `70b4027` عبر Git وإثبات التوافق العكسي التام | **PASS** |
| **F6** | طباعة مفتاح العميل التجريبي في سجلات خطوات GitHub Actions | حذف طباعة `CREATE_OUTPUT` بالكامل، واستخراج `client_id` فقط، وإخفاء الـ API key من مخرجات CI | **PASS** |

---

## 2. تفاصيل المعالجة الفنية والأدلة

### F1 — بروتوكول نقل Pepper الذري والمحكم (Atomic Migration Protocol)
1. **معالجة احتمال الفشل الزائف:**
   - تم إلغاء استخدام `grep | cut | tr -d '\r\n'` أو أي pipe غير محمي.
   - تم اعتماد Bash مع تفعيل صارم لـ `set -Eeuo pipefail` و `trap cleanup EXIT ERR INT TERM`.
   - يتم إنشاء ملف مؤقت محمي `/etc/ai-gateway/secrets/.pepper.tmp.$$` بصلاحيات `0400` مملوكاً لـ `10001:10001`.
   - يتم استخراج البايتات الخام مباشرة من ذاكرة العملية عبر `os.environb.get(b"GATEWAY_PEPPER")` في Python، مع شرط توقف فوري إذا كانت البايتات أقل من 32 بايت أو احتوت على محارف فواصل أسطر (`\r` أو `\n`).
2. **فحص التجزئة والحجم:**
   - مقارنة مستقلة للحجم (`SRC_SIZE == DST_SIZE >= 32`).
   - مقارنة مستقلة لـ `sha256sum`.
   - **فحص مانع للتجزئة الفارغة:** رفض فوري إذا طابقت البصمة بصمة النص الفارغ (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
3. **فحص التكافؤ الوظيفي لـ HMAC (Zero-Knowledge):**
   - مقارنة توقيع HMAC لمفتاح اختباري في الذاكرة بين المصدر والملف المؤقت، وطباعة `MATCH` فقط دون طباعة التوقيع أو السر.
4. **النقل الذري:**
   - نقل الملف المؤقت ذرياً إلى الوجهة النهائية `/etc/ai-gateway/secrets/pepper` عبر `sudo mv`.
   - تم تضمين وتوثيق البروتوكول في سكربت مخصص: [scripts/migrate_pepper.sh](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/scripts/migrate_pepper.sh).
   - تم إنشاء اختبارات وحدة شاملة للحالات السلبية والإيجابية في [tests/test_pepper_migration.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/tests/test_pepper_migration.py) واجتازت بنجاح.

---

### F2 — إصلاح سكربت النسخ الاحتياطي [scripts/backup.sh](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/scripts/backup.sh)
1. **تصحيح خيارات Docker CLI:**
   - تم حذف الخيار غير الصالح `-T` من أمر `docker exec` في مسار الحاوية المنفردة (Docker Run).
   - تم الإبقاء على `-T` فقط مع `docker compose exec -T`.
2. **عزل ملف النسخ الاحتياطي خارج Volume الإنتاج:**
   - إنشاء النسخة الاحتياطية الحية أولاً في ملف مؤقت داخل الحاوية: `/tmp/online-backup-<timestamp>.sqlite3`.
   - نقل النسخة فورياً إلى مجلد محمي على المضيف خارج الـ Volume عبر الاستخراج بالتدفق المباشر (`cat > "$DEST"`) لضمان التوافق مع الحاويات المقيدة ذات الـ `--tmpfs /tmp` (حيث يتعذر على `docker cp` الوصول إلى ذاكرة tmpfs).
   - ضبط الصلاحيات على المضيف لـ `0600`.
   - التحقق من سلامة النسخة على المضيف عبر `sqlite3 "$DEST" "PRAGMA integrity_check;"`.
   - حذف الملف المؤقت من الحاوية بعد نجاح التحقق على المضيف فقط.
   - تم إنشاء اختبارات وحدة في [tests/test_backup_script.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/tests/test_backup_script.py) واجتازت بنجاح.

---

### F3 — توحيد إعداد وتوثيق الأسرار المستندة إلى الملفات
1. **تحديث [scripts/init_env.sh](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/scripts/init_env.sh):**
   - إضافة وضع الإنتاج الصريح: `./scripts/init_env.sh --production` لإنشاء `/etc/ai-gateway/secrets` بالصلاحيات `0750` وتوليد `pepper` بصلاحيات `0400` مملوكاً لـ `10001:10001`.
   - حصر توليد ملف `.env` للتطوير المحلي فقط مع إظهار تحذير صريح بأنه محظور في بيئات الإنتاج.
2. **تحديث [.env.example](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/.env.example) و [README.md](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/README.md):**
   - النص صراحة على أن أسرار الإنتاج لا تُخزن في `.env` أو متغيرات البيئة، بل عبر ملفات محمية بمسارات `GATEWAY_PEPPER_FILE` و `OPENROUTER_API_KEY_FILE`.
3. **تحديث [docker-compose.yml](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/docker-compose.yml):**
   - إضافة `pids_limit: 100` لتوحيد قيود التشغيل مع أوامر `docker run`.
   - التأكيد على ربط `/etc/ai-gateway/secrets:/secrets:ro`.

---

### F4 — سد فجوة Carrier-Grade NAT (`100.64.0.0/10`) في [app/ssrf.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/app/ssrf.py)
1. **إغلاق النطاقات غير القابلة للتوجيه عالمياً:**
   - إضافة فحص `not ip.is_global` الشامل في دالة `is_ip_forbidden`.
   - إضافة قائمة شبكات محظورة صريحة كخط دفاع ثانٍ تشمل:
     - `100.64.0.0/10` (RFC 6598 Carrier-Grade NAT / Shared Address Space).
     - `198.18.0.0/15` (RFC 2544 Network Interconnect Device Benchmark).
     - `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (Documentation TEST-NETs).
     - `240.0.0.0/4` (Reserved for Future Use).
     - `100::/64` (IPv6 Discard prefix) و `2001:db8::/32` (IPv6 Documentation).
2. **الاختبارات:**
   - تم تحديث [tests/test_ssrf_protection.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/tests/test_ssrf_protection.py) وإثبات رفض كافة هذه العناوين بصرامة.

---

### F5 — إثبات التوافق العكسي لـ SQLite باستخدام كود الالتزام الأساسي الفعلي
1. **تحديث [tests/test_sqlite_backward_compatibility.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/tests/test_sqlite_backward_compatibility.py):**
   - يتم استدعاء كود فئة `Database` التاريخية مباشرة من الالتزام الأساسي `70b4027` عبر أمر Git، وتشغيلها في مساحة اسم معزولة.
   - تم إنشاء قاعدة اختبار جديدة، وتهيئتها بكود الالتزام `70b4027`.
   - تم إضافة عميل وسجلات واستهلاك معدل الطلبات عبر الدوال التاريخية الأصلية.
   - تمت الترقية وفتح القاعدة بكود التطبيق المرشح، وتحديث `PRAGMA user_version = 1` بنجاح، والتحقق من `integrity_check`.
   - تم بنجاح تشغيل كود `Database` التاريخي مرة أخرى على نفس القاعدة بعد ترقيتها، وتأكيد قدرته على قراءة العملاء، وإنشاء سجلات جديدة، واستهلاك الـ Rate Limits دون أدنى تعارض.

---

### F6 — تنقية سجلات خطوات CI من بيانات الاعتماد الاختبارية
1. **تحديث سير العمل [.github/workflows/phase-d-linux-validation.yml](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/.github/workflows/phase-d-linux-validation.yml):**
   - إزالة سطر `echo "create-key output: ${CREATE_OUTPUT}"` الذي كان يطبع مفتاح العميل التجريبي.
   - استخراج `client_id` فقط وطباعته، مع كتم كامل لبقية المخرجات الحاوية على `api_key`.
   - إضافة اختبار تشغيلي لـ `scripts/backup.sh` داخل بيئة CI للتحقق من سلامة نقل النسخة الاحتياطية خارج الحاوية.

---

---

## 3. أدلة التحقق المستقل من تشغيل GitHub Actions (Run ID: `43496356039`)

تم تنفيذ فحص شامل على بيئة **Ubuntu Linux 24.04 LTS** المستقلة بالكامل، وأسفرت النتائج عن الآتي:

| المحور | النتيجة في تشغيل CI رقم `43496356039` | الدليل الموثق في السجلات |
| :--- | :---: | :--- |
| **مجموعة اختبارات Linux POSIX الكاملة** | **112 / 112 PASSED** (0 skipped / 0 failed) | `112 passed, 1 warning in 1.12s` |
| **اختبارات الطفرات (Mutation Tests)** | **PASSED (ALL KILLED)** | تم تحييد طفرة HMAC بنجاح، وتم تحييد طفرة Rate Limiting بنجاح |
| **اختبار S5 Canary لكشف تسريب الأسرار** | **PASSED (ZERO LEAKS)** | تم فحص المحادثة، ورمز المصادقة، وسر المزود في الاستجابات وسجلات الحاوية وقاعدة البيانات، ولم يُسجل أي تسريب |
| **حماية SSRF ونطاقات CGNAT و DNS Rebinding** | **22 / 22 PASSED** | حظر `100.64.0.0/10` وكافة العناوين غير العامة، وتثبيت IP وتأكيد عدم إعادة حل DNS |
| **بناء الصورة المرشحة وتدقيقها** | **PASSED** | Image ID: `sha256:879e05c8994d8a6af0dece2059594cacfde9184e64353693edf701a93e5581dc`<br>الحجم: 144,700,563 بايت (~138 MB)<br>المستخدم الافتراضي: `10001:10001`<br>خلوها من `pytest` ومن أي ملفات `.env` |
| **تشغيل الحاوية المعزولة (Strict Isolation)** | **PASSED** | جذر قراءة فقط (`--read-only`)، وذاكرة مؤقتة مقيدة (`--tmpfs /tmp`, `--tmpfs /data`) |
| **فحص Config.Env في Docker** | **PASSED** | طباعة أسماء المتغيرات فقط والتأكد من غياب الأسرار المباشرة (`_DIRECT=ABSENT`، `_FILE=PRESENT`) |
| **تحميل الأسرار من مجلد 0750** | **PASSED** | نجح المستخدم `10001:10001` في قراءة الأسرار من المجلد `0750` المملوك لـ `root:10001` دون أي خطأ |
| **حماية مفاتيح الاعتماد في سجلات CI** | **PASSED** | إنشاء مفتاح عميل دون طباعة `api_key` الخام في السجلات، واستخراج `client_id` فقط |
| **التحقق من سكربت النسخ الاحتياطي `backup.sh`** | **PASSED** | تم إنشاء النسخة، ونقلها للمضيف خارج الـ Volume عبر التدفق المباشر (`cat > $DEST`)، وضبط صلاحياتها `0600`، واجتياز `PRAGMA integrity_check` ("ok")، وحساب SHA-256 (`fb8810041fa93758f20cc59498882a198cfe9e475737844e109294527ac3cbac`)، وحذف الملف المؤقت من الحاوية |
| **سجلات الحاوية (Container Logs)** | **PASSED (ZERO LEAKS)** | خلو سجلات الحاوية تماماً من مفتاح Pepper أو رمز المزود |

---

## 4. القرار النهائي

```text
=====================================================
FINAL VERDICT: READY FOR OWNER CUTOVER APPROVAL
STATUS: HOLD — AWAITING OWNER MAINTENANCE WINDOW
=====================================================
```

تمت معالجة كافة الموانع الستة بالكامل وتوثيقها بأدلة قاطعة عبر التحقق المستقل على Linux في GitHub Actions (Run ID: `43496356039`)، دون أي مساس بقاعدة بيانات الإنتاج أو الحاوية الحالية، والمشروع جاهز للمراجعة النهائية واعتماد نافذة التبديل من قبل المالك.
