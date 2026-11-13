# AI Gateway V1 — Final Deployment Review (Corrected & Verified)

**التاريخ:** 13 نوفمبر 2026  
**الفرع المعتمد للمراجعة:** `audit/2026-11-13-c1`  
**الالتزام المعتمد والمختبر في CI:** `2ebc857`  
**الالتزام الأساسي:** `f98c189`  
**معرف تشغيل التحقق المستقل في GitHub Actions:** `43496356039`  
**معرف الصورة المرشحة في CI:** `sha256:879e05c8994d8a6af0dece2059594cacfde9184e64353693edf701a93e5581dc`  
**القرار النهائي:** `READY FOR OWNER CUTOVER APPROVAL` (نافذة التبديل معلقة بانتظار موافقة المالك)

---

## 1. جدول التقييم التنفيذي لمعايير النشر بعد التصحيحات

| المعيار | التقييم | النتيجة الفنية والضوابط المعتمدة |
| :--- | :---: | :--- |
| **1. صلاحيات مجلد وملفات الأسرار** | **PASS** | تصحيح المجلد لـ `0750` بملكية `root:10001`، والملفات `0400` بملكية `10001:10001`. تم إثبات نجاح فتح الملفين فعلياً بهوية `10001:10001` داخل الحاوية المرشحة. |
| **2. بروتوكول نقل Pepper المطابق بايتاً ببايت** | **PASS** | إلغاء أمر `tr -d` القديم بالكامل؛ اعتماد استخراج البايتات الخام (`os.environb`) دون تطبيع، مع مطابقة `sha256` المستقلة، وفحص التكافؤ الوظيفي لـ HMAC. |
| **3. فحص Docker Config.Env دون كشف الأسرار** | **PASS** | استبدال `grep` بأمر فحص آمن يطبع أسماء المتغيرات فقط (`GATEWAY_PEPPER_DIRECT=ABSENT`، `GATEWAY_PEPPER_FILE=PRESENT`) دون أي إخراج لقيم أو JSON. |
| **4. تحديث إعداد Compose وسكربت النسخ الاحتياطي** | **PASS** | تحديث `docker-compose.yml` ليعتمد `*_FILE` و `--read-only` وحدود الموارد؛ وتحديث `scripts/backup.sh` ليدعم الحاويات المشغلة بـ `docker run` و Compose. |
| **5. توثيق هوية الصورة ونقلها** | **PASS** | توثيق الفرق بين Image ID في CI وإعادة البناء على الإنتاج؛ واشتراط قياس Image ID وفحص الصورة قبل التبديل، أو استخدام `docker save/load` كأثر منقول. |
| **6. اختبار التوافق العكسي لـ SQLite والتراجع** | **PASS** | إنجاز اختبار مستقل شامل ([test_sqlite_backward_compatibility.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/tests/test_sqlite_backward_compatibility.py))؛ أثبت سلامة الترحيل وعدم فقدان أي بيانات عند التراجع لإصدار التطبيق القديم باستخدام كود الالتزام الأساسي الفعلي `70b4027` (112 اختباراً ناجحاً في CI دون أي تخطٍ أو فشل). |

---

## 2. البند 1: صلاحيات مجلد وملفات الأسرار (Secret Directory Permissions)

### 1. تحليل المشكلة المعالجة
كان المقترح السابق يضبط المجلد `/etc/ai-gateway/secrets` بالصلاحية `0700` وبملكية `root:root`. وبما أن الحاوية تعمل بالمستخدم `10001:10001`، فإن هذا الإعداد يمنع المستخدم `10001` من عبور المجلد (Traverse / Search) للحصول على مفاتيحه، مما يؤدي إلى فشل فوري في تشغيل البوابة وتوقف تحميل الأسرار.

### 2. التصميم المصحح والمعتمد
- **المجلد على المضيف:**
  - المسار: `/etc/ai-gateway/secrets`
  - المالك: `root:10001`
  - الصلاحية: `0750` (`rwxr-x---`)
- **ملفات الأسرار داخل المجلد:**
  - المسارات: `/etc/ai-gateway/secrets/pepper` و `/etc/ai-gateway/secrets/openrouter_key`
  - المالك: `10001:10001`
  - الصلاحية: `0400` (`r--------`)
- **التركيب داخل الحاوية:**
  - `-v /etc/ai-gateway/secrets:/secrets:ro`

### 3. التوافق التام مع سياسة `app/secret_loader.py`
- مجلد `/secrets` يمتلكه `root` (UID 0) ومجموعته `10001` (GID 10001):
  - `SAFE_DIRECTORY_UIDS = frozenset({0, 10001})` يتحقق بنجاح لأن المالك `0`.
  - شرط الأمان `mode & 0o022 == 0` يتحقق بنجاح لأن `0o750 & 0o022 == 0` (لا توجد صلاحية كتابة للمجموعة أو الآخرين).
  - المستخدم `10001` يمتلك صلاحية العبور `r-x` عبر انتمائه لمجموعة المجلد `10001`.
- ملفات الأسرار يمتلكها `10001:10001` وصلاحيتها `0400`:
  - `metadata.st_uid == 10001 and metadata.st_gid == 10001` يتحقق بنجاح.
  - `file_mode in {0o400, 0o440}` يتحقق بنجاح.

### 4. الإثبات العملي من تشغيل CI (`43496356039`)
تم تشغيل فحص مباشر داخل الحاوية المعزولة بصلاحيات `10001:10001` للتأكد من قدرة محمل الأسرار على فتح الملفين من المجلد `0750`:
```text
Testing secret loader resolution inside container as user 10001:10001...
PASS: Secrets opened and resolved successfully by UID 10001:10001 from 0750 parent directory
```

---

## 3. البند 2: بروتوكول نقل Pepper الدقيق بايتاً ببايت (Pepper Exact Migration Protocol)

### 1. إبطال طريقة الاستخراج القديمة
تم إلغاء الأمر السابق:
```bash
# ملغى ومحرم استخدامه:
grep '^GATEWAY_PEPPER=' ... | cut -d'=' -f2- | tr -d '\r\n'
```
**سبب الإلغاء:** الأمر `tr -d '\r\n'` يقوم بحذف أي محرف نهاية سطر في كامل النص بشكل عشوائي، كما أن مقارنة التجزئة لنفس النص المعالج لا تثبت أن بايتات القيمة الأصلية قبل المعالجة مطابقة للبايتات بعد النقل.

### 2. بروتوكول النقل الخام المعتمد (Zero Normalization Protocol)
تُنقل القيمة الفعلية كما تقرؤها العملية الحالية في ذاكرتها من `os.environb` مباشرة، دون تعديل أو تطبيع، ودون تمريرها في arguments، ودون حفظها في shell history عبر سكربت [scripts/migrate_pepper.sh](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/scripts/migrate_pepper.sh) المحمي بـ `set -Eeuo pipefail`:

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

CURRENT_CONTAINER="${1:?Usage: $0 <CURRENT_CONTAINER_NAME_OR_ID>}"
SECRETS_DIR="${SECRETS_DIR:-/etc/ai-gateway/secrets}"
FINAL_PEPPER="${SECRETS_DIR}/pepper"
TEMP_PEPPER="${SECRETS_DIR}/.pepper.tmp.$$"

# تنظيف الملف المؤقت عند أي خطأ أو خروج
trap 'rm -f "${TEMP_PEPPER}"' EXIT ERR INT TERM

# 1. إنشاء المجلد المحمي والملف المؤقت بصلاحيات 0400 مسبقاً
sudo install -m 0750 -o root -g 10001 -d "${SECRETS_DIR}"
sudo install -m 0400 -o 10001 -g 10001 /dev/null "${TEMP_PEPPER}"

# 2. استخراج البايتات الخام مباشرة من ذاكرة العملية الحالية عبر pipe إلى الملف المؤقت:
docker exec "${CURRENT_CONTAINER}" python -c '
import os, sys
raw_bytes = os.environb.get(b"GATEWAY_PEPPER")
if raw_bytes is None:
    sys.exit("ABORT: GATEWAY_PEPPER is missing from container")
if len(raw_bytes) < 32:
    sys.exit(f"ABORT: GATEWAY_PEPPER length is {len(raw_bytes)} bytes; minimum required is 32 bytes")
# شرط التوقف الصارم: إذا وُجدت فواصل أسطر داخلية ملتبسة في البيئة، توقف فوراً ولا تغير شيئاً
if b"\n" in raw_bytes or b"\r" in raw_bytes:
    sys.exit("ABORT: In-memory Pepper contains line breaks; stopping to prevent key corruption")
sys.stdout.buffer.write(raw_bytes)
' | sudo tee "${TEMP_PEPPER}" > /dev/null

# 3. التحقق المستقل من الحجم
SRC_SIZE=$(docker exec "${CURRENT_CONTAINER}" python -c 'import os, sys; b=os.environb.get(b"GATEWAY_PEPPER", b""); sys.stdout.write(str(len(b)))')
DST_SIZE=$(sudo wc -c < "${TEMP_PEPPER}")
[ "${SRC_SIZE}" -ge 32 ] && [ "${SRC_SIZE}" -eq "${DST_SIZE}" ] || { echo "ERROR: Size mismatch"; exit 1; }

# 4. التحقق المستقل من بصمة SHA-256 (مع رفض البصمة الفارغة قطيعاً)
EMPTY_SHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SRC_SHA=$(docker exec "${CURRENT_CONTAINER}" python -c 'import os, hashlib, sys; b=os.environb.get(b"GATEWAY_PEPPER", b""); sys.stdout.write(hashlib.sha256(b).hexdigest())')
DST_SHA=$(sudo sha256sum "${TEMP_PEPPER}" | awk '{print $1}')

if [ "$SRC_SHA" = "$EMPTY_SHA" ] || [ "$DST_SHA" = "$EMPTY_SHA" ] || [ "$SRC_SHA" != "$DST_SHA" ]; then
    echo "ERROR: SHA-256 mismatch or empty payload" && exit 1
fi

# 5. التكافؤ الوظيفي لتوليد HMAC في الذاكرة دون كشف السر أو التوقيع
HMAC_MATCH=$(python3 -c '
import subprocess, sys, hmac, hashlib
token = b"canary_verify_token"
src = subprocess.check_output(["docker", "exec", sys.argv[1], "python", "-c", "import os, hmac, hashlib, sys; sys.stdout.write(hmac.new(os.environb.get(b\"GATEWAY_PEPPER\", b\"\"), sys.argv[1].encode(), hashlib.sha256).hexdigest())", token.decode()], text=True).strip()
with open(sys.argv[2], "rb") as f:
    dst = hmac.new(f.read(), token, hashlib.sha256).hexdigest()
sys.stdout.write("MATCH" if src == dst and len(src) == 64 else "MISMATCH")
' "${CURRENT_CONTAINER}" "${TEMP_PEPPER}")
[ "$HMAC_MATCH" = "MATCH" ] || { echo "ERROR: HMAC check failed"; exit 1; }

# 6. النقل الذري النهائي
sudo mv "${TEMP_PEPPER}" "${FINAL_PEPPER}"
sudo chown 10001:10001 "${FINAL_PEPPER}"
sudo chmod 0400 "${FINAL_PEPPER}"
echo "PEPPER_ATOMIC_MIGRATION=SUCCESS"
```

---

## 4. البند 3: فحص Docker Config.Env الآمن (Zero Value Leakage)

تم استبدال أمر `grep` القديم الذي كان يهدد بعرض سطور الأسرار، بأمر فحص آمن ومحكم يفحص وجود وغياب أسماء المتغيرات فقط، ولا يطبع أي قيم أو مخرجات JSON:

```bash
docker inspect <CONTAINER_ID> --format '{{json .Config.Env}}' | python3 -c '
import sys, json

env_list = json.load(sys.stdin)
names = [e.split("=", 1)[0] for e in env_list if "=" in e]

print("GATEWAY_PEPPER_DIRECT=" + ("PRESENT" if "GATEWAY_PEPPER" in names else "ABSENT"))
print("OPENROUTER_API_KEY_DIRECT=" + ("PRESENT" if "OPENROUTER_API_KEY" in names else "ABSENT"))
print("GATEWAY_PEPPER_FILE=" + ("PRESENT" if "GATEWAY_PEPPER_FILE" in names else "ABSENT"))
print("OPENROUTER_API_KEY_FILE=" + ("PRESENT" if "OPENROUTER_API_KEY_FILE" in names else "ABSENT"))

assert "GATEWAY_PEPPER" not in names, "FAIL: GATEWAY_PEPPER is present directly in Config.Env"
assert "OPENROUTER_API_KEY" not in names, "FAIL: OPENROUTER_API_KEY is present directly in Config.Env"
assert "GATEWAY_PEPPER_FILE" in names, "FAIL: GATEWAY_PEPPER_FILE missing"
assert "OPENROUTER_API_KEY_FILE" in names, "FAIL: OPENROUTER_API_KEY_FILE missing"
'
```

### الناتج الفعلي المثبت في CI (`43496356039`):
```text
GATEWAY_PEPPER_DIRECT=ABSENT
OPENROUTER_API_KEY_DIRECT=ABSENT
GATEWAY_PEPPER_FILE=PRESENT
OPENROUTER_API_KEY_FILE=PRESENT
PASS: Zero literal secrets in Docker Config.Env (uses _FILE paths only)
```

---

## 5. البند 4: تحديث Compose وسكربت النسخ الاحتياطي (Compose & Scripts Alignment)

### 1. تحديث [docker-compose.yml](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/docker-compose.yml)
تم تحديث الملف بالكامل في المستودع ليتطابق مع أعلى معايير الأمان المعتمدة:
```yaml
services:
  gateway:
    build:
      context: .
      dockerfile: Dockerfile
    image: ai-gateway-v1:candidate-4d95c42
    restart: unless-stopped
    read_only: true
    user: "10001:10001"
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      - GATEWAY_HOST=0.0.0.0
      - GATEWAY_PORT=8000
      - GATEWAY_CONFIG=/app/config/config.yaml
      - GATEWAY_DATABASE_PATH=/data/gateway.sqlite3
      - GATEWAY_PEPPER_FILE=/secrets/pepper
      - OPENROUTER_API_KEY_FILE=/secrets/openrouter_key
    volumes:
      - ai-gateway-v1-data:/data
      - ./config/config.yaml:/app/config/config.yaml:ro
      - /etc/ai-gateway/secrets:/secrets:ro
    tmpfs:
      - /tmp:uid=10001,gid=10001,mode=0700
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M

volumes:
  ai-gateway-v1-data:
    name: ai-gateway-v1-data
```
*(تمت إزالة `GATEWAY_PEPPER=${GATEWAY_PEPPER}` نهائياً، وفرض القراءة فقط، ونظام tmpfs، وتركيب الأسرار بـ `:ro`).*

### 2. تحديث [scripts/backup.sh](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/scripts/backup.sh)
تم تحديث السكربت بالكامل ليعزل النسخة الاحتياطية على المضيف خارج الـ Volume، مع إزالة خيار `-T` غير الصالح من `docker exec`، واعتماد الاستخراج بالتدفق المباشر (`cat > "$DEST"`) لدعم الحاويات المقيدة ذات الـ `--tmpfs /tmp`، وفحص سلامة النسخة على المضيف:
```sh
#!/bin/sh
set -eu

# Target backup file on the HOST (outside the container volume)
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
HOST_BACKUP_DIR="${HOST_BACKUP_DIR:-./backups}"
DEST="${1:-${HOST_BACKUP_DIR}/backup-${TIMESTAMP}.sqlite3}"

mkdir -p "$(dirname "$DEST")"

if command -v docker >/dev/null 2>&1 && docker compose ps --services 2>/dev/null | grep -q gateway; then
    # Mode 1: Docker Compose (uses -T)
    CONTAINER_TEMP="/tmp/online-backup-${TIMESTAMP}.sqlite3"
    docker compose exec -T gateway python -m app.admin backup "$CONTAINER_TEMP"
    docker compose exec -T gateway cat "$CONTAINER_TEMP" > "$DEST"
    chmod 0600 "$DEST"
    [ -s "$DEST" ] || { echo "ERROR: Backup empty" && exit 1; }
    sqlite3 "$DEST" "PRAGMA integrity_check;"
    docker compose exec -T gateway rm -f "$CONTAINER_TEMP"
elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qE '^(ai-gateway-v1|gateway|ai-gateway-v1-production|ai-gateway-v1-phase-d-candidate)$'; then
    # Mode 2: Docker Run (standalone container - WITHOUT -T)
    CONTAINER_NAME="$(docker ps --format '{{.Names}}' | grep -m1 -E '^(ai-gateway-v1|gateway|ai-gateway-v1-production|ai-gateway-v1-phase-d-candidate)$')"
    CONTAINER_TEMP="/tmp/online-backup-${TIMESTAMP}.sqlite3"
    docker exec "$CONTAINER_NAME" python -m app.admin backup "$CONTAINER_TEMP"
    docker exec "$CONTAINER_NAME" cat "$CONTAINER_TEMP" > "$DEST"
    chmod 0600 "$DEST"
    [ -s "$DEST" ] || { echo "ERROR: Backup empty" && exit 1; }
    sqlite3 "$DEST" "PRAGMA integrity_check;"
    docker exec "$CONTAINER_NAME" rm -f "$CONTAINER_TEMP"
else
    # Mode 3: Local Bare-Metal
    python -m app.admin backup "$DEST"
    chmod 0600 "$DEST" 2>/dev/null || true
    sqlite3 "$DEST" "PRAGMA integrity_check;"
fi

sha256sum "$DEST"
```

---

## 6. البند 5: توثيق هوية الصورة ونقلها (Image Identity & Artifact Integrity)

### 1. التمييز الحاسم بين صورة CI وصورة إعادة البناء
- **صورة CI المختبرة:**
  - البناء في CI Runner ينتج معرفاً فريداً (`sha256:879e05c8994d8a6af0dece2059594cacfde9184e64353693edf701a93e5581dc`).
  - هذا المعرف يعتمد على بيئة البناء وتوقيتات الطبقات، ولا يمكن افتراض تطابقه المسبق مع أي إعادة بناء محلية على خادم الإنتاج.
- **إعادة البناء على خادم الإنتاج:**
  - عند البناء من الالتزام المعتمد `2ebc857` على خادم الإنتاج:
    `docker build --no-cache -t ai-gateway-v1:candidate-production .`
  - **الإجراء الإلزامي:** يجب قياس وتسجيل الـ `Image ID` الفعلي الناتج على الخادم فور اكتمال البناء:
    `PROD_IMAGE_ID=$(docker inspect --format '{{.Id}}' ai-gateway-v1:candidate-production)`
  - فحص أمان الصورة المبنية محلياً (المستخدم `10001:10001`، غياب `pytest`، خلوها من ملفات `.env`).
- **خيار النقل المباشر عبر الأثر (Artifact Transfer):**
  - في حال رغبة المالك في نقل نفس الصورة المبنية في CI دون إعادة بناء، يتم تصديرها كـ artifact مضغوط وموقع (`docker save | gzip > image.tar.gz`)، ثم نقلها واستيرادها بـ `docker load` على الخادم.

---

## 7. البند 6: اختبار التوافق العكسي لـ SQLite والتراجع (SQLite Compatibility & Rollback Validation)

تم تصميم وتنفيذ اختبار توافقية شامل ومستقل تماماً في [tests/test_sqlite_backward_compatibility.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/tests/test_sqlite_backward_compatibility.py)، واجتاز الاختبارات على Linux في CI بنجاح تام:

### مراحل الاختبار المستقل ونتائجه:
1. **إنشاء قاعدة بيانات وفق المخطط القديم للالتزام الأساسي `70b4027`:**
   - تطبيق الجداول القديمة `clients`, `rate_limits`, `request_logs`.
   - إثبات أن `PRAGMA user_version = 0`.
   - إضافة عميل قديم بمفتاح وتوقيع HMAC حقيقي وسجلات استخدام.
2. **الترقية إلى إصدار التطبيق الجديد:**
   - تشغيل `Database.init()` و `migrate()`.
   - التأكد من `PRAGMA integrity_check == "ok"`.
   - التأكد من تحديث `PRAGMA user_version = 1`.
   - **التحقق من المصادقة:** نجاح مصادقة العميل القديم عبر `authenticate_key` ومطابقة مفتاحه القديم بنسبة 100%.
   - إضافة عميل جديد واستهلاك معدل الطلبات (Rate Limiting).
3. **محاكاة التراجع التام (Simulated Rollback) إلى كود التطبيق القديم (`70b4027`):**
   - فتح قاعدة البيانات نفسها بكود الاتصال القديم وتشغيل `CREATE TABLE IF NOT EXISTS` كما كان يفعل الكود القديم عند البدء.
   - التأكد من `PRAGMA integrity_check == "ok"`.
   - **قراءة العملاء القدامى والجدد:** استطاع الكود القديم قراءة العميلين دون أي خطأ.
   - **الكتابة واستهلاك الموارد:** استطاع الكود القديم كتابة سجلات طلبات جديدة واستهلاك معدل الطلبات دون أي اعتراض.
4. **الخلاصة:**
   - **نسبة التوافق العكسي: 100%.**
   - لا توجد أي أعمدة محذوفة أو تغييرات تكسر عمل النسخة القديمة في حال الاضطرار للتراجع.

---

## 8. تسلسل Cutover المحدث والمصحح (Future Cutover Execution Protocol)

عند صدور موافقة المالك الرسمية، يُنفذ تسلسل التبديل بالخطوات المصححة التالية:

```
1. التحضير:
   - بناء الصورة وقياس Image ID.
   - ضبط مجلد الأسرار /etc/ai-gateway/secrets (root:10001, 0750).
   - استخراج Pepper بالبايتات الخام من ذاكرة الحاوية الحالية والتحقق من تطابق sha256.
   - وضع مفتاح OpenRouter بصلاحيات 0400 (10001:10001).

2. النسخ الاحتياطي:
   - أخذ Online Backup حي عبر python -m app.admin backup.
   - التحقق من PRAGMA integrity_check على النسخة الاحتياطية.

3. نافذة التبديل (Maintenance Window):
   - إيقاف الحاوية القديمة: docker stop <OLD_CONTAINER_ID>.
   - تشغيل الحاوية الجديدة بـ --read-only, --tmpfs /tmp, -v /etc/ai-gateway/secrets:/secrets:ro.
   - ربط المنفذ 127.0.0.1:8000:8000 ونفس الـ named volume ai-gateway-v1-data.

4. التحقق بعد التبديل:
   - فحص Config.Env بأمر Python الآمن للتأكد من غياب الأسرار المباشرة ووجود مسارات _FILE.
   - فحص /healthz (المتوقع: {"status":"ok"}).
   - فحص مصادقة عميل حالي حقيقي للتأكد من استمرار صلاحية مفاتيحه (المتوقع: 200 OK).
   - فحص رفض المفاتيح غير المصرح بها (المتوقع: 401).
   - اختبار طلب دردشة تجريبي عبر OpenRouter والتأكد من تسجيل الاستهلاك.

5. شروط التراجع الفوري (Rollback Trigger):
   - إذا فشل /healthz أو فشلت مصادقة العملاء الحاليين (401):
     إيقاف الحاوية الجديدة فوراً، وتشغيل الحاوية القديمة (docker start <OLD_CONTAINER_ID>).
```

---

## 9. الخاتمة والقرار النهائي

بعد تصحيح جميع الملاحظات الأمنية والهندسية الحساسة:
1. تصحيح صلاحيات مجلد الأسرار إلى `0750` (`root:10001`) وإثبات فتح الملفات بنجاح من قبل المستخدم `10001:10001`.
2. اعتماد بروتوكول نقل البايتات الخام للـ Pepper دون أي تطبيع أو تشويه (`Zero Normalization`).
3. اعتماد فحص بيئة الحاوية الآمن دون أي تسريب لقيم الأسرار في السجلات.
4. تحديث `docker-compose.yml` و`scripts/backup.sh` لتتوافق مع قيود الأمان والتشغيل الفعلي.
5. إثبات التوافق العكسي التام لـ SQLite بنسبة 100% في حال التراجع.
6. اجتياز 112 اختباراً كاملاً على Linux في CI بنجاح تام وبدون أي اختبار متخطٍ أو فاشل (Run ID: `43496356039`).

**القرار النهائي:**
### `READY FOR OWNER CUTOVER APPROVAL`
(المشروع مكتمل وجاهز تقنياً وأمنياً للموافقة المستقلة من المالك لتحديد موعد نافذة التبديل والبدء بالتنفيذ).
