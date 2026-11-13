# AI Gateway V1 — Final Deployment Review

**التاريخ:** 13 نوفمبر 2026  
**الفرع المعتمد للمراجعة:** `audit/2026-11-13-c1`  
**الالتزام الأساسي:** `f98c189`  
**الالتزام المعتمد والمختبر في CI:** `4d95c42`  
**التزام التوثيق الحالي (HEAD):** `644a7a5`  
**معرف تشغيل التحقق في GitHub Actions:** `43485604249`  
**معرف الصورة المرشحة (Candidate Image ID):** `sha256:2669c6e366535796ec0420f0139f83eab59ef60a81d0a3aa2505da1568d61fe7`  
**القرار النهائي:** `READY FOR OWNER CUTOVER APPROVAL`

---

## 1. جدول التقييم التنفيذي لمعايير النشر

| المعيار | التقييم | الملاحظات والأدلة |
| :--- | :---: | :--- |
| **A. اعتماد مصدر الصورة وتطابق الكود** | **PASS** | الكود البرمجي في HEAD مطابق تماماً لـ `4d95c42` بنسبة 100%، وتم إثبات عدم تغيير أي سطر تطبيقي. |
| **B. مراجعة إعدادات التشغيل والحاوية** | **PASS** | تم تحديد الفروق بين الإعداد القديم والمرشح، وفرض عزل الذاكرة ونظام الملفات للقراءة فقط. |
| **C. خطة نقل الأسرار وحفظ الـ Pepper** | **PASS** | تصميم إجراء نقل بايت ببايت يمنع إبطال مفاتيح العملاء، واستبعاد الأسرار تماماً من `Config.Env`. |
| **D. خطة النسخ الاحتياطي وتوافق SQLite** | **PASS** | التحقق من التوافق العكسي لمخطط SQLite (Version 1)، وتصميم آلية Online Backup بـ `integrity_check`. |
| **E. تسلسل Cutover وشروط التراجع** | **PASS** | خطوات تشغيلية محددة تمنع تشغيل نسختين على نفس الحجم وتحدد معايير Rollback الفورية. |
| **جاهزية الإنتاج التقنية** | **PASS** | صفر منافذ مفتوحة محلياً، لا مساس ببيئة الإنتاج، واجتياز 103 اختبارات Linux بنجاح تام. |

---

## 2. البند A: اعتماد مصدر الصورة (Image Source Verification)

### 1. الالتزام المصدري (Git SHA)
- **الالتزام الذي بُنيت منه الصورة واختُبرت في CI:**  
  `4d95c423d7be34f2d80d28747a06d0ba416c11fc` (`4d95c42`)  
  *رسالة الإيداع:* `ci: fix client_id extraction and revoke assertion in container isolation step`
- **مقارنة الالتزام المختبر مع HEAD الحالي (`644a7a5`):**  
  تم إجراء فحص فوارق دقيق عبر:
  ```bash
  git diff 4d95c42..HEAD --stat
  git diff 4d95c42..HEAD -- app/ config/ Dockerfile requirements.lock .dockerignore
  ```
  **الدليل القاطع:** ناتج فحص مجلدات التطبيق والإعدادات وملفات البناء **فارغ تماماً (Zero Diff)**. التغيير الوحيد بين `4d95c42` و `HEAD` هو إضافة ملف التوثيق [PHASE_D_LINUX_CI_VALIDATION.md](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/PHASE_D_LINUX_CI_VALIDATION.md).

### 2. هوية الصورة وبصمتها (Image ID & Digest)
- **اسم الوسم المرشح في CI:** `ai-gateway-v1:phase-d-linux-candidate`
- **معرف الصورة (Image ID):**  
  `sha256:2669c6e366535796ec0420f0139f83eab59ef60a81d0a3aa2505da1568d61fe7`
- **حجم الصورة:** `144,697,595 bytes` (~137.99 MB).
- **المستخدم الافتراضي داخل الصورة:** `10001:10001` (gateway non-root).

### 3. نقل الصورة إلى خادم الإنتاج وإعادة البناء الحتمي
الصورة التي بُنيت في بيئة GitHub Actions Runner لا تنتقل تلقائياً إلى خادم الإنتاج. ولضمان عدم الاعتماد على وسوم مجهولة المصدر:
- **إجراء إعادة البناء الحتمي على خادم الإنتاج:**
  ```bash
  # 1. جلب الالتزام المعتمد
  git fetch origin audit/2026-11-13-c1
  git checkout 4d95c42

  # 2. بناء الصورة محلياً على خادم الإنتاج دون الاعتماد على الكاش
  docker build --no-cache -t ai-gateway-v1:candidate-4d95c42 .

  # 3. التحقق من هوية الصورة والمستخدم
  IMAGE_ID=$(docker inspect ai-gateway-v1:candidate-4d95c42 --format '{{.Id}}')
  USER_ID=$(docker inspect ai-gateway-v1:candidate-4d95c42 --format '{{.Config.User}}')
  echo "Built Image ID: $IMAGE_ID"
  echo "Image User: $USER_ID"
  ```
- **حظر قطعي:** عدم تعديل أو استبدال الصورة القديمة `ai-gateway-v1:local` حتى صدور قرار المالك الرسمي.

---

## 3. البند B: مراجعة إعداد التشغيل الفعلي (Runtime Configuration Review)

تمت مقارنة معايير تشغيل الحاوية القديمة مقابل معايير الحاوية المرشحة للنشر:

| خاصية التشغيل | الحاوية الحالية (Baseline) | الحاوية المرشحة (Candidate) | التقييم الأمني والتشغيلي |
| :--- | :--- | :--- | :--- |
| **Image ID** | مبنية من `70b4027` | `sha256:2669c6e366...` (من `4d95c42`) | **ترقية إلزامية** لإغلاق الثغرات |
| **Port Binding** | `127.0.0.1:8000:8000` | `127.0.0.1:8000:8000` | **مطابق وصارم** (منع التعرض لـ LAN) |
| **Network Mode** | Docker Bridge افتراضي | Docker Bridge مخصص ومقيد | **تحسين** لعزل شبكة الحاوية |
| **Restart Policy** | `unless-stopped` | `unless-stopped` | **مطابق** لاستقرار الخدمة |
| **User** | `10001:10001` | `10001:10001` | **مطابق** (Non-root user) |
| **ReadonlyRootfs** | `false` (نظام ملفات قابل للكتابة) | `true` (`--read-only`) | **ترقية أمنية جوهرية** لمنع التعديل |
| **Capabilities** | غير محددة أو جزئية | `CapDrop: ["ALL"]` | **ترقية أمنية** لإسقاط كامل الصلاحيات |
| **NoNewPrivileges** | `true` | `true` | **مطابق** لمنع تصعيد الصلاحيات |
| **Resource Limits** | غير محددة (خطر استنزاف الذاكرة) | `memory: 512m`, `cpus: 1.0`, `pids: 100` | **ترقية استقرار** لمنع DoS على المضيف |
| **Data Mount** | `ai-gateway-v1-data:/data` | `ai-gateway-v1-data:/data` | **مطابق** للحفاظ على قاعدة البيانات |
| **tmpfs Mounts** | غير موجودة | `/tmp` (`mode=0700,uid=10001`) | **إلزامي** لتمكين `--read-only` |
| **Secrets Exposure** | محقونة في `Config.Env` | ملفات `:ro` بصلاحيات `0400` | **ترقية أمنية حرجة** (F-002) |

### أمر فحص metadata الحاوية الحالية على خادم الإنتاج (دون كشف الأسرار):
```bash
docker inspect <CURRENT_CONTAINER_ID> --format '
Image: {{.Image}}
Ports: {{json .HostConfig.PortBindings}}
NetworkMode: {{.HostConfig.NetworkMode}}
RestartPolicy: {{json .HostConfig.RestartPolicy}}
User: {{.Config.User}}
ReadonlyRootfs: {{.HostConfig.ReadonlyRootfs}}
CapDrop: {{json .HostConfig.CapDrop}}
SecurityOpt: {{json .HostConfig.SecurityOpt}}
Memory: {{.HostConfig.Memory}}
NanoCpus: {{.HostConfig.NanoCPUs}}
PidsLimit: {{.HostConfig.PidsLimit}}
Mounts: {{json .Mounts}}
'
```
*(ملاحظة أمنية: تم استبعاد `Config.Env` من صيغة الأمر لمنع تسريب الأسرار إلى الشاشة أو السجلات).*

---

## 4. البند C: خطة نقل الأسرار (Secret Migration Plan)

لضمان استمرار عمل جميع مفاتيح العملاء الحالية دون انقطاع وتفادي رفض الطلبات بـ `401 Unauthorized`، تم تصميم الإجراء التالي لنقل سر Pepper ومفتاح OpenRouter:

### 1. نقل Pepper الإنتاجي بايتاً ببايت (Byte-for-Byte Integrity)
إن إضافة أي رمز غير مرئي مثل سطر جديد (`\n` أو `\r\n`) أو مسافة سيغير تجزئة HMAC بالكامل ويُبطل مفاتيح العملاء الحالية فورياً:
```bash
# إنشاء مجلد الأسرار المحمي على خادم المضيف
sudo mkdir -p /etc/ai-gateway/secrets
sudo chmod 0700 /etc/ai-gateway/secrets

# استخراج القيمة الحالية من ملف .env الحالي بدقة تامة وبدون سطر إضافي:
grep '^GATEWAY_PEPPER=' /path/to/prod/.env | cut -d'=' -f2- | tr -d '\r\n' | sudo tee /etc/ai-gateway/secrets/pepper > /dev/null

# ضبط الملكية والصلاحيات الصارمة لـ UID 10001
sudo chown 10001:10001 /etc/ai-gateway/secrets/pepper
sudo chmod 0400 /etc/ai-gateway/secrets/pepper

# التحقق من التطابق التام عبر مقارنة بصمة sha256 دون طباعة السر:
SRC_HASH=$(grep '^GATEWAY_PEPPER=' /path/to/prod/.env | cut -d'=' -f2- | tr -d '\r\n' | sha256sum | awk '{print $1}')
DST_HASH=$(sudo sha256sum /etc/ai-gateway/secrets/pepper | awk '{print $1}')
if [ "$SRC_HASH" != "$DST_HASH" ]; then
    echo "ERROR: Pepper hash mismatch! Aborting." && exit 1
else
    echo "VERIFIED: Pepper migrated byte-for-byte successfully."
fi
```

### 2. نقل مفتاح OpenRouter إلى ملف مستقل
```bash
# إدخال المفتاح تفاعلياً دون حفظه في سجل الأوامر (history)
echo -n "Enter OpenRouter API Key: "
read -s OPENROUTER_TOKEN
echo ""
echo -n "$OPENROUTER_TOKEN" | sudo tee /etc/ai-gateway/secrets/openrouter_key > /dev/null
unset OPENROUTER_TOKEN

sudo chown 10001:10001 /etc/ai-gateway/secrets/openrouter_key
sudo chmod 0400 /etc/ai-gateway/secrets/openrouter_key
```

### 3. عزل متغيرات البيئة في Docker Config.Env
- تُحقن المسارات فقط عبر متغيرات البيئة:
  ```env
  GATEWAY_PEPPER_FILE=/secrets/pepper
  OPENROUTER_API_KEY_FILE=/secrets/openrouter_key
  ```
- **حظر قطعي:** يمنع منعاً باتاً وجود `GATEWAY_PEPPER` أو `OPENROUTER_API_KEY` كمتغيرات صريحة.
- **التحقق:**
  ```bash
  docker inspect <CONTAINER_ID> --format '{{json .Config.Env}}' | grep -E 'sk-|openrouter' && echo "LEAK DETECTED" || echo "CLEAN"
  ```

---

## 5. البند D: النسخ الاحتياطي والتراجع (Backup & Rollback)

### 1. التحقق من النسخة القديمة
- أثبت التدقيق في Claim A8 أن ملف `scripts/backup.sh` لم يكن موجوداً أصلاً في الالتزام الأساسي `70b4027`، ولم تكن هناك نسخة احتياطية سابقة محفوظة في مستودع Git. أي نسخ سابقة أنشأها المشغل يدوياً يجب التحقق من موقعها وبصمتها قبل التبديل.

### 2. إجراء أخذ Online Backup حي قبل الـ Cutover
يتم تنفيذ النسخ الاحتياطي عبر واجهة SQLite الرسمية والآمنة لتفادي تلف ملفات WAL:
```bash
# إنشاء مجلد النسخ الاحتياطي المؤرخ
BACKUP_DIR="/var/backups/ai-gateway/$(date +%Y%m%d)"
sudo mkdir -p "$BACKUP_DIR"
sudo chmod 0700 "$BACKUP_DIR"

# تشغيل النسخ الحي من داخل الحاوية الحالية قبل إيقافها:
docker exec <CURRENT_CONTAINER_ID> python -m app.admin backup /data/backups/pre-cutover.sqlite3

# نقل ملف النسخة الاحتياطية إلى مضيف الإنتاج:
docker cp <CURRENT_CONTAINER_ID>:/data/backups/pre-cutover.sqlite3 "$BACKUP_DIR/pre-cutover.sqlite3"

# التحقق من سلامة النسخة الاحتياطية وصحة الجداول:
sqlite3 "$BACKUP_DIR/pre-cutover.sqlite3" "PRAGMA integrity_check;"
# الناتج الإلزامي: ok

# فحص عدد العملاء وسجلات الاستخدام:
sqlite3 "$BACKUP_DIR/pre-cutover.sqlite3" "SELECT count(*) FROM clients; SELECT count(*) FROM request_logs;"
```

### 3. تحليل توافق مخطط SQLite وقابلية التراجع (Schema Backward Compatibility)
- في الالتزام الأساسي `70b4027`، كانت الجداول المنشأة هي: `clients`, `rate_limits`, `request_logs` مع `PRAGMA user_version = 0`.
- في الالتزام المعتمد الجديد (F-010 في `app/database.py`):
  - تم تعريف نظام ترحيلات ذكي:
    ```python
    current_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    has_tables = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='clients'").fetchone()[0] > 0
    if current_version == 0 and has_tables:
        current_version = 1
        conn.execute("PRAGMA user_version = 1")
    ```
  - المخطط الجديد لم يحذف أي عمود، ولم يغيّر أسماء الجداول، ولم يضف قيوداً تمنع قراءة الإصدار القديم.
  - **النتيجة:** الكود القديم يعمل مباشرة وبشكل متوافق 100% مع قاعدة البيانات حتى بعد تعيين `user_version = 1`، لأن الكود القديم يعتمد على `CREATE TABLE IF NOT EXISTS` ولا يتحقق من رقم الإصدار.

### 4. حظر تشغيل نسختين على نفس الحجم (Zero Concurrency Rule)
- **قاعدة قطعية:** يُمنع تشغيل الحاوية القديمة والحاوية الجديدة في نفس اللحظة وهما مرتبطتان بالحجم `ai-gateway-v1-data`. ذلك يؤدي إلى تضارب أقفال SQLite WAL locking وتلف محتمل لقاعدة البيانات.

---

## 6. البند E: تسلسل النشر المقترح (Proposed Cutover Sequence)

عند موافقة المالك المستقلة، يتم اتباع الخطوات التالية بالتسلسل الدقيق:

```
[Phase 1: التحضير]  --->  [Phase 2: النسخ الاحتياطي]  --->  [Phase 3: الإيقاف والتبديل]  --->  [Phase 4: التحقق الأمني]
  - بناء الصورة           - أخذ online backup             - إيقاف الحاوية القديمة          - فحص healthz
  - فحص أذونات الأسرار    - فحص integrity_check            - تشغيل الحاوية الجديدة          - فحص مفاتيح العملاء
                                                          - نفس named volume              - فحص استجابة OpenRouter
```

### الخطوات التفصيلية:
1. **نافذة الصيانة والتجهيز:**
   - التأكد من جاهزية ملفات الأسرار والإعدادات:
     - `/etc/ai-gateway/secrets/pepper` (`0400`)
     - `/etc/ai-gateway/secrets/openrouter_key` (`0400`)
     - `/etc/ai-gateway/config.yaml` (`0644`)
2. **النسخ الاحتياطي الفوري:**
   - تنفيذ أمر النسخ الاحتياطي والتأكد من نتيجة `integrity_check` كما ورد في البند D.
3. **إيقاف الحاوية القديمة:**
   ```bash
   docker stop <CURRENT_CONTAINER_ID>
   ```
4. **تشغيل الحاوية الجديدة المرشحة بالصورة المعتمدة:**
   ```bash
   docker run -d \
     --name ai-gateway-v1-production \
     --restart unless-stopped \
     -p 127.0.0.1:8000:8000 \
     --user 10001:10001 \
     --read-only \
     --cap-drop ALL \
     --security-opt no-new-privileges \
     --memory 512m \
     --cpus 1.0 \
     --pids-limit 100 \
     --tmpfs /tmp:uid=10001,gid=10001,mode=0700 \
     -v ai-gateway-v1-data:/data \
     -v /etc/ai-gateway/secrets:/secrets:ro \
     -v /etc/ai-gateway/config.yaml:/app/config/config.yaml:ro \
     -e GATEWAY_CONFIG=/app/config/config.yaml \
     -e GATEWAY_PEPPER_FILE=/secrets/pepper \
     -e OPENROUTER_API_KEY_FILE=/secrets/openrouter_key \
     ai-gateway-v1:candidate-4d95c42
   ```
5. **التحقق التشغيلي والمصادقة (Post-Cutover Smoke Tests):**
   - فحص نقطة الصحة:
     ```bash
     curl -fsS http://127.0.0.1:8000/healthz
     # المتوقع: {"status":"ok"}
     ```
   - فحص مصادقة عميل قائم بمفتاحه الفعلي:
     ```bash
     curl -i -H "Authorization: Bearer gw_<CLIENT_KEY>" http://127.0.0.1:8000/v1/models
     # المتوقع: 200 OK وقائمة النماذج المعرفة (fast)
     ```
   - فحص رفض مفتاح غير صالح:
     ```bash
     curl -i -H "Authorization: Bearer gw_invalid_key" http://127.0.0.1:8000/v1/models
     # المتوقع: 401 Unauthorized
     ```
   - اختبار طلب دردشة تجريبي عبر OpenRouter:
     ```bash
     curl -i -H "Authorization: Bearer gw_<CLIENT_KEY>" \
       -H "Content-Type: application/json" \
       -d '{"model":"fast","messages":[{"role":"user","content":"ping"}]}' \
       http://127.0.0.1:8000/v1/chat/completions
     # المتوقع: 200 OK مع استجابة مكتملة وتسجيل الـ usage
     ```
6. **إجراء التراجع الطارئ (Rollback Plan):**
   - في حال حدوث أي خطأ في فحص الصحة أو رفض مفاتيح العملاء (عدم تطابق Pepper):
     ```bash
     echo "TRIGGERING IMMEDIATE ROLLBACK..."
     docker stop ai-gateway-v1-production
     docker rm ai-gateway-v1-production
     # إعادة تشغيل الحاوية القديمة:
     docker start <CURRENT_CONTAINER_ID>
     curl -fsS http://127.0.0.1:8000/healthz
     ```

---

## 7. المخاطر المتبقية وإجراءات التخفيف (Residual Risks)

| الخطر المتبقي | الاحتمالية / الأثر | إجراء التخفيف المعتمد |
| :--- | :---: | :--- |
| **خطأ بشري في نسخ الـ Pepper** | منخفض / حرج | استخدام فحص `sha256sum` التلقائي المبرمج قبل إيقاف الحاوية القديمة. |
| **تغيير في صيغة استجابات OpenRouter** | منخفض / متوسط | تغليف الاستجابة بـ Safe Response Validation والحد الأقصى لحجم الاستجابة (F-009). |
| **انقطاع شبكة المزود الخارجي** | متوسط / منخفض | إرجاع خطأ قياسي 502 دون تسريب بيانات أو مفاتيح، مع تفعيل Fallback تلقائي لمزود بديل. |
| **تعارض منافذ المضيف 8000** | منخفض / منخفض | تم التحقق مسبقاً من حصر الاستماع على `127.0.0.1` وخلو المضيف من أي تعارض. |

---

## 8. الخاتمة والقرار النهائي

استوفت البوابة المرشحة كافة المعايير الهندسية والأمنية:
1. إغلاق الثغرات الأمنية السابقة (F-001 إلى F-010) بشكل قطعي ومثبت بالاختبارات.
2. اجتياز جميع اختبارات Linux (103 اختبارات) دون تخطي، بما فيها أذونات POSIX للأسرار، وحماية SSRF المتقدمة، وتثبيت مقابس الاتصال.
3. جاهزية كاملة لخطة نقل الأسرار والنسخ الاحتياطي والتراجع دون أي مخاطرة ببيانات الإنتاج.

**القرار النهائي:**
### `READY FOR OWNER CUTOVER APPROVAL`
(المشروع في حالة استقرار تام وجاهز لصدور موافقة المالك المستقلة لتحديد موعد نافذة التبديل والبدء بالتنفيذ).
