# AI Gateway V1

بوابة محلية خفيفة بواجهة متوافقة مع OpenAI، مبنية على FastAPI وSQLite. ملفات المشروع واختباراته جاهزة، لكن **لم تُشغّل الخدمة عبر Compose**: أمر `docker compose` غير مثبت في بيئة التنفيذ الحالية. لم يُفتح أي منفذ، ولم يُفعّل نفق أو رابط معاينة.

## ما الذي يفعله الإصدار

يدعم `/healthz`، و`/v1/models`، و`/v1/chat/completions` بنمط عادي أو SSE. يتضمن مفاتيح عملاء عشوائية، تخزين HMAC-SHA-256 مع Pepper، إلغاءً فوريًا للمفتاح، حدًا لكل عميل في الدقيقة مخزنًا في SQLite، محاولتين كحد أقصى للتراجع إلى مزود تالٍ عند أخطاء محددة، وتسجيلًا آمنًا للبيانات الوصفية والاستخدام من دون نصوص الرسائل أو مفاتيح API.

لا توجد مزودات أو معرفات نماذج مفعّلة افتراضيًا؛ لم تُختبر بيانات اعتماد مزود حقيقي. أضف نقطة OpenAI-compatible ومعرّف نموذج حقيقيًا إلى `config/config.yaml`، واجعل alias مفعّلًا، ومرّر اسم متغير المفتاح في إعداد المزود. ضع المفتاح نفسه في `.env`، ولا تضعه في ملف التكوين أو سجل الأدلة. مثال placeholders موجود في `config/config.example.yaml` ويظل معطلًا.

## التثبيت والتشغيل بعد توافر Docker Compose

نفّذ الأوامر التالية منفصلة وبالترتيب:

1. أنشئ Pepper محليًا؛ لا تُعرض قيمته على الشاشة:

   ```sh
   ./scripts/init_env.sh
   ```

2. راجع مزوداتك ومعرّفات النماذج الفعلية في `config/config.yaml`، وأضف أسرارها إلى `.env` عند الحاجة. لا تفعّل مزودًا قبل التحقق من توافقه ووجهة مشاركة الطلبات.

3. افحص إعداد Compose؛ يجب أن يبقى نشر المضيف على `127.0.0.1:8000`:

   ```sh
   docker compose config
   ```

4. **لا تشغّل `docker compose up` بالنسخة الحالية.** ملف Compose يربط منفذ المضيف على loopback، لكن Uvicorn داخل الحاوية مضبوط على `0.0.0.0` ليتصل به Docker. هذا لا يطابق حرفيًا شرط ربط التطبيق نفسه على `127.0.0.1`، ويحتاج حسم التصميم قبل النشر.

5. افحص الصحة المحلية فقط:

   ```sh
   ./scripts/health_check.sh
   ```

يعرّف Compose ربط المضيف بصيغة `127.0.0.1:8000:8000`، بينما يستمع Uvicorn داخل واجهة شبكة الحاوية على `0.0.0.0`. لم يُشغّل هذا الإعداد. ربط التطبيق حرفيًا على `127.0.0.1` داخل حاوية bridge لا يتصل تلقائيًا بتحويل Docker؛ أي تغيير إلى host networking يقلل عزل الشبكة ويحتاج قرارًا منفصلًا. لم يُفتح منفذ عام أو يُفعّل نفق أو رابط معاينة.

## مفاتيح العملاء والإدارة

إنشاء المفتاح يعرض السر الخام مرة واحدة، لذا شغّله في جلسة محلية موثوقة واحفظ النتيجة في مدير أسرار:

```sh
docker compose exec -T gateway python -m app.admin create-key --name local-app --rpm 60
```

أرسل المفتاح إلى واجهة API كـ`Authorization: Bearer <key>`. لا تُضمّن المفتاح في سجلات أو أوامر محفوظة.

إلغاء مفتاح باستخدام `client_id` غير السري:

```sh
docker compose exec -T gateway python -m app.admin revoke-key <client_id>
```

سرد البيانات الوصفية أو الاستخدام، دون كشف المفاتيح:

```sh
docker compose exec -T gateway python -m app.admin list-clients
```

```sh
docker compose exec -T gateway python -m app.admin usage <client_id>
```

## الإدارة والمصادقة والتشفير (المرحلة الأولى)

- **أول مدير:** يُنشأ من سطر الأوامر فقط، ويُرفض إذا كان مدير موجودًا. تُقرأ كلمة المرور من الطرفية أو من stdin، ولا تُمرَّر كوسيط:

  ```sh
  python -m app.admin bootstrap-admin --username admin
  ```

- **واجهة الإدارة:** `POST /api/admin/login` و`POST /api/admin/logout` و`GET /api/admin/session` و`GET /api/admin/health` و`GET|POST /api/admin/ip-rules` و`DELETE /api/admin/ip-rules/{id}`. تُرسل الجلسة في كوكي `amnabd_admin_session` بخصائص `HttpOnly` و`Secure` و`SameSite=Lax` ومسار `/api/admin`. معرّف الجلسة الخام لا يظهر في JSON. كل طلب يغيّر البيانات يحتاج الرأس `X-CSRF-Token`. قيمة CSRF تُعاد من `GET /api/admin/session` أو من تسجيل الدخول، ولا تُخزَّن في Local Storage. كل استدعاء لـ `GET /api/admin/session` يستبدل القيمة السابقة.
- **الحد من تسجيل الدخول:** خمس محاولات فاشلة لكل IP خلال 15 دقيقة، ثم `429` مع `Retry-After`. تُحجز المحاولة في SQLite قبل فحص كلمة المرور لمنع تجاوز الحد بالطلبات المتزامنة.
- **قواعد IP:** تنطبق على كل مسارات `/api/admin` بما فيها الدخول. الرفض له أولوية على السماح. إذا وُجدت قاعدة سماح نشطة فلا يُسمح إلا بالعناوين المطابقة. يُرفض أي تعديل يحجب العنوان الحالي بالرمز `409`.
- **`TRUSTED_PROXIES`:** لا تُقرأ ترويسة `X-Forwarded-For` إلا إذا جاء الاتصال المباشر من عنوان مذكور في هذا الإعداد. السلسلة المشوهة من proxy موثوق تُرفض. الافتراضي فارغ.
- **`ADMIN_ALLOWED_ORIGINS`:** إذا كان الوسيط العكسي يغيّر المخطط أو المضيف الذي يراه المتصفح، فضع هنا أصل HTTPS الذي تستخدمه الواجهة. الطلبات التي تحمل `Origin` أو `Referer` من أصل آخر تُرفض.
- **الطوارئ (CLI محلي فقط):**

  ```sh
  python -m app.admin ip-rules list
  python -m app.admin ip-rules disable <id>
  python -m app.admin ip-rules delete <id>
  python -m app.admin ip-rules reopen
  python -m app.admin ip-rules clear --confirm DELETE-ALL-ADMIN-IP-RULES
  python -m app.admin disable-admin <username>
  python -m app.admin revoke-admin-sessions <username>
  ```

  كل عملية تُسجَّل في `audit_logs` بالمصدر `break-glass-cli`. لا توجد نقطة HTTP لهذه العمليات.
- **مفاتيح المزودين المشفّرة:** تُحفظ بـ AES-256-GCM. المفتاح الرئيسي من `GATEWAY_MASTER_KEY` أو `GATEWAY_MASTER_KEY_FILE`، ولا يُكتب في SQLite. تُقرأ القيمة من الطرفية أو stdin، والأوامر لا تعرض القيمة:

  ```sh
  python -m app.admin provider-secret set OPENAI_API_KEY
  python -m app.admin provider-secret list
  python -m app.admin provider-secret rotate
  python -m app.admin provider-secret delete OPENAI_API_KEY
  ```

  إذا وُجد مفتاح مخزَّن ومصدر env أو ملف للاسم نفسه، يفشل الطلب بشكل آمن ولا يُختار أحدهما.
- **حماية الاتصال بالمزودين:** يُسمح بـ HTTPS على المنفذ 443 فقط. تُرفض عناوين الـ metadata وlink-local وmulticast والعناوين غير المعيّنة، ولا يُتبع إعادة التوجيه، ولا تُستخدم proxies من متغيرات البيئة. العناوين الداخلية أو HTTP أو منفذ غير 443 تحتاج إلى `trusted_internal_networks` لذلك المزود فقط.
- **ترقية قاعدة البيانات:** قبل أول ترقية لقاعدة موجودة تُنسخ إلى `<database>.pre-schema-v<N>-<time>.bak` بصلاحيات `0600`. انسخ القاعدة يدويًا أيضًا قبل النشر.
- **متغيرات بيئة جديدة:** `TRUSTED_PROXIES`، `ADMIN_ALLOWED_ORIGINS`، `ADMIN_SESSION_TTL_SECONDS` (افتراضي 28800)، `ADMIN_SESSION_IDLE_SECONDS` (افتراضي 1800)، `ADMIN_LOGIN_MAX_FAILURES` (افتراضي 5)، `ADMIN_LOGIN_WINDOW_SECONDS` (افتراضي 900)، `GATEWAY_MASTER_KEY` أو `GATEWAY_MASTER_KEY_FILE`، `GATEWAY_MASTER_KEY_VERSION` (افتراضي 1)، و`GATEWAY_MASTER_KEY_PREVIOUS` أو `_FILE` مع `GATEWAY_MASTER_KEY_PREVIOUS_VERSION` أثناء التدوير فقط.

## الاختبارات والبيانات

توليد القفل يتضمن hashes لكل الحزم؛ يثبَّت باستخدام `--require-hashes`. الحزم المضافة في المرحلة الأولى (`argon2-cffi` و`cryptography` وتبعياتهما) نُشرت قبل 2026-11-01، وتم توليد القفل بالخيار `--exclude-newer 2026-11-01` مع تثبيت الإصدارات الموجودة كما هي. شغّل الاختبارات محليًا عبر:

```sh
.venv/bin/python -m pytest -q
```

قاعدة البيانات في حجم Docker المسمى `ai-gateway-v1-data`، مع WAL ونسخ احتياطي عبر `scripts/backup.sh`. فترة الاحتفاظ الافتراضية لسجلات البيانات الوصفية 30 يومًا. لا تُسجّل الرسائل أو مفاتيح العملاء الخام أو مفاتيح المزودين.

## الحالة في بيئة التنفيذ الحالية

- اجتازت اختبارات الوحدة والتكامل المحاكية: **21 passed**.
- لم يُختبر أي مزود حقيقي لأن إعداد المزود متروك عمدًا للمستخدم.
- `docker compose version` أعاد أن الأمر الفرعي `compose` غير معروف، ولا يوجد `docker-compose` أو plugin مثبت. لذلك لم يُنفّذ `docker compose config` أو `up`، ولم تُنشأ خدمة مستمرة أو منفذ محلي.
- يوجد قرار نشر غير محسوم: ربط مضيف loopback مع bind داخلي wildcard، أم host networking لربط حرفي على loopback مقابل عزل شبكي أقل. لم يُختر أحدهما أو يُفعّل.
- تقرير الأدلة: `evidence/final-report.md`. سجلات الأوامر والاختبارات الخام في `evidence/`.
