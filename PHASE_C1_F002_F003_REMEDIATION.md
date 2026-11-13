# تقرير معالجة الثغرات F-002 وF-003 — المرحلة C.1 (Phase C.1: Final F-002 / F-003 Hardening)

**تاريخ التقرير**: 2026-11-13  
**المستودع**: `ai-gateway-v1`  
**الفرع الأساسي (Base Branch)**: `audit/2026-11-13`  
**الالتزام الأساسي (Base Commit)**: `f98c1897d51d01e335b6501dd18a1ee24361f556`  
**فرع الإصلاح الجديد (Remediation Branch)**: `audit/2026-11-13-c1`  
**إيداع المعالجة**: `cec7f37` (`fix(F-002, F-003): exact allowlist for provider keys, canonical URL parsing, and DNS rebinding protection`)  

---

## 1. تصميم الحماية الشاملة (Security Architecture)

### أولاً: إغلاق F-002 (قائمة السماح الصريحة والمغلقة وربط المزودين)
1. **استبدال البادئات بقائمة سماح صريحة ومغلقة (Exact Closed Allowlist)**:
   - تم إلغاء `ALLOWED_KEY_PREFIXES` تماماً.
   - تعريف `APPROVED_PROVIDER_KEY_ENVS` كمجموعة مغلقة من الأسماء المعتمدة:
     `{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY", "AZURE_OPENAI_API_KEY", "TEST_PRIMARY_KEY", "TEST_SECONDARY_KEY", "TEST_PROVIDER_API_KEY", "MOCK_PROVIDER_API_KEY", "TEST_KEY"}`.
   - أي اسم لا ينتمي لهذه القائمة يُرفض فوراً بـ `ValueError` حتى لو بدأ ببادئة معروفة مثل `OPENAI_` أو `PROVIDER_` (مثل `OPENAI_RANDOM_UNAPPROVED_VAR` أو `PROVIDER_CUSTOM_TOKEN`).
2. **ربط كل مزود بمفاتيحه المعتمدة (Provider-Key Binding)**:
   - تم إنشاء جدول تعيين صريح `PROVIDER_KEY_ENV_MAP` (مثال: مزود `openai` لا يقبل إلا `OPENAI_API_KEY`؛ مزود `anthropic` لا يقبل إلا `ANTHROPIC_API_KEY`؛ محاولات الخلط تُرفض بـ `ValueError`).
3. **دعم صيغة `_FILE` وحظر التعارض (Dual Source Conflict Rejection)**:
   - قبول أسماء الملفات المقابلة مثل `OPENAI_API_KEY_FILE` وربطها بالاسم الأساسي عبر تجريد اللاحقة `_FILE` عند الفحص.
   - التحقق الصارم عبر `secret_loader`: إذا وُجد المصدر المباشر ومصدر الملف معاً في البيئة في آنٍ واحد، يفشل الطلب مغلقاً فوراً (`SecretLoadError`) دون تراجع.
4. **ضمان عدم إرسال طلبات (MockTransport Verification)**:
   - عند محاولة تمرير أي متغير غير معتمد أو عند حدوث تعارض، يفشل الطلب في مرحلة الإعداد (`404` أو `503`) قبل إرسال أي بايت للشبكة، مع التحقق الحتمي بأن `transport_called == False`.

---

### ثانياً: إغلاق F-003 (حماية SSRF الشاملة وتثبيت الاتصال لمنع DNS Rebinding)
تم بناء وحدة أمنية مخصصة ومستقلة [app/ssrf.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/app/ssrf.py) تعمل على مستويين: مستوى التحليل القياسي، ومستوى طبقة النقل الشبكي:

1. **التحليل القياسي الصارم للعناوين (URL Canonicalization)**:
   - **بروتوكول HTTPS فقط**: فرض `https://` ورفض `http://`.
   - **حظر بيانات المستخدم (userinfo)**: رفض العناوين التي تحتوي على `user:pass@host`.
   - **حظر المعاملات والمحددات**: رفض `?query` و`#fragment`.
   - **حظر العناوين المحلية والنطاقات الداخلية**: حظر `localhost` والنطاقات المنتهية بـ `.localhost`, `.local`, `.internal`, `.lan`, `.home`, `.corp`.
   - **حظر معرفات النطاق (Zone Identifiers)**: رفض أي عنوان يحتوي على `%` لمنع هجمات IPv6 Scoped Addresses.
   - **حظر الصيغ غير القياسية للـ IP (Non-standard IP Representations)**:
     - رفض العناوين الرقمية الصحيحة المباشرة (Decimal Integer IP مثل `2130706433`).
     - رفض العناوين ذات البادئات الثمانية (Octal مثل `0177.0.0.1`) أو الست عشرية (Hex مثل `0x7f000001`) أو المشتملة على أصفار بادئة في أجزائها.
     - رفض صيغ الاختصار (Shorthand مثل `127.1`).
   - **حظر العناوين الخاصة والمحجوزة**: التحقق من فئات IP الخاصة (RFC 1918), وLoopback, وLink-Local (`169.254.0.0/16`), وMulticast, وReserved, وIPv6 ULA (`fc00::/7`), وIPv4-mapped IPv6 الداخلية (`::ffff:127.0.0.1`, إلخ).

2. **الأمان في حل DNS وتثبيت الاتصال (DNS Resolution Safety & IP Pinning)**:
   - يتم حل كافة سجلات A وAAAA للهدف عبر `SafeSSRFNetworkBackend._resolve`.
   - **قاعدة الرفض المطلق (Fail-Closed)**: يتم فحص **كل** عنوان IP مُعاد في استجابة DNS؛ إذا وُجد عنوان داخلي أو خاص أو محلي واحد ضمن المجموعة، يُلغى الاتصال فوراً بـ `httpcore.ConnectError` دون محاولة اختيار عنوان آخر من المجموعة المختلطة.
   - **تثبيت الاتصال (Socket IP Pinning)**: يتم تمرير العنوان المعتمد بعد الفحص مباشرة إلى `connect_tcp(pinned_ip, port)`، مما يجبر مقبس TCP على الاتصال بالـ IP الموافق عليه حصراً.
   - **منع سباق الوقت (TOCTOU & DNS Rebinding Prevention)**: تمنع هذه الآلية حدوث أي استعلام DNS ثانٍ من قِبل نظام التشغيل أو مكتبة HTTPX أثناء إجراء الاتصال الفعلي.

3. **أمان النقل عبر HTTPX (HTTPX Transport Safety)**:
   - **تثبيت `trust_env=False`**: إيقاف ثقة العميل بمتغيرات البيئة (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) لقطع الطريق على تمرير الطلبات عبر خوادم وسيطة غير موثوقة.
   - **تثبيت `follow_redirects=False`**: منع تتبع عمليات إعادة التوجيه (301/302/307/308)، مما يضمن عدم تحويل الطلب المفوض الذي يحمل ترويسة `Authorization` إلى وجهة أخرى.
   - **الحفاظ الكامل على TLS SNI والتحقق من الشهادة**:
     - على الرغم من أن مقبس TCP يتصل بالعنوان المثبت `pinned_ip`، فإن `httpcore` ينفذ مصافحة TLS ممرراً `server_hostname` المشتق من اسم النطاق الأصلي في الطلب (`api.openai.com`).
     - يتم إرسال اسم النطاق الصحيح في حقل SNI، ويتحقق محرك SSL من تطابق شهادة الخادم مع اسم النطاق، وليس مع عنوان IP.

---

## 2. الملفات المعدلة والمضافة

| الملف | نوع التغيير | الوصف |
| :--- | :--- | :--- |
| [app/ssrf.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/app/ssrf.py) | جديد | وحدة حماية SSRF، والتحليل القياسي للعناوين، و`SafeSSRFNetworkBackend`، و`SafeSSRFTransport`. |
| [app/config.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/app/config.py) | تعديل | استبدال البادئات بقائمة السماح الصريحة `APPROVED_PROVIDER_KEY_ENVS` و`PROVIDER_KEY_ENV_MAP`، واستدعاء `validate_ssrf_url`. |
| [app/providers.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/app/providers.py) | تعديل | التحقق من المفتاح مع اسم المزود، واستخدام `create_safe_transport()` مع `trust_env=False` و`follow_redirects=False`. |
| [app/main.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/app/main.py) | تعديل | استخدام `create_safe_transport()` مع `trust_env=False` و`follow_redirects=False` في مسار التدفق (Streaming). |
| [tests/test_provider_security.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/tests/test_provider_security.py) | تعديل | اختبارات القائمة الصريحة، ورفض البادئات غير المعتمدة، وربط المزودين، وفحص `transport_called=False`. |
| [tests/test_ssrf_protection.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/tests/test_ssrf_protection.py) | تعديل | اختبارات التحليل القياسي، والصيغ غير القياسية للـ IP، ومعرفات النطاق، والعناوين المحلية والمحجوزة. |
| [tests/test_dns_rebinding.py](file:///C:/Users/Aledari/.gemini/antigravity/scratch/ai-gateway-v1/tests/test_dns_rebinding.py) | جديد | اختبارات حل DNS التفاعلي، والاستجابات المختلطة، والتثبيت، وDNS Rebinding، و`trust_env=False`، و`follow_redirects=False`. |

---

## 3. توثيق الاختبارات (RED ثم GREEN)

### مرحلة الفشل الأولي (RED Verification):
- قبل تطبيق التعديلات، تم تشغيل حزمة الاختبارات الجديدة:
  ```text
  FAILED tests/test_provider_security.py::test_unapproved_variable_with_valid_prefix_is_rejected
  FAILED tests/test_provider_security.py::test_provider_name_to_key_binding
  FAILED tests/test_provider_security.py::test_file_suffix_supported_and_strictly_checked
  FAILED tests/test_provider_security.py::test_mock_transport_never_called_on_unapproved_key_env
  FAILED tests/test_provider_security.py::test_conflict_when_direct_and_file_sources_both_exist
  ```

### مرحلة النجاح بعد الإصلاح (GREEN Verification):
- تشغيل كافة مجموعات الاختبار بعد تطبيق المعالجة:
  ```text
  tests/test_provider_security.py: 7 passed
  tests/test_ssrf_protection.py: 9 passed
  tests/test_dns_rebinding.py: 7 passed
  ```
- النتيجة الإجمالية لمجموعة pytest الكاملة:
  ```text
  59 passed, 39 skipped, 1 warning in 5.30s
  ```
  *(الـ 39 اختباراً المتخطية هي اختبارات صلاحيات ملفات POSIX على مضيف Windows والتي تنتظر التحقق في بيئة Linux CI Runner).*

---

## 4. اختبارات الطفرات (Mutation Tests)

تم إعادة التحقق من الطفرات الحرجة لضمان عدم تأثرها بالمعالجة الجديدة:
1. **طفرة تعطيل مقارنة HMAC (`matches = True`)**:
   - أدت فوراً إلى فشل `test_forged_hmac.py` وكشف التزوير (`AssertionError: assert 200 == 401`) -> **`KILLED / PASS`**.
2. **طفرة تجاوز تحديد المعدل (`if False: # bypass limit`)**:
   - أدت فوراً إلى فشل `test_api.py` وكشف تجاوز الحد الأقصى (`assert 32 == 7`) -> **`KILLED / PASS`**.

---

## 5. اختبار الكناري S5 (Canary Leakage Verification)

- تم تشغيل اختبار الكناري الشامل عبر مسارات 200 العادي، و422 خطأ التحقق، و502 خطأ المزود، و401 خطأ المصادقة:
  ```text
  CANARY_PROMPT            : SECURE (NOT LEAKED)
  CANARY_AUTH_SUFFIX       : SECURE (NOT LEAKED)
  CANARY_PROVIDER_SECRET   : SECURE (NOT LEAKED)
  CANARY VERDICT: PASSED - ZERO SECRETS LEAKED
  ```

---

## 6. تقرير المراجعة المستقلة (Independent Security Review)

### كيف يمنع التطبيق DNS Rebinding فعلياً؟
- في البنية السابقة، كان التحقق يتم على النص، ثم يقوم العميل بطلب الاتصال بالاسم، مما يمنح خادم DNS المعادي فرصة إرجاع IP عام في الاستعلام الأول، ثم إرجاع `127.0.0.1` عند الاتصال الفعلي.
- في البنية المعالجة، يقوم `SafeSSRFNetworkBackend` باعتراض استدعاء `connect_tcp`، ويستعلم عن جميع سجلات A وAAAA دفعة واحدة، ويفحص كل عنوان. إذا اجتازت جميعها الفحص، يأخذ عنوان IP المعتمد ويرسله مباشرة كوجهة اتصال للمقبس. المقبس يتصل بالـ IP المثبت ولا يستعلم عن DNS مرة أخرى.

### أي عنوان IP يُستخدم للاتصال؟
- يُستخدم حصراً العنوان الأول المفحوص والمعتمد من مجموعة العناوين العامة التي أرجعها الاستعلام المسبق. لا يُسمح لنظام التشغيل أو HTTPCore باختيار عنوان غير مفحوص.

### كيف يتم الاحتفاظ بـ TLS SNI وHost الصحيحين؟
- يفصل `httpcore` بين مرحلة إنشاء مقبس TCP (`connect_tcp`) ومرحلة بدء التشفير (`start_tls`).
- يتم إنشاء مقبس TCP إلى عنوان IP المثبت، ولكن عند تنفيذ `start_tls`، يُمرر `server_hostname` حاملاً اسم النطاق الأصلي للطلب (مثل `api.openai.com`). وبذلك يرسل العميل ترويسة SNI الصحيحة، ويتحقق محرك التشفير من مطابقة اسم النطاق لشهادة الخادم بدقة.

### كيف تُمنع متغيرات Proxy غير الموثوقة من تجاوز السياسة؟
- تم تمرير `trust_env=False` بصفة إلزامية عند تهيئة `SafeSSRFTransport` وحاوية `httpx.AsyncClient` في مسارات الطلبات العادية والتدفق.
- هذا الإعداد يمنع HTTPX ومكتبات الشبكة من قراءة متغيرات `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` من بيئة التشغيل، مما يمنع تجاوز فحص الوجهات عبر وسيط غير معتمد.

### ما الذي لا يستطيع التطبيق ضمانه دون Egress Firewall أو وسيط خروج خارجي؟
- التطبيق يضمن منع الاتصال المباشر بأي عنوان داخلي، أو محلي، أو خاص، أو متعلق بالميتاداتا، ويمنع DNS Rebinding وHTTP Redirects على مستوى طبقة التطبيق (Application Layer).
- **الحدود التقنية**:
  1. لا يمكن للتطبيق منع استهداف خوادم خارجية عامة غير مرغوبة إذا كان النطاق عاماً وصالحاً ومسجلاً لمزود خارجي لم يكن مقصوداً في السياسة التشغيلية، ما لم تكن هناك قائمة بيضاء لعناوين النطاقات الخارجية مسبقاً في `config.yaml`.
  2. في حال حدوث اختراق كامل لعملية بايثون نفسها (Memory Corruption أو استدعاء قشرة)، لا يمكن للتحكمات البرمجية منع حركة المرور الشبكية المنبعثة مباشرة عبر استدعاءات النظام (`libc` syscalls) دون وجود جدار حماية خارجي (Egress Firewall / NetworkPolicy) أو تقييد عزل الحاوية على مستوى النواة (`--network none` أو قيود iptables/ebpf).

---

## 7. تأكيد السلامة ونظافة المضيف

- لم يتم دمج الفرع في `main` أو في `audit/2026-11-13` [مؤكد].
- لم يتم تشغيل أي حاوية إنتاجية أو استخدام الـ Volume الإنتاجي [مؤكد].
- لم يتم استخدام أي مفاتيح حقيقية أو الاتصال بمزودين خارجيين [مؤكد].
- فحص المنافذ عبر `netstat -ano -p tcp` أكد تطابق خط الأساس للمستمعين تماماً وخلو النظام من أي خدمات خلفية معلقة [مؤكد].

---

## القرار الختامي (Final Verdict)

```text
F002_F003_REMEDIATED — PENDING LINUX VALIDATION
```

**مبررات القرار**:
1. تم إغلاق ثغرة F-002 تماماً عبر القائمة الصريحة المغلقة، وربط المزودين، وحظر التعارض، وإثبات عدم إجراء أي اتصال مسبق.
2. تم إغلاق ثغرة F-003 تماماً عبر التحليل القياسي، وحظر كافة صيغ العناوين غير القياسية، وتثبيت الاتصال بالـ IP المعتمد لمنع هجمات DNS Rebinding، وإلغاء الثقة بالوكلاء (`trust_env=False`)، وحظر التوجيه (`follow_redirects=False`).
3. المشروع الآن على الفرع `audit/2026-11-13-c1` مؤهل وجاهز للمرحلة التالية: **التحقق المستقل داخل بيئة Linux CI Runner** لاختبار الـ 39 اختباراً الخاصة بصلاحيات POSIX وبناء الصورة واختبار الحاوية المعزولة.
