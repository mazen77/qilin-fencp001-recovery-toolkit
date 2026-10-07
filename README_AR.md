# أداة Qilin FENCP001 للاسترداد

[![Author: Mazen Bassiso](https://img.shields.io/badge/Author-Mazen%20Bassiso-2f81f7)](https://fa7ma.com)
![Focus: Cybersecurity Research](https://img.shields.io/badge/Focus-Cybersecurity%20Research-238636)
![Use: Defensive Recovery](https://img.shields.io/badge/Use-Defensive%20Recovery-8250df)


أداة تجريبية **دفاعية للاسترداد وفك التشفير** للملفات المرتبطة بـ Qilin والتي تستخدم التذييل غير الموثق `FENCP001`.

> **مهم:** هذه ليست أداة عامة لفك جميع إصدارات Qilin، ولا تكسر RSA-4096 أو AES أو ChaCha20. مسار فك التشفير الحقيقي هنا يعتمد على وجود ضعف في التطبيق، وأهم مثال هو **إعادة استخدام نفس تيار التشفير/nonce مع توفر plaintext مطابق ومعروف**.

[English](README.md)

## إعداد وبحث مازن بسيسو

**مازن بسيسو — باحث في الأمن السيبراني ومطور تقني**

- الموقع: https://fa7ma.com
- الحساب التقني العام: **@maz_tech**
- مجالات التركيز: الأمن السيبراني الدفاعي، استرداد ملفات ransomware، الاستجابة للحوادث، الأدوات التي تراعي الخصوصية، تحليل تنسيقات الملفات، وتقوية الأنظمة والتطبيقات.

يقود **مازن بسيسو** هذا المشروع ويقوم بصيانته ونشره للعامة. بدأ المشروع من بحث دفاعي عملي في سلوك ملفات ransomware غير الموثق، ثم تم تحويل النتائج إلى أداة عامة وآمنة تساعد الضحايا وفرق الاستجابة للحوادث والباحثين الأمنيين.

يركز العمل في هذا المستودع على:

- الاسترداد المبني على أدلة بدل الادعاء بوجود “universal decryptor” غير مثبت؛
- تحليل إعادة استخدام stream/nonce والاسترداد عبر exact known plaintext؛
- أدوات مناسبة لـ DFIR لا تقوم بتشغيل الملفات المشبوهة؛
- حماية الخصوصية افتراضياً عند إنشاء التقارير؛
- بحث أمني عملي وقابل لإعادة الاختبار والتطوير من باحثين آخرين.

عند الاستفادة من المشروع في بحث أو مقال أو محاضرة أو أداة، يرجى الإشارة إلى **Mazen Bassiso / مازن بسيسو** وإلى هذا المستودع. يوجد ملف اقتباس جاهز `CITATION.cff`.

## إصدار عام يحافظ على الخصوصية

هذا المستودع لا يحتوي على ملفات ضحايا أو قواعد بيانات عملاء أو امتدادات خاصة بالضحية أو رسائل فدية أو جهات اتصال للحملة أو مفاتيح خاصة أو مسارات خوادم أو hashes خاصة بحادثة معينة أو أسماء شركات/منتجات أو malware حي.

كما أن تقارير الأداة تحذف المعرفات افتراضياً. لا تظهر أسماء الملفات المحلية أو hashes أو أسماء الملفات داخل الأرشيف أو بايتات footer غير المعروفة إلا عند استخدام خيار opt-in واضح مثل `--include-identifiers`.

## الفكرة

إذا أعاد برنامج الفدية استخدام نفس stream في أكثر من ملف، وكان لدينا ملف أصلي **مطابق تماماً** لأحد الملفات المشفرة، يمكن استخراج stream بدون معرفة مفتاح المهاجم:

```text
keystream = plaintext المعروف XOR ciphertext المطابق
plaintext المستعاد = ciphertext الآخر XOR keystream
```

هذا لا يعني كسر AES أو ChaCha؛ بل استغلال خطأ في كيفية استخدام التشفير.

## إمكانيات الأداة

- فحص الملفات بدون تشغيلها.
- اكتشاف أرشيفات RAR4 حتى لو كان امتداد الملف مضللاً.
- قراءة metadata الأساسية من `FENCP001`.
- إنشاء profile عام لتنسيق RAR4 من نسختين سليمتين أو أكثر.
- اشتقاق keystream جزئي من رأس RAR المعروف.
- مقارنة ملفات مشفرة للبحث عن دليل على إعادة استخدام stream.
- اشتقاق keystream كامل من زوج plaintext/ciphertext مطابق تماماً.
- استخدام keystream موثوق لفك ملف آخر استخدم نفس stream والمحاذاة.
- دمج stream maps مع رفض أي تعارض.
- إنشاء نسخ sparse بحثية دون تعديل الأصل.
- تنفيذ heuristic على نسختين تاريخيتين سليمتين ونسختين مشفرتين.
- إخراج JSON مع إخفاء المعرفات افتراضياً.

## ما لا تستطيع الأداة فعله

- استخراج RSA private key.
- brute-force لمفتاح AES/ChaCha عشوائي قوي.
- تحويل نسخة قديمة "مشابهة" إلى keystream كامل.
- ضمان أن كل إصدار Qilin يستخدم `FENCP001` أو يعيد استخدام stream.
- اعتبار sparse recovery فك تشفير كامل عندما توجد بايتات غير معروفة.

## التثبيت

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

أو:

```bash
python3 src/qilin_fencp001_recovery.py --help
```

يمكن استخدام رسائل CLI بالعربية عبر `--lang ar`.

## أمثلة آمنة وعامة

### فحص ملف

```bash
qilin-fencp-recovery inspect "encrypted_sample.victim"
```

لإظهار hash وmetadata حساسة في تقرير خاص فقط:

```bash
qilin-fencp-recovery inspect "encrypted_sample.victim" --include-identifiers
```

### إنشاء profile من نسخ RAR4 سليمة

```bash
qilin-fencp-recovery profile-rar4 \
  --clean "clean_reference_A.bin" "clean_reference_B.bin" \
  --out rar4_profile.json
```

### استخراج stream جزئي من رأس RAR4

```bash
qilin-fencp-recovery rar4-header-map \
  --encrypted "backup_YYYYMMDD_HHMM.rar.victim" \
  --profile rar4_profile.json \
  --out stream_A.json
```

### دمج الخرائط

```bash
qilin-fencp-recovery merge-maps \
  --maps stream_A.json stream_B.json \
  --out merged_stream.json
```

### إنشاء نسخة sparse

```bash
qilin-fencp-recovery apply-map \
  --encrypted "backup_YYYYMMDD_HHMM.rar.victim" \
  --map merged_stream.json \
  --out sparse_recovery.rar
```

## فك تشفير كامل بدون مفتاح المهاجم عند وجود ملف أصلي مطابق

```bash
qilin-fencp-recovery derive-exact \
  --plaintext exact_original.bin \
  --encrypted exact_original.bin.victim \
  --out recovered.stream.bin
```

ثم:

```bash
qilin-fencp-recovery decrypt-keystream \
  --encrypted second_file.victim \
  --keystream recovered.stream.bin \
  --out second_file.recovered
```

هذا فك تشفير حقيقي باستخدام stream مستخرج ومثبت، وليس brute force.

## تحليل ملفين مشفرين

```bash
qilin-fencp-recovery analyze-pair \
  encrypted_A.victim encrypted_B.victim \
  --out pair_report.json
```

## heuristic لأربع نسخ

```bash
qilin-fencp-recovery stable-four-way \
  --clean-a clean_old.bin \
  --clean-b clean_newer.bin \
  --enc-a encrypted_A.victim \
  --enc-b encrypted_B.victim \
  --min-run 8 \
  --out stable_candidates.json
```

هذه النتيجة **heuristic فقط** ولا تثبت أن plaintext الحديث يساوي النسخة التاريخية.

## تشغيل RAR4 كامل بأمر واحد

```bash
qilin-fencp-recovery auto-rar4 \
  --clean "clean_reference_A.bin" "clean_reference_B.bin" \
  --encrypted "encrypted_A.victim" "encrypted_B.victim" \
  --out-dir recovery_out
```

## الخصوصية عند نشر النتائج

الإعداد الافتراضي يخفي:

- أسماء ومسارات الملفات المحلية؛
- SHA-256؛
- opaque bytes داخل `FENCP001`؛
- أسماء الملفات داخل الأرشيف؛
- metadata الخاصة بمصادر الـprofile.

لا تستخدم خيارات `--include-identifiers` في تقرير عام قبل مراجعته يدوياً.

## الاستخدام المسؤول

الأداة مخصصة للاستجابة للحوادث واسترجاع البيانات والبحث الدفاعي. لا تحتوي على وظائف لنشر ransomware أو persistence أو exploitation أو سرقة credentials أو التخريب.

## الباحث / المؤلف

هذا المشروع من إعداد وصيانة **مازن بسيسو (Mazen Bassiso)**، باحث في الأمن السيبراني ومطور تقني. راجع [`AUTHOR_AR.md`](AUTHOR_AR.md) للتعريف العام و[`MEDIA_KIT.md`](MEDIA_KIT.md) لمواد النشر والتعريف بالمشروع.

## الترخيص

MIT.
