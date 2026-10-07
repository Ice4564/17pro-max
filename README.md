# Sleuth 🔍

เครื่องมือ OSINT ที่รวมความสามารถของ [Sherlock](https://github.com/sherlock-project/sherlock), [Maigret](https://github.com/soxoj/maigret) และ [SpiderFoot](https://github.com/smicallef/spiderfoot) ไว้ในตัวเดียว โดยเขียนขึ้นใหม่ทั้งหมด

- **ค้น Username:** ตรวจว่า username มีบัญชีบนเว็บไหนบ้าง และดึงข้อมูลโปรไฟล์ (แบบ Sherlock/Maigret)
- **สแกนเป้าหมาย:** ใส่โดเมน, IP, อีเมล หรือ username แล้วระบบจะใช้ module หลายตัวหาข้อมูลและค้นต่อจากสิ่งที่เจอเองอัตโนมัติ (แบบ SpiderFoot)

| ความสามารถ | Sherlock | Maigret | SpiderFoot | **Sleuth** |
|---|:-:|:-:|:-:|:-:|
| ตรวจ username บนหลายเว็บพร้อมกัน (async) | ✅ | ✅ | ✅ | ✅ |
| ดึงข้อมูลโปรไฟล์ + ค้นต่อแบบ recursive | ❌ | ✅ | บางส่วน | ✅ |
| ตรวจจับหน้า anti-bot / rate limit (ไม่นับเป็น "พบ") | บางส่วน | ✅ | ❌ | ✅ |
| Self-check ทดสอบกฎของทุกเว็บกับเว็บจริง | ❌ | ✅ | ❌ | ✅ |
| สแกนโดเมน / IP / อีเมล ด้วยระบบ module แบบ event-driven | ❌ | ❌ | ✅ | ✅ |
| ซับโดเมน, DNS, WHOIS, SSL, พอร์ต, CVE, เทคโนโลยีเว็บ | ❌ | ❌ | ✅ | ✅ |
| ข้อสรุปความเสี่ยงอัตโนมัติ (correlation rules) | ❌ | ❌ | ✅ | ✅ |
| ประวัติการสแกน (SQLite) + กราฟความสัมพันธ์ | ❌ | ❌ | ✅ | ✅ |
| ใช้ได้ทันทีโดยไม่ต้องสมัคร API key | ✅ | ✅ | บางส่วน | ✅ |
| สร้างชื่อใกล้เคียงอัตโนมัติ (`ice_4564`, `ice4564x`, `ice4564th` …) | ❌ | บางส่วน | ❌ | ✅ |
| ค้น `"username" site:...` ใน DuckDuckGo / Bing แล้วเก็บเป็นหลักฐาน | ❌ | ❌ | บางส่วน | ✅ |
| คะแนนตัวตน 0–100 + รวมบัญชีที่น่าจะเป็นคนเดียวกัน (ชื่อ, bio, รูป, ลิงก์, อีเมล, โดเมน) | ❌ | บางส่วน | ❌ | ✅ |
| หลักฐานทุกชิ้นมี Source / First seen / Last checked / Confidence | ❌ | ❌ | บางส่วน | ✅ |
| ติดตามการเปลี่ยนแปลงของโปรไฟล์ (bio, รูป, ผู้ติดตาม) ระหว่างการค้นแต่ละครั้ง | ❌ | ❌ | ❌ | ✅ |
| Cache + จำกัดความถี่ต่อเว็บ (ไม่ยิงเว็บเดิมซ้ำ, เคารพ 429 / Retry-After) | ❌ | บางส่วน | บางส่วน | ✅ |
| Plugin: เพิ่มแหล่งข้อมูลใหม่โดยไม่ต้องแก้ core | ❌ | ❌ | ✅ | ✅ |
| รายงาน TXT / CSV / JSON / Markdown / HTML / PDF + timeline | บางส่วน | ✅ | ✅ | ✅ |
| **Web UI ภาษาไทย แสดงผลแบบ real-time** | ❌ | บางส่วน | ✅ | ✅ |

> บน Windows ถ้าพิมพ์ `python` แล้วไม่เจอคำสั่ง ให้ใช้ `py` แทน หรือดับเบิลคลิก `web.bat`

## ติดตั้ง

ต้องมี Python 3.10 ขึ้นไป

```bash
pip install -r requirements.txt
```

หรือติดตั้งเป็นคำสั่ง `sleuth`:

```bash
pip install -e .
```

## วิธีใช้

### Web UI (ง่ายที่สุด)

```bash
python -m sleuth --web
```

จากนั้นเปิด http://localhost:8787 พิมพ์ username แล้วกดค้นหา ผลจะขึ้นแบบ real-time พอค้นเสร็จจะได้หน้าสรุป (dashboard)

```
🔎 torvalds

บัญชีที่พบ 42 · บัญชีที่เชื่อมโยงกัน 12 · หลักฐาน 219 · ความมั่นใจ สูง 7 / กลาง 15 / ต่ำ 20 · โปรไฟล์เปลี่ยน 3

[ภาพรวม] [บัญชี] [Identity Graph] [Timeline] [หลักฐาน] [Export รายงาน]
```

- **ภาพรวม:** ตัวตนที่น่าจะเป็นคนเดียวกัน, คะแนน 0–100 ของแต่ละบัญชีพร้อมเหตุผล, โปรไฟล์ที่เปลี่ยนไปจากครั้งก่อน
- **Identity Graph:** กราฟ username → บัญชี → เว็บไซต์ → อีเมล ลาก/ซูมได้ กดกล่องไหนก็เปิดหลักฐานของสิ่งนั้น
- **Timeline:** วันสร้างบัญชี, archive.org, ครั้งแรกที่ Sleuth เห็น, การเปลี่ยนแปลง
- **หลักฐาน:** ทุก finding พร้อม Source / URL / Evidence / First seen / Last checked / Confidence กรองตามประเภทและระดับได้
- **Export:** HTML, PDF, Markdown, JSON, CSV, TXT

### เมนูตัวเลข

พิมพ์ `python -m sleuth` เฉย ๆ (หรือดับเบิลคลิก `sleuth.bat` / `1.bat`) จะมีหน้าโหลดสั้น ๆ (กดปุ่มใดก็ได้เพื่อข้าม หรือใช้ `--no-intro`) แล้วได้เมนูให้เลือกด้วยตัวเลข ระบบจะถามสิ่งที่ต้องใช้ทีละข้อ

ถ้าเพิ่มโฟลเดอร์นี้ใน PATH แล้ว พิมพ์ `1` ใน cmd ได้เลย ส่วนใน PowerShell ตัว `1` จะถูกอ่านเป็นตัวเลข จึงต้องเพิ่ม Enter handler ของ PSReadLine ใน `$PROFILE` ให้เปลี่ยน `1` เป็น `sleuth` ก่อนรัน

```
[1]  เว็บ    เปิดหน้าเว็บ Web UI
[2]  คน     ค้น username + ตามลิงก์ต่อ
[3]  โดเมน  สแกนโดเมน
[4]  อีเมล   สแกนอีเมล
[0]  ออก

เลือก:
```

### Command line

```bash
python -m sleuth torvalds
```

```bash
python -m sleuth alice bob --tags coding,gaming
```

```bash
python -m sleuth torvalds -f all
```

ตัวเลือกที่ใช้บ่อย:

| ตัวเลือก | ความหมาย |
|---|---|
| `-t coding,gaming` | ตรวจเฉพาะเว็บที่มี tag เหล่านี้ |
| `-s GitHub -s Reddit` | ตรวจเฉพาะเว็บที่ระบุ |
| `-d 0` | ปิดการค้นต่อแบบ recursive (ค่าเริ่มต้น `-d 1`) |
| `-v` / `--mutations` | ลองชื่อใกล้เคียง เช่น `ice4564` → `ice_4564`, `ice.4564`, `ice4564_`, `ice4564x`, `ice4564th`, `realice4564` … ค้นพร้อมกันในรอบเดียว (แยกผลจากชื่อที่พิมพ์) |
| `--max-candidates 12` | จำนวนชื่อใกล้เคียงต่อ username |
| `-n 1-10` / `--numbers 1-10` | ลองเติมเลขท้ายชื่อด้วย เช่น `ice` → `ice1`, `ice2` … `ice10` (สูงสุด 100 เลข, ในหน้าเว็บติ๊ก "เติมเลข") |
| `--show-mutations` | แสดงชื่อใกล้เคียงที่จะลอง แล้วจบ |
| `-w` / `--web-search` | ค้น `"username"`, `"username" site:instagram.com` ฯลฯ ใน DuckDuckGo (สำรองด้วย Bing) |
| `--max-search 6` | จำนวนคำค้นต่อ username |
| `--rate 0.3` | เว้นอย่างน้อยกี่วินาทีระหว่าง request ไปเว็บเดียวกัน (`0` = ไม่จำกัด) |
| `--no-cache` / `--cache-ttl 6` | ไม่ใช้คำตอบเดิม / ใช้คำตอบที่ตรวจไว้ไม่เกินกี่ชั่วโมง |
| `--no-history` | ไม่บันทึกการค้นครั้งนี้ (จะไม่มีการเทียบการเปลี่ยนแปลง) |
| `--changes [username]` | ดูการเปลี่ยนแปลงของโปรไฟล์ที่บันทึกไว้ |
| `--runs` / `--clear-cache` | ดูประวัติการค้น / ล้าง cache |
| `--no-domains` / `--max-domains 5` | ปิด / จำกัดการตามเว็บไซต์ส่วนตัวที่เจอในโปรไฟล์ |
| `-a` | แสดงผล "ไม่พบ" และ "ตรวจไม่ได้" ด้วย |
| `-f html,md,pdf` หรือ `-f all` | บันทึกรายงาน `txt`, `csv`, `json`, `md`, `html`, `pdf` (ลงโฟลเดอร์ `reports/`, PDF ต้องมี Chrome หรือ Edge ในเครื่อง) |
| `--timeout 20` | เวลารอต่อเว็บ (วินาที) |
| `--proxy http://127.0.0.1:8080` | ใช้ proxy |
| `--tor` | ผ่าน Tor (ต้อง `pip install aiohttp-socks` และเปิด Tor ไว้) |
| `--list-sites` | ดูรายชื่อเว็บและ tag ทั้งหมด |
| `--self-check` | ทดสอบกฎของทุกเว็บกับเว็บจริง |

### ผลลัพธ์มี 3 แบบ

- **พบ** — มีบัญชีนี้อยู่จริง
- **ไม่พบ** — ไม่มีบัญชีนี้
- **ตรวจไม่ได้** — เว็บบล็อก (Cloudflare/captcha), โดน rate limit, timeout หรือเชื่อมต่อไม่ได้ ระบบจะ*ไม่*เดาผลในกรณีนี้ จึงลด false positive ได้

## Candidate → Verification → Correlation

หัวใจของ Sleuth ไม่ใช่จำนวนเว็บ แต่เป็นการลด false positive และอธิบายได้ว่าแต่ละผลมาจากไหน

```
username ──► Mutations ──► ตรวจบนทุกเว็บ ──► Verification ──► Recursion ──► Search engine ──► Correlation ──► Evidence ──► History ──► รายงาน
             (ชื่อใกล้เคียง)  (cache + rate limit) (ไม่เชื่อแค่ 200)  (โปรไฟล์ → ลิงก์ → โดเมน)  (DDG / Bing)   (คะแนน 0–100)  (finding)   (snapshot)
```

**1. Mutations** (`-v`): `ice4564` → `ice_4564`, `ice.4564`, `ice-4564`, `ice`, `4564ice`, `ice4564_`, `_ice4564`, `ice4564x`, `ice4564th`, `ice4564_th`, `realice4564` … ([mutations.py](sleuth/mutations.py)) ทุกผลมีฟิลด์ `query` = `input` (พิมพ์เอง) / `candidate` (ระบบเดา, มี `candidate_of`) / `discovered` (เจอจากโปรไฟล์) หน้าเว็บแยกแท็บ "candidate" และ candidate จะเริ่มที่ความมั่นใจ "ต่ำ" เสมอ

**2. Verification:** HTTP 200 อย่างเดียวไม่พอ หลังกฎของเว็บบอกว่า "พบ" ระบบจะตรวจหน้าเว็บซ้ำ:

| ตรวจ | ผลถ้าไม่ผ่าน |
|---|---|
| `title` เช่น "Page not found", "404", "ไม่พบผู้ใช้" | ไม่พบ |
| `redirect` ไปหน้าแรก / login ของเว็บเดียวกัน | ไม่พบ |
| `username` หน้าเว็บไม่มี username เลย (หน้า SPA/default) | ตรวจไม่ได้ |
| `canonical` / `og:url` ชี้ไปหน้าแรก | เตือนเท่านั้น (บางเว็บทำแบบนี้กับโปรไฟล์จริง) |
| `profile` og:type=profile, JSON-LD Person, API ส่งข้อมูลกลับ | ✓ เพิ่มความมั่นใจ (API ตอบข้อมูลว่าง = ไม่พบ) |

ผลแต่ละข้อเก็บใน `checks` ของผลลัพธ์ (แสดงเป็น ✓ / ✗ บนการ์ดและในรายงาน) ปิดรายเว็บได้ด้วย `"verify": false` ใน sites.json

**3. Recursion** (`-d 1` ขึ้นไป): username → โปรไฟล์ → ลิงก์ → **เว็บไซต์ส่วนตัว** → บัญชีที่เว็บนั้นลิงก์ไป → username ใหม่ เว็บไซต์จะถูกนับเป็นหลักฐานเฉพาะเมื่อชื่อโดเมนมี username/ชื่อเจ้าของ หรือเว็บลิงก์กลับมาที่โปรไฟล์เดิม (เช่นเว็บบริษัทที่ใส่ไว้ใน bio จะไม่ทำให้บัญชีโซเชียลของบริษัทกลายเป็นของคนนั้น)

**4. Correlation:** เทียบบัญชีที่เจอทีละคู่ แล้วอธิบายคะแนน

```
Possible connection  82%
  ✓ username คล้ายกัน
  ✓ เว็บไซต์ภายนอกเดียวกัน
  ✓ bio คล้ายกัน
  ✗ รูปโปรไฟล์ต่างกัน
```

สัญญาณที่ใช้: ลิงก์ถึงกันโดยตรง, username, ชื่อที่แสดง, bio, เว็บไซต์/บัญชีที่ลิงก์ไป, รูปโปรไฟล์ (dHash), ที่อยู่ คะแนนเป็นแนวทางให้ตรวจต่อ **ไม่ได้ยืนยันว่าเป็นคนเดียวกัน** คู่ที่ username เหมือนกันต้องมีหลักฐานมากกว่าแค่ชื่อที่แสดงตรงกัน (บัญชีแฟนคลับก็ใช้ชื่อเดียวกันได้)

สัญญาณอีเมล: อีเมลเดียวกันบนสองโปรไฟล์, อีเมลโดเมนเดียวกัน (ไม่นับ gmail/hotmail ฯลฯ) หรืออีเมลที่อยู่บนโดเมนเว็บไซต์ของอีกบัญชี

**5. Identity score (0–100):** แต่ละบัญชีได้คะแนนว่าน่าจะเป็นของเป้าหมายแค่ไหน รวมจากที่มาของ username, เจ้าของลิงก์ไว้เอง, ชื่อจริงตรงกับบัญชีอื่น, รูปเหมือนกัน, ความเชื่อมโยงที่แข็งแรง และการที่ search engine มีหน้าโปรไฟล์นั้น (สูง ≥ 70, กลาง ≥ 45) แล้วรวมบัญชีที่มีหลักฐานเชื่อมกันเป็น **ตัวตน** ([identity.py](sleuth/identity.py)) คะแนนของกลุ่มคือหลักฐานที่อ่อนที่สุดที่เชื่อมสมาชิกเข้าด้วยกัน

**6. Evidence:** ทุกสิ่งที่เจอเป็น finding ([evidence.py](sleuth/evidence.py))

```
Finding
├── Source         เจอจากอะไร เช่น "ตรวจกับเว็บ GitHub โดยตรง (HTTP 200)", "เจ้าของลิงก์ไว้จาก linktree/ice4564", "Bing · คำค้น ..."
├── URL
├── Evidence       ผลตรวจหน้าเว็บ, ข้อมูลโปรไฟล์, อีเมล, archive.org, search engine, สัญญาณที่เชื่อมโยง
├── First seen     ครั้งแรกที่ Sleuth เห็น (จากประวัติ)
├── Last checked
└── Confidence     0–100
```

finding มี 5 ประเภท: บัญชี, อีเมล, เว็บไซต์, เบาะแส (IG/FB/TikTok ที่ archive.org หรือ search engine เห็น หรือโปรไฟล์จากผลค้นหา) และหน้าที่กล่าวถึง username รายงาน JSON มี `meta.findings`, `meta.clusters`, `meta.timeline`, `meta.changes`, `meta.search`, `meta.summary` และ `meta.graph`

## ค้นใน search engine

ติ๊ก "ค้นใน search engine" ในหน้าเว็บ (เปิดไว้เป็นค่าเริ่มต้น) หรือใช้ `-w` ระบบจะสร้างคำค้นให้เอง

```
"ice4564"
"ice4564" site:instagram.com
"ice4564" site:tiktok.com
"ice4564" site:facebook.com
"ice4564" (site:x.com OR site:twitter.com)
"ice4564" site:github.com
```

แล้วค้นใน DuckDuckGo ทีละคำค้น (เว้นช่วง 1.5 วินาที) ถ้าโดนบล็อกจะเปลี่ยนไปใช้ Bing ต่อ **ไม่พยายามหลบ CAPTCHA** ผลที่ได้:

- หน้าโปรไฟล์ที่ handle ตรงกับ username (เช่น `instagram.com/ice4564`) → บัญชี IG/TikTok ที่ "ตรวจเอง" จะขึ้นว่า "อยู่ในผลค้นหา" และได้คะแนนเพิ่ม
- หน้าที่กล่าวถึง username → เก็บเป็นหลักฐาน "กล่าวถึง" พร้อม engine, คำค้น, อันดับ และข้อความตัวอย่าง

Google ไม่อนุญาตให้ค้นอัตโนมัติ จึงมีแค่ปุ่มให้กดเปิดเอง

## ติดตามการเปลี่ยนแปลงของโปรไฟล์ + cache

ทุกการค้นถูกบันทึกที่ `~/.sleuth/history.db` (เปลี่ยนที่เก็บได้ด้วย environment variable `SLEUTH_HISTORY`) ครั้งต่อไปที่ค้นชื่อเดิม ระบบจะเทียบให้

```
GitHub @ice4564
  เปลี่ยน Bio        "เขียนเกม"  →  "เขียนเกม + AI"
  เปลี่ยนรูปโปรไฟล์   (เทียบจากภาพจริงด้วย dHash ไม่ใช่แค่ลิงก์)
  ผู้ติดตาม           1,240 → 1,391 (+151)
  บัญชีหายไป         พบ → ไม่พบแล้ว
```

- ดูได้ในหน้าเว็บ (ภาพรวม + Timeline) หรือ `python -m sleuth --changes ice4564`
- **Cache:** คำตอบ "พบ" / "ไม่พบ" ถูกใช้ซ้ำ 6 ชั่วโมง (`--cache-ttl`) เว็บที่ตรวจไม่ได้จะถามใหม่ทุกครั้ง และถ้ากฎของเว็บใน sites.json เปลี่ยน cache ของเว็บนั้นจะไม่ถูกใช้ คำตอบจาก cache ไม่นับเป็นการเปลี่ยนแปลง
- **Rate limit:** เว้นช่วงระหว่าง request ไปเว็บเดียวกัน (`--rate`, ค่าเริ่มต้น 0.3 วินาที) ถ้าเว็บตอบ 429 ระบบจะรอตาม `Retry-After` (สูงสุด 10 วินาที) แล้วชะลอทุก request ไปเว็บนั้นก่อนลองใหม่

## ตามหาบัญชี IG / Facebook / TikTok / X ของคนเดียวกัน

Instagram, Facebook, TikTok, X และ Threads **บล็อกการตรวจอัตโนมัติ** (ส่งหน้าเดียวกันกลับมาไม่ว่าบัญชีจะมีจริงหรือไม่) Sleuth จึงไม่เดาผล แต่ใช้วิธีที่นักสืบ OSINT ใช้จริง:

1. **ตามลิงก์ที่เจ้าของใส่ไว้เอง:** ถ้าบัญชีที่เจอ (Linktree, GitHub, YouTube, Twitch, Gravatar, About.me ฯลฯ) ลิงก์ไปหา IG / FB / TikTok / X ระบบจะบันทึกเป็นบัญชี **"เชื่อมโยง"** พร้อมหลักฐาน แล้วเอา handle นั้นไปค้นต่อบนเว็บอื่น
2. **อ่าน bio:** จับข้อความแบบ `IG: @name`, `tiktok @name`, `เฟส: name`, `ติ๊กต็อก @name`
3. **ลอง candidate** (`-v` หรือติ๊กในหน้าเว็บ): `john.doe` → `johndoe`, `john_doe`, `john-doe` (ผลแยกจากชื่อที่พิมพ์ ดูหัวข้อด้านบน)
4. **ตรวจเอง:** IG / FB / TikTok / X / Threads ที่ยังไม่มีหลักฐาน จะขึ้นในแท็บ **"ตรวจเอง"** กด "เปิดตรวจ" เพื่อดูในเบราว์เซอร์ของคุณ ถ้าเจอก็กด **"✓ เจอแล้ว"**
5. **เทียบรูปโปรไฟล์:** ถ้าบัญชีบนเว็บต่าง ๆ ใช้รูปเดียวกัน (เทียบด้วย perceptual hash แม้ขนาดรูปต่างกันก็จับได้) จะนับเป็นหลักฐาน และระบบจะข้ามรูป default เช่นรูปช้างของ Mastodon
6. **ค้นใน archive.org:** สำหรับ IG / FB / TikTok / X ถ้า Wayback Machine เคยเก็บหน้าโปรไฟล์ไว้ แปลว่าบัญชีน่าจะมีจริง กด "ดูหน้าที่เก็บไว้" เพื่อดูได้โดยไม่ต้อง login
7. **ค้นใน search engine:** DuckDuckGo / Bing หา `"username" site:instagram.com` ให้อัตโนมัติ (ดูหัวข้อด้านบน) และมีปุ่มเปิดคำค้นเดียวกันใน Google
8. **สรุปตัวตน:** คะแนน 0–100 ของแต่ละบัญชี
   - **สูง (≥ 70):** เจ้าของลิงก์ไว้เอง, รูปเหมือนบัญชีที่ยืนยันแล้ว, หลายหลักฐานตรงกัน หรือคุณยืนยันเอง
   - **กลาง (≥ 45):** ชื่อจริง (2 คำขึ้นไป) หรือรูปโปรไฟล์ตรงกับบัญชีอื่น หรือความเชื่อมโยงที่แข็งแรง
   - **ต่ำ:** แค่ username ตรงกัน ซึ่งอาจเป็นคนอื่น

```bash
python -m sleuth selenagomez
```

ตัวอย่างผล: เจอ Linktree ของ @selenagomez แล้วได้ Instagram, Facebook, TikTok และ X มาพร้อมกัน ทุกบัญชีมีหลักฐานว่า "ลิงก์จากโปรไฟล์ Linktree"

## สแกนเป้าหมาย (แบบ SpiderFoot)

ในหน้าเว็บ ให้กดแท็บ **สแกนเป้าหมาย** (http://localhost:8787/scan) หรือใช้ command line:

```bash
python -m sleuth --scan example.com
```

```bash
python -m sleuth --scan 8.8.8.8
```

```bash
python -m sleuth --scan name@company.com -f html
```

```bash
python -m sleuth --scan example.com -m dns,crt,sslcert,webpage
```

ระบบจะเดาประเภทเป้าหมายให้เอง ผลแต่ละอย่างที่เจอเรียกว่า **event** และจะถูกส่งต่อให้ module อื่นค้นต่อ เช่น

```
example.com → ซับโดเมน (crt.sh) → IP → พอร์ตที่เปิด / CVE (Shodan)
            → หน้าเว็บ → อีเมล → Gravatar / username → บัญชีบน 70+ เว็บ
            → ลิงก์โซเชียล → username → บัญชีบน 70+ เว็บ
```

### Modules (ทั้งหมดฟรี ไม่ต้องใช้ API key)

| Module | ทำอะไร |
|---|---|
| `dns` | A / AAAA / MX / NS / TXT records ผ่าน DNS-over-HTTPS |
| `emailsec` | ตรวจ SPF และ DMARC (ป้องกันอีเมลปลอม) |
| `crt` | หาซับโดเมนจาก Certificate Transparency (crt.sh, CertSpotter) |
| `hackertarget` | หาซับโดเมนจาก passive DNS |
| `rdap_domain` | WHOIS ของโดเมน: ผู้รับจด, วันจด, วันหมดอายุ |
| `rdap_ip` | เจ้าของช่วง IP |
| `ipgeo` | ประเทศ / เมือง / ASN ของ IP |
| `internetdb` | พอร์ตที่เปิด, ซอฟต์แวร์, CVE จาก Shodan InternetDB (ข้อมูล passive) |
| `sslcert` | Certificate: ผู้ออก, วันหมดอายุ, ชื่อโฮสต์อื่นใน cert |
| `webpage` | ชื่อเว็บ, server, เทคโนโลยี, อีเมล, ลิงก์โซเชียล, security header, security.txt |
| `wayback` | ประวัติใน archive.org |
| `email_parse` | ใช้ชื่อหน้า @ เป็น username และหาโดเมนของอีเมล |
| `gravatar` | โปรไฟล์ Gravatar ที่ผูกกับอีเมล |
| `pgp` | PGP key บน keys.openpgp.org |
| `accounts` | ค้น username บนทุกเว็บ (ระบบค้น Username) |
| `websearch` | ค้น username / อีเมลใน DuckDuckGo (สำรองด้วย Bing) เก็บโปรไฟล์และหน้าที่กล่าวถึง |

ดูรายละเอียดได้ด้วย `python -m sleuth --list-modules`

### ข้อสรุปความเสี่ยงที่ตรวจอัตโนมัติ

ไม่มี SPF/DMARC, SPF แบบ `+all`, SSL ไม่ถูกต้องหรือใกล้หมดอายุ, โดเมนใกล้หมดอายุ, พบ CVE, เปิดพอร์ตอันตราย (เช่น MySQL, RDP, Redis), ขาด security header, อีเมลถูกเปิดเผยบนเว็บ, ไม่มี security.txt และ username เดียวกันมีบัญชีหลายเว็บ

### ขอบเขตการสแกน

- **ไม่ลามออกนอกเป้าหมาย:** ระบบค้นต่อเฉพาะซับโดเมนของโดเมนเป้าหมาย ส่วนโดเมนอื่นที่เจอจะแค่บันทึกว่า "โดเมนที่ลิงก์ออกไป"
- **มีงบจำกัด:** เช่น โหลดหน้าเว็บสูงสุด 15 โฮสต์, ตรวจ IP 25 ตัว, ค้นบัญชี 5 username ต่อการสแกน
- **ไม่สแกนพอร์ตเอง:** ข้อมูลพอร์ตและ CVE มาจากฐานข้อมูลสาธารณะของ Shodan ส่วนหน้าเว็บโหลดแค่หน้าแรกเหมือนคนเปิดดูทั่วไป
- **ประวัติ:** การสแกนทุกครั้งถูกบันทึกที่ `~/.sleuth/scans.db` ดูได้ในแท็บ "ประวัติการสแกน" หรือใช้ `python -m sleuth --history`

## เพิ่มเว็บใหม่

แก้ไฟล์ [`sleuth/data/sites.json`](sleuth/data/sites.json) ได้เลย ใช้ `{}` แทนตำแหน่ง username

```json
"GitHub": {
  "url": "https://github.com/{}",
  "check": "status_code",
  "regex": "^[a-zA-Z0-9-]{1,39}$",
  "tags": ["coding"],
  "claimed": "torvalds"
}
```

| ฟิลด์ | ความหมาย |
|---|---|
| `url` | ลิงก์โปรไฟล์ที่แสดงให้ผู้ใช้ |
| `probe` | (ไม่บังคับ) URL ที่ใช้ตรวจจริง เช่น API ที่แม่นยำกว่า |
| `check` | `status_code` (200 = พบ), `message` (เจอข้อความ `error_msg` = ไม่พบ) หรือ `response_url` (โดน redirect = ไม่พบ) |
| `error_msg` | ข้อความที่แปลว่า "ไม่มีผู้ใช้นี้" (ใส่เป็น list ได้) |
| `presence_msg` | (ไม่บังคับ) ข้อความที่ต้องมีในหน้าโปรไฟล์จริง |
| `error_url` | ใช้กับ `response_url`: redirect ไปที่นี่ = ไม่พบ |
| `method`, `json`, `headers` | สำหรับ API แบบ POST / GraphQL |
| `regex` | รูปแบบ username ที่เว็บยอมรับ (ไม่ตรงจะข้ามไป) |
| `claimed` | username ที่มีอยู่จริงแน่นอน ใช้กับ `--self-check` |
| `aliases` | URL โปรไฟล์รูปแบบอื่นของเว็บเดียวกัน เช่น `["https://www.reddit.com/u/{}"]` ใช้จับลิงก์ตอนค้นต่อ |
| `verify` | `false` = ไม่ตรวจหน้าเว็บซ้ำหลังกฎบอกว่า "พบ" (ค่าเริ่มต้น `true`) |
| `disabled` | `true` = ปิดไว้ (เช่น เว็บบล็อกบอท) |

เพิ่มเว็บแล้วให้ทดสอบด้วยคำสั่งนี้:

```bash
python -m sleuth --self-check -s "ชื่อเว็บ"
```

ระบบจะลองค้น username ใน `claimed` (ต้องได้ "พบ") และ username สุ่ม (ต้องได้ "ไม่พบ")
ถ้าใส่ `--disable-broken` ระบบจะปิดเว็บที่ไม่ผ่านให้อัตโนมัติ

## ทดสอบโค้ด

```bash
python -m pytest -q tests
```

เทสใช้เซิร์ฟเวอร์จำลองในเครื่อง จึงไม่ต้องต่ออินเทอร์เน็ต

## โครงสร้างโปรเจกต์

```
sleuth/
├── data/sites.json   ฐานข้อมูลเว็บ + กฎการตรวจ
├── sites.py          โหลด/กรองเว็บ, จับคู่ลิงก์โปรไฟล์กับเว็บ
├── engine.py         ตัวค้นหา async, ตัดสินผล, recursive search (โปรไฟล์ + โดเมน)
├── verify.py         ตรวจซ้ำหลัง HTTP 200 (title, redirect, canonical, username, profile marker)
├── linker.py         candidate username, ลิงก์โซเชียลใน bio, คะแนนตัวตน 0–100
├── mutations.py      สร้างชื่อใกล้เคียง (ice4564 → ice_4564, ice4564x, ice4564th …)
├── websearch.py      ค้น DuckDuckGo / Bing ด้วย dork แล้วแยกผลเป็นหลักฐาน
├── similarity.py     เทียบบัญชีทีละคู่ → possible connection + เหตุผล ✓/✗ (รวมอีเมล/โดเมน)
├── identity.py       รวมบัญชีที่มีหลักฐานเชื่อมกันเป็น "ตัวตน"
├── evidence.py       evidence graph, findings, timeline, ตัวเลข dashboard
├── history.py        ประวัติการค้น, snapshot, การเปลี่ยนแปลงของโปรไฟล์, cache (SQLite)
├── avatars.py        เทียบรูปโปรไฟล์ด้วย dHash
├── extractor.py      ดึงข้อมูลโปรไฟล์จาก HTML / JSON-LD / JSON API
├── report.py         รายงาน TXT / CSV / JSON / Markdown / HTML / PDF
├── selfcheck.py      ทดสอบกฎกับเว็บจริง
├── web.py            Web UI server (SSE streaming)
├── static/           หน้าเว็บ (index.html = ค้น username, scan.html = สแกนเป้าหมาย)
├── cli.py            คำสั่ง command line
└── scan/             ระบบสแกนแบบ SpiderFoot
    ├── core.py       event, scanner, scope และงบจำกัด
    ├── modules/      dns.py, network.py, web.py, identity.py, search.py + plugin loader
    ├── correlate.py  กฎสรุปความเสี่ยง
    ├── store.py      ประวัติการสแกน (SQLite)
    └── report.py     รายงาน HTML / JSON
```

### เขียน plugin (เพิ่มแหล่งข้อมูลโดยไม่แก้ core)

module แบ่งเป็นกลุ่ม `username`, `social`, `domain`, `email`, `image`, `search` สร้างไฟล์ `.py` ไว้ใน `~/.sleuth/plugins/` (หรือโฟลเดอร์ที่ระบุใน environment variable `SLEUTH_PLUGINS`) แล้ว Sleuth จะโหลดให้เองตอนเปิด แยกโฟลเดอร์ตามกลุ่มได้ เช่น

```
~/.sleuth/plugins/
├── social/mastodon.py
├── image/tineye.py
└── email/hibp.py
```

ไฟล์ที่ขึ้นต้นด้วย `_` จะถูกข้าม ถ้า plugin มี error ระบบจะแจ้งใน `python -m sleuth --list-modules` แต่ยังทำงานต่อได้

```python
from sleuth.scan.core import Module

class MyModule(Module):
    name = "my_module"
    title = "ชื่อที่แสดง"
    description = "ทำอะไร"
    watches = ("DOMAIN_NAME",)           # event ที่อยากได้รับ

    async def handle(self, event, ctx):
        status, data, _ = await ctx.get(f"https://api.example.com/{event.data}", json=True)
        if status == 200:
            yield event.child("EMAIL", data["email"], self.name)   # ส่ง event ใหม่ต่อให้ module อื่น
```

ถ้าเป็น module ที่มากับโปรแกรม ให้ใส่ไว้ใน `BUILTIN` ใน `sleuth/scan/modules/__init__.py` แทน

## ⚠️ ใช้อย่างรับผิดชอบ

ใช้เฉพาะข้อมูลสาธารณะเพื่อวัตถุประสงค์ที่ชอบธรรม เช่น ตรวจ digital footprint ของตัวเอง งานวิจัย หรือ OSINT/pentest ที่ได้รับอนุญาต
username เดียวกันบนคนละเว็บ**ไม่จำเป็นต้องเป็นคนเดียวกัน** ควรตรวจสอบก่อนสรุปผลเสมอ และควรเคารพข้อกำหนดการใช้งานของแต่ละเว็บ
