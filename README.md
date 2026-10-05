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
| รายงาน TXT / CSV / JSON / HTML | บางส่วน | ✅ | ✅ | ✅ |
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

จากนั้นเปิด http://localhost:8787 พิมพ์ username แล้วกดค้นหา ผลจะขึ้นแบบ real-time และกดดาวน์โหลดรายงาน HTML / JSON / CSV ได้

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
| `-a` | แสดงผล "ไม่พบ" และ "ตรวจไม่ได้" ด้วย |
| `-f html,json` หรือ `-f all` | บันทึกรายงาน (ลงโฟลเดอร์ `reports/`) |
| `--timeout 20` | เวลารอต่อเว็บ (วินาที) |
| `--proxy http://127.0.0.1:8080` | ใช้ proxy |
| `--tor` | ผ่าน Tor (ต้อง `pip install aiohttp-socks` และเปิด Tor ไว้) |
| `--list-sites` | ดูรายชื่อเว็บและ tag ทั้งหมด |
| `--self-check` | ทดสอบกฎของทุกเว็บกับเว็บจริง |

### ผลลัพธ์มี 3 แบบ

- **พบ** — มีบัญชีนี้อยู่จริง
- **ไม่พบ** — ไม่มีบัญชีนี้
- **ตรวจไม่ได้** — เว็บบล็อก (Cloudflare/captcha), โดน rate limit, timeout หรือเชื่อมต่อไม่ได้ ระบบจะ*ไม่*เดาผลในกรณีนี้ จึงลด false positive ได้

## ตามหาบัญชี IG / Facebook / TikTok / X ของคนเดียวกัน

Instagram, Facebook, TikTok, X และ Threads **บล็อกการตรวจอัตโนมัติ** (ส่งหน้าเดียวกันกลับมาไม่ว่าบัญชีจะมีจริงหรือไม่) Sleuth จึงไม่เดาผล แต่ใช้วิธีที่นักสืบ OSINT ใช้จริง:

1. **ตามลิงก์ที่เจ้าของใส่ไว้เอง:** ถ้าบัญชีที่เจอ (Linktree, GitHub, YouTube, Twitch, Gravatar, About.me ฯลฯ) ลิงก์ไปหา IG / FB / TikTok / X ระบบจะบันทึกเป็นบัญชี **"เชื่อมโยง"** พร้อมหลักฐาน แล้วเอา handle นั้นไปค้นต่อบนเว็บอื่น
2. **อ่าน bio:** จับข้อความแบบ `IG: @name`, `tiktok @name`, `เฟส: name`, `ติ๊กต็อก @name`
3. **ลองชื่อใกล้เคียง** (`-v` หรือติ๊กในหน้าเว็บ): `john.doe` → `johndoe`, `john_doe`, `john-doe`
4. **ตรวจเอง:** IG / FB / TikTok / X / Threads ที่ยังไม่มีหลักฐาน จะขึ้นในแท็บ **"ตรวจเอง"** กด "เปิดตรวจ" เพื่อดูในเบราว์เซอร์ของคุณ ถ้าเจอก็กด **"✓ เจอแล้ว"**
5. **เทียบรูปโปรไฟล์:** ถ้าบัญชีบนเว็บต่าง ๆ ใช้รูปเดียวกัน (เทียบด้วย perceptual hash แม้ขนาดรูปต่างกันก็จับได้) จะนับเป็นหลักฐาน และระบบจะข้ามรูป default เช่นรูปช้างของ Mastodon
6. **ค้นใน archive.org:** สำหรับ IG / FB / TikTok / X ถ้า Wayback Machine เคยเก็บหน้าโปรไฟล์ไว้ แปลว่าบัญชีน่าจะมีจริง กด "ดูหน้าที่เก็บไว้" เพื่อดูได้โดยไม่ต้อง login
7. **ปุ่มค้นต่อใน Google:** เช่น `"username" site:instagram.com` และ `site:pantip.com`
8. **สรุปตัวตน:** จัดระดับความมั่นใจของแต่ละบัญชี
   - **สูง:** เจ้าของลิงก์ไว้เอง, รูปเหมือนบัญชีที่ยืนยันแล้ว หรือคุณยืนยันเอง
   - **กลาง:** ชื่อจริง (2 คำขึ้นไป) หรือรูปโปรไฟล์ตรงกับบัญชีอื่น
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
├── engine.py         ตัวค้นหา async, ตัดสินผล, recursive search
├── extractor.py      ดึงข้อมูลโปรไฟล์จาก HTML / JSON-LD / JSON API
├── report.py         รายงาน TXT / CSV / JSON / HTML
├── selfcheck.py      ทดสอบกฎกับเว็บจริง
├── web.py            Web UI server (SSE streaming)
├── static/           หน้าเว็บ (index.html = ค้น username, scan.html = สแกนเป้าหมาย)
├── cli.py            คำสั่ง command line
└── scan/             ระบบสแกนแบบ SpiderFoot
    ├── core.py       event, scanner, scope และงบจำกัด
    ├── modules/      dns.py, network.py, web.py, identity.py
    ├── correlate.py  กฎสรุปความเสี่ยง
    ├── store.py      ประวัติการสแกน (SQLite)
    └── report.py     รายงาน HTML / JSON
```

### เพิ่ม module ใหม่

สร้าง class ที่สืบทอด `Module` แล้วใส่ไว้ใน `ALL_MODULES` ใน `sleuth/scan/modules/__init__.py`

```python
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

## ⚠️ ใช้อย่างรับผิดชอบ

ใช้เฉพาะข้อมูลสาธารณะเพื่อวัตถุประสงค์ที่ชอบธรรม เช่น ตรวจ digital footprint ของตัวเอง งานวิจัย หรือ OSINT/pentest ที่ได้รับอนุญาต
username เดียวกันบนคนละเว็บ**ไม่จำเป็นต้องเป็นคนเดียวกัน** ควรตรวจสอบก่อนสรุปผลเสมอ และควรเคารพข้อกำหนดการใช้งานของแต่ละเว็บ
