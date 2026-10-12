# Sleuth v2.0.0

เวอร์ชันนี้ต่อยอดงานสืบสวนจาก v1.1 ด้วยการ **วิเคราะห์ข้อมูลจากโปรไฟล์ที่เจอแล้ว** เพิ่ม search engine ประจำภูมิภาค รายงาน Excel และการเทียบผลสองครั้งแบบเคียงข้างกัน พร้อม Docker และ CI

## ของใหม่

### วิเคราะห์โปรไฟล์ (Enrichment) — [enrich.py](sleuth/enrich.py)
หลังค้นเสร็จ ระบบวิเคราะห์จากข้อมูลสาธารณะที่ดึงมาแล้ว **โดยไม่ยิงเว็บเพิ่ม** แสดงในแฟ้มบุคคลและรายงาน:
- **ภาษาที่ใช้** ในโปรไฟล์ (ไทย/อังกฤษ/จีน/ญี่ปุ่น/เกาหลี ฯลฯ จากช่วงอักขระ)
- **ค้นรูปโปรไฟล์ซ้ำ** (reverse image search) — ลิงก์ Google Lens, TinEye, Yandex, Bing (ข้ามรูป default อัตโนมัติ)
- **คริปโต/ENS** — ชื่อ `.eth` และ address `0x...` ที่พบในโปรไฟล์
- **เบอร์โทรไทย** ที่ระบุไว้ในโปรไฟล์ (normalize + บอกค่ายมือถือ/ภูมิภาค)
- **สัญญาณบอต** — heuristic จากรูปแบบ username, bio, สัดส่วนผู้ติดตาม, อายุบัญชี (แสดงเฉพาะที่น่าสงสัย)

### โมดูลวิเคราะห์ — [analysis.py](sleuth/analysis.py)
bot detection, sentiment (EN/TH), language detection, graph centrality (Brandes), temporal pattern — pure Python ไม่ต้องใช้ ML

### Regional — [regional.py](sleuth/regional.py)
- normalize เบอร์โทรไทย + รหัสพื้นที่ (แก้ให้ถูกต้องแล้ว)
- ลิงก์ค้นใน search engine ประจำภูมิภาค: Baidu, Yandex, Naver, Seznam, Yahoo Japan, Sogou, Qwant
- ลิงก์ค้นข่าวไทย: ThaiPBS, Bangkok Post, The Nation, Khaosod, Matichon

### Crypto — [crypto.py](sleuth/crypto.py)
ENS resolution, wallet lookup (Etherscan), wallet clustering, ดึง ENS/address จากข้อความ

### Imaging — [imaging.py](sleuth/imaging.py)
ตัวสร้างลิงก์ reverse image search + อ่าน EXIF/GPS จากรูป (ต้องมี Pillow)

### รายงาน
- **Excel (.xlsx)** — หลายชีต (บัญชี, ตัวตน, หลักฐาน, timeline, การเปลี่ยนแปลง) ต้องมี `openpyxl` ไม่มีก็ตกไปเป็น CSV
- **เทียบผลสองครั้งแบบเคียงข้างกัน** (`to_comparison_html`) — บัญชีที่เพิ่ม/หาย/เปลี่ยน
- ปุ่มสลับธีมในรายงาน HTML, responsive บนมือถือ, แผนที่จากพิกัด EXIF

### Infrastructure
- **105 เว็บ** (เพิ่ม Pantip, Wongnai, Bitbucket, Replit, Stack Overflow, Vimeo, Weibo, Zhihu, Bilibili, Naver Blog ฯลฯ)
- **Docker** — [Dockerfile](Dockerfile) + [docker-compose.yml](docker-compose.yml)
- **GitHub Actions CI** — รันเทสต์บน Ubuntu/Windows/macOS × Python 3.10–3.13

## ที่ตัดออกโดยตั้งใจ
เพื่อให้เครื่องมืออยู่ในขอบเขต "หาบัญชีสาธารณะอย่างรับผิดชอบ" รุ่นนี้ **ไม่รวม**: ชุดหลบการตรวจจับ (proxy rotation/หลบ WAF/CAPTCHA), การค้นฐานข้อมูลข้อมูลรั่ว (HIBP/DeHashed) และการถอด/ตรวจเลขบัตรประชาชน ซึ่งเสี่ยงเรื่องความเป็นส่วนตัวและข้อตกลงการใช้งานของเว็บ

## ความเข้ากันได้
- Python ≥ 3.10 · เทสต์ผ่านครบ (73 ข้อ) · ไม่มี breaking change
- `openpyxl` สำหรับ xlsx (ไม่มีก็ตกไปเป็น CSV), `pillow` สำหรับ EXIF (มีอยู่แล้ว)
