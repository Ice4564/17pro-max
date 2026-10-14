# Sleuth v3.1.0 — Redesign & Hardening

ต่อยอดจาก v3.0.0 ด้วยการ **ยกเครื่องหน้าเว็บ** และ **ทำให้เชื่อถือได้/ปลอดภัย/ใช้ง่ายขึ้น** (ไม่เพิ่มการเก็บข้อมูลบุคคลที่สาม)

## หน้าเว็บใหม่ — Cyber HUD
ทุกหน้า (ค้น username / สแกน / Workspace) เป็นธีม command-center สีนีออน:
- ไล่สีไซยาน→ม่วงที่แบรนด์/หัวข้อ, ออโรราพื้นหลัง, เส้นนีออนใต้เมนู, มุม HUD รอบแผง
- หัวข้อแบบ terminal (`>` + เคอร์เซอร์กระพริบ), ปุ่มไล่สีเต้นเรืองแสง, stat tiles เรืองแสง
- ยังอ่านง่าย รองรับทั้งโหมดมืด (ค่าเริ่มต้น) และสว่าง, เคารพ `prefers-reduced-motion`
- แก้ปัญหาแคช: ใส่เวอร์ชันท้าย asset + ส่ง `no-cache` ให้หน้า HTML

## A — ความแม่น (Accuracy)
- **Benchmark การให้คะแนนตัวตน** ([benchmark.py](sleuth/benchmark.py)): ชุดคู่บัญชีที่รู้คำตอบ (คนเดียวกัน/คนละคน) วัด AUC + precision/recall ที่เกณฑ์ HIGH/MEDIUM → `python -m sleuth --benchmark` และมี regression test
- จาก benchmark พบว่ายังไม่ได้ใช้ **คริปโต/ENS** เป็นสัญญาณ จึงเพิ่มเข้า `similarity.compare` (AUC 0.87→1.00, high-confidence precision คง 1.00 = ไม่เหมาคนละคนเป็นคนเดียวกัน)

## B — ใช้อย่างรับผิดชอบ
- **ลบข้อมูล**: `--purge-target <user>` (ลบทุกอย่างของเป้าหมาย), `--purge-old <วัน>`, `--wipe-db` + แผง Privacy ในหน้า Workspace
- **ปิดบังรายงาน (redact)**: ซ่อนอีเมล/เบอร์/รูปโปรไฟล์ทุกฟอร์แมตก่อนแชร์ — checkbox ในหน้า Export หรือ `--redact`

## C — ความทนทาน
- โมดูลที่เรียก external API (Shodan, crt.sh, ipinfo, reddit...) คืนค่าว่างเมื่อเน็ตล่ม/ไม่มี key แทนที่จะพัง (มีเทสต์ยืนยัน)
- Shodan ไม่มี key จะไม่ยิง request ที่ล้มเหลวแน่ ๆ

## D — API keys / Settings
- หน้า **Settings เก็บ API key** ([settings.py](sleuth/settings.py)): Shodan, GitHub token, HIBP, ipinfo — อ่านจาก env (`SLEUTH_SHODAN_KEY` ฯลฯ) หรือ `~/.sleuth/keys.json`, ตั้งได้ในแผง Workspace, API ไม่คืนค่า key ออกมา

## ความเข้ากันได้
- Python ≥ 3.10 · **135 เทสต์ผ่าน** · ไม่มี breaking change
- โมดูล v3.0.0 (archive, infra_intel, forensics, behavior, deepsearch, threatintel, counter, realtime, casemgmt, viz) ยังอยู่ครบ
