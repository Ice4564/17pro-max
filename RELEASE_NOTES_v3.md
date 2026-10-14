# Sleuth v3.0.0 — "Hardcore OSINT"

อัปเกรดครั้งใหญ่: เพิ่ม **46 ฟีเจอร์** ใน **10 หมวด** พร้อม **10 โมดูลใหม่** (~4,200 บรรทัด)

## โมดูลใหม่

### 1. Archive Intelligence — [archive.py](sleuth/archive.py)
- **Wayback Machine** — ค้น snapshot เก่าของโปรไฟล์ผ่าน CDX API, หาเนื้อหาที่ถูกลบ
- **archive.today** — ค้น snapshot ที่บันทึกไว้
- **Google Cache** — URL builder สำหรับเวอร์ชันแคช
- **Deleted content detection** — เทียบ archived snapshots กับสถานะปัจจุบันเพื่อตรวจการลบ

### 2. Infrastructure Intelligence — [infra_intel.py](sleuth/infra_intel.py)
- **Certificate Transparency (crt.sh)** — ค้น CT logs หาโดเมนที่เชื่อมกับอีเมล/ชื่อ
- **Shodan** — ค้นอุปกรณ์/เซอร์วิส/พอร์ต/ช่องโหว่ ที่เชื่อมกับ IP
- **DNS resolution** — A/AAAA/MX/NS/TXT/CNAME ผ่าน Google DNS-over-HTTPS
- **Subdomain enumeration** — รวม CT logs + HackerTarget
- **WHOIS lookup** — ข้อมูลการจดโดเมน, ผู้จด, วันที่, email
- **IP geolocation** — ตำแหน่ง + ASN + org ผ่าน ipinfo.io
- **Combined infra scan** — รันทุกอย่างพร้อมกัน

### 3. Image Forensics — [forensics.py](sleuth/forensics.py)
- **LSB Steganography detection** — ตรวจข้อมูลซ่อนในรูปด้วย chi-square analysis
- **Error Level Analysis (ELA)** — ตรวจการแก้ไข/ตัดต่อด้วย JPEG re-compression
- **Face detection** — ตัดใบหน้าด้วย YCbCr skin-tone heuristic (pure Python, no ML)
- **Image hash clustering** — pHash (DCT) + color histogram + Hamming distance
- **Deepfake indicators** — frequency-domain analysis ตรวจ GAN artifacts
- **Full forensic analysis** — รันทุกการตรวจพร้อมกัน

### 4. Behavioral Profiling — [behavior.py](sleuth/behavior.py)
- **Timezone inference** — อนุมานเขตเวลาจากรูปแบบเวลาที่โพสต์
- **Activity heatmap** — กริด 7×24 (วัน×ชั่วโมง) พร้อม peak detection
- **Stylometry** — วิเคราะห์ลายมือเขียน (sentence length, word length, punctuation, capitalization, vocabulary richness) เทียบข้ามแพลตฟอร์ม
- **Emoji fingerprint** — ลายเซ็นอิโมจิ + Jaccard similarity comparison
- **Hashtag/interest analysis** — จัดหมวดความสนใจ (tech, gaming, music, art, finance, fitness, travel, food, fashion, politics)

### 5. Deep Search — [deepsearch.py](sleuth/deepsearch.py)
- **Google Dorking automation** — สร้าง advanced operators (site:, intext:, inurl:, intitle:, filetype:) อัตโนมัติ สำหรับ username/email/domain/phone
- **Reddit deep search** — ค้น submissions + user profile lookup ผ่าน JSON API
- **4chan archive search** — ค้นใน archive.4plebs.org
- **Discord server/user search** — URL builders สำหรับ disboard.org และ discord.id
- **GitHub code search** — ค้น code + users ผ่าน GitHub API
- **GitLab search** — ค้น projects ผ่าน GitLab API
- **Academic search** — Google Scholar, ORCID (public API), ResearchGate URL builders
- **Paste site monitor** — ค้น pastebin ผ่าน Google site: search
- **Social geosearch** — URL builders สำหรับ Twitter/Instagram/Flickr/YouTube geosearch

### 6. Threat Intelligence Export — [threatintel.py](sleuth/threatintel.py)
- **IOC extraction** — ดึง IPs (v4/v6), URLs, emails, hashes (MD5/SHA1/SHA256), CVEs, ETH/BTC addresses, domains จากข้อความ
- **STIX 2.1 export** — ส่งออกเป็น STIX bundle (identity + indicator objects)
- **MISP event export** — ส่งออกเป็น MISP event JSON พร้อม attributes + tags
- **Maltego graph XML** — ส่งออกกราฟในรูปแบบ Maltego .graph (entities + edges)
- **OpenCTI export** — STIX bundle พร้อม SRO relationship objects

### 7. Counter-OSINT — [counter.py](sleuth/counter.py)
- **Privacy risk score** — คะแนน 0-100 พร้อมระดับ (Critical/High/Moderate/Low/Minimal) วิเคราะห์จากข้อมูลที่เปิดเผย
- **Self-footprint checker** — ตรวจ footprint ตัวเอง "คนอื่นเจออะไรเกี่ยวกับคุณได้บ้าง"
- **Remediation guide** — คู่มือทีละขั้นตอนสำหรับ Instagram/Twitter/Facebook/TikTok/GitHub/Reddit/LinkedIn/YouTube
- **Remediation plan** — แผนแก้ไขจัดลำดับความสำคัญตาม risk factors
- **Exposure timeline** — timeline ของการเปิดเผยข้อมูล (account creation, data exposure, avatar exposure)

### 8. Visualization — [viz.py](sleuth/viz.py)
- **Network graph data** — D3.js force-directed graph (nodes: accounts/identities/emails/domains/crypto, edges: relationships)
- **Timeline data** — เหตุการณ์เรียงตามเวลา พร้อม category + importance
- **Geographic heatmap data** — พิกัดจาก location names + IP geolocation
- **Activity calendar** — GitHub-style contribution graph (52 weeks × 7 days, 5 levels)
- **Dashboard data** — รวมทุกอย่างในโครงสร้างเดียวสำหรับ web UI

### 9. Real-time & Automation — [realtime.py](sleuth/realtime.py)
- **WebSocket AlertManager** — แจ้งเตือน real-time เมื่อเจอบัญชีใหม่/โปรไฟล์เปลี่ยน/scan เสร็จ
- **RSS/Atom feed monitor** — ติดตาม feeds หาการกล่าวถึงเป้าหมาย (RSS + Atom parser)
- **Auto-Investigation mode** — วางแผนค้นหาอัตโนมัติ (archive check → mutations → IOC extraction → deep search → infra scan → behavior analysis → privacy assessment)
- **Scheduled scan + email delivery** — กำหนดเวลา scan ส่งรายงานทางอีเมล (SMTP)

### 10. Case Management — [casemgmt.py](sleuth/casemgmt.py)
- **Investigation playbooks** — 5 เทมเพลต: Missing Person, Fraud, Identity Theft, Threat Assessment, Due Diligence (พร้อมขั้นตอน + legal notes)
- **Evidence chain of custody** — ติดตามการจัดการหลักฐาน (SQLite, SHA-256 hashing, verification)
- **Multi-investigator notes** — บันทึกหมายเหตุร่วม (add/search/pin/delete)
- **Tagging & annotation** — ติดป้ายผลการค้นหา (confirmed/suspicious/false_positive/high_value/monitor/deleted/bot/impersonation) + confidence score

## สถิติ
- **10 โมดูลใหม่** (~4,200 บรรทัด)
- **46 ฟีเจอร์ใหม่**
- **46 เทสต์ใหม่** (รวม 119 เทสต์ — ผ่านครบ)
- **0 breaking changes**
- Python ≥ 3.10 · Pillow ≥ 10 · aiohttp ≥ 3.9
