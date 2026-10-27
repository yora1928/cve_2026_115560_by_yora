# CVE Checker — Defensive HTTP Diagnostics

Tool Python sederhana untuk diagnostik HTTP defensif terkait assessment CVE-2026-115560.

## Batasan penting
- Ini **bukan exploit** dan tidak mencoba RCE.
- Respons HTTP tidak dapat membuktikan konfigurasi PHP server-side.
- Gunakan hanya pada sistem milik sendiri atau yang secara eksplisit Anda berwenang uji.
- Program ini hanya melakukan HTTP GET dan tidak mengirim file upload.

## Persyaratan
- Python 3.11 atau lebih baru
- `requests`

## Instalasi

Windows:
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Penggunaan
```bash
python cve_checker.py --url https://example.com
python cve_checker.py --url https://example.com --timeout 20 --retries 1 --output report.json
python cve_checker.py --help
```

## Tes lokal
```bash
python -m unittest -v
```

Tes memakai mock dan tidak mengirim request ke server eksternal.

## Interpretasi
`NOT_ASSESSED` berarti pemeriksaan HTTP tidak dapat menentukan apakah prasyarat CVE terpenuhi. Periksa konfigurasi PHP dan kode aplikasi melalui akses administrator yang sah, lalu ikuti advisori resmi PHP untuk mitigasi dan patch.
