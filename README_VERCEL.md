# PT. JKL Kredit Digital — Deploy ke Vercel

Project ini adalah Flask + SQLAlchemy untuk alur pengajuan kredit. Versi ini sudah disiapkan untuk deployment Vercel:

- Flask tetap memakai `app.py` di root.
- Tidak membutuhkan `vercel.json` atau folder `api/` untuk Flask modern di Vercel.
- PDF dibuat langsung di memory dengan ReportLab.
- Dokumen upload disimpan terenkripsi di database, bukan di filesystem deployment.
- Audit log memakai runtime log.
- PostgreSQL dipakai untuk deployment.

## 1. Install lokal

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Salin `.env.example` menjadi `.env`, lalu isi:

```env
APP_ENV=development
SECRET_KEY=isi-random-secret
ENCRYPTION_KEY=isi-fernet-key
DATABASE_URL=
RATELIMIT_STORAGE_URI=memory://
TRUST_PROXY=0
```

Generate key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Untuk lokal tanpa PostgreSQL, `DATABASE_URL` boleh dikosongkan sehingga memakai SQLite.

## 2. Jalankan lokal

```bash
python app.py
```

Buka `http://127.0.0.1:5000`.

Untuk membuat tabel dan akun demo:

```bash
flask --app app seed
```

Perintah `seed` akan menampilkan password acak untuk akun:

- `dealer1`
- `marketing1`
- `atasan1`
- `backoffice1`

Simpan password tersebut.

## 3. Database untuk Vercel

Gunakan PostgreSQL hosted, misalnya database PostgreSQL dari provider yang Anda pilih.

Ambil connection string PostgreSQL dan masukkan sebagai `DATABASE_URL` di Vercel.

Contoh format:

```text
postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME?sslmode=require
```

## 4. Inisialisasi database produksi

Sebelum membuka aplikasi produksi, jalankan seed dengan `DATABASE_URL` yang menunjuk ke database PostgreSQL produksi.

Contoh PowerShell:

```powershell
$env:APP_ENV="production"
$env:SECRET_KEY="secret-yang-sama-dengan-Vercel"
$env:ENCRYPTION_KEY="fernet-key-yang-sama-dengan-Vercel"
$env:DATABASE_URL="postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME?sslmode=require"
flask --app app seed
```

Jalankan hanya sekali pada database baru.

## 5. Environment Variables di Vercel

Set minimal:

```text
APP_ENV=production
SECRET_KEY=...
ENCRYPTION_KEY=...
DATABASE_URL=...
RATELIMIT_STORAGE_URI=memory://
TRUST_PROXY=1
```

Jangan masukkan `.env` ke GitHub.

## 6. Deploy

Import repository ini ke Vercel atau gunakan Vercel CLI:

```bash
npm i -g vercel
vercel
vercel --prod
```

Flask modern di Vercel dapat dideteksi tanpa `vercel.json` tambahan.

## 7. Cek deployment

Health check:

```text
/health
```

Contoh:

```text
https://DOMAIN-ANDA.vercel.app/health
```

Harus menghasilkan:

```json
{"status":"ok"}
```

## 8. PDF

Setelah login dan membuka detail pengajuan, klik:

**Cetak / Download PDF**

PDF dibuat di memory sehingga tidak membuat file PDF permanen di filesystem Vercel.

## Catatan upload

Batas form dibuat 4 MB total agar berada di bawah batas payload Function Vercel yang sekitar 4,5 MB. Untuk file yang lebih besar, gunakan object storage/client-side upload.
