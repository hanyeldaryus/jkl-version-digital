import os
import re
import uuid
from datetime import date, datetime
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request,
                   url_for)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import io
import logging
import secrets
from datetime import timedelta

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import send_file, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from sqlalchemy.types import Text, TypeDecorator
from werkzeug.middleware.proxy_fix import ProxyFix

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

load_dotenv()

BASE = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
def wajib_env(nama):
    nilai = os.environ.get(nama)
    if not nilai:
        raise RuntimeError(f"Environment variable {nama} belum diatur. Lihat .env.example")
    return nilai


PROD = os.environ.get("APP_ENV") == "production"

def database_url():
    url = os.environ.get("DATABASE_URL")
    if not url:
        return "sqlite:///" + os.path.join(BASE, "jkl.db")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"): ]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"): ]
    return url


app.config.update(
    SECRET_KEY=wajib_env("SECRET_KEY"),
    SQLALCHEMY_DATABASE_URI=database_url(),
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
    # Dipertahankan untuk kompatibilitas lokal; dokumen produksi disimpan di DB.
    UPLOAD_FOLDER=os.path.join(BASE, "uploads"),
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=PROD,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=PROD,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)
if os.environ.get("TRUST_PROXY") == "1":  # di belakang reverse proxy/load balancer
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
Talisman(app, force_https=PROD, strict_transport_security=PROD, session_cookie_secure=PROD,
         frame_options="DENY", referrer_policy="no-referrer",
         content_security_policy={"default-src": "'self'",
                                  "style-src": ["'self'", "https://cdn.jsdelivr.net"],
                                  "img-src": ["'self'", "data:"], "frame-ancestors": "'none'"})
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"],
                  storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"))
db = SQLAlchemy(app)
CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"
cipher = Fernet(wajib_env("ENCRYPTION_KEY"))

# Vercel/serverless tidak cocok untuk file log lokal yang persisten.
# StreamHandler membuat audit masuk ke runtime logs Vercel dan tetap bisa dipakai lokal.
_h = logging.StreamHandler()
_h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
audit_log = logging.getLogger("audit")
audit_log.setLevel(logging.INFO)
if not audit_log.handlers:
    audit_log.addHandler(_h)


def audit(event, **kw):
    """Catat kejadian keamanan. Nilai dibersihkan (anti log-injection); jangan pernah log password/NIK."""
    bersih = lambda v: re.sub(r"[^\w.@:/-]", "?", str(v))[:60]
    user = current_user.username if current_user.is_authenticated else "-"
    audit_log.info("%s ip=%s user=%s %s", event, request.remote_addr, user,
                   " ".join(f"{k}={bersih(v)}" for k, v in kw.items()))


class Terenkripsi(TypeDecorator):
    """Kolom dienkripsi at-rest dengan Fernet (AES-128-CBC + HMAC)."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, v, dialect):
        return cipher.encrypt(v.encode()).decode() if v else v

    def process_result_value(self, v, dialect):
        return cipher.decrypt(v.encode()).decode() if v else v


OWN_ONLY = ("dealer", "marketing")  # hanya boleh melihat record milik sendiri
KAWIN = ("Belum kawin", "Kawin", "Cerai")
ASURANSI = ("All risk", "TLO", "Kombinasi")
MAGIC = {"pdf": b"%PDF", "png": b"\x89PNG\r\n\x1a\n", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff"}
MIME = {"pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}
DUMMY_HASH = generate_password_hash("dummy-untuk-timing")


# ---- Konfigurasi domain -------------------------------------------------
STATUS = ["Diajukan", "Disetujui", "Dokumen dicetak", "Sudah TTD", "Dicairkan", "Ditolak"]
ROLES = {"dealer": "Sales Dealer", "marketing": "Marketing",
         "atasan": "Atasan Marketing", "backoffice": "Admin Backoffice"}
TRANSISI = {  # role -> {status sekarang: [status tujuan]}
    "atasan": {"Diajukan": ["Disetujui", "Ditolak"]},
    "backoffice": {"Disetujui": ["Dokumen dicetak"], "Dokumen dicetak": ["Sudah TTD"],
                   "Sudah TTD": ["Dicairkan"]},
}
LABEL_AKSI = {"Disetujui": "Setujui", "Ditolak": "Tolak", "Dokumen dicetak": "Buat kontrak dan PO",
              "Sudah TTD": "Simpan dokumen TTD", "Dicairkan": "Cairkan dana"}
JENIS_DOK = {"ktp": "KTP", "tanda_jadi": "Bukti bayar tanda jadi",
             "form_aplikasi": "Form aplikasi pengajuan", "kk": "Kartu keluarga", "ttd": "Dokumen TTD"}
DOK_WAJIB = ("ktp", "tanda_jadi", "form_aplikasi", "kk")
BUNGA_FLAT = 10  # persen per tahun (asumsi)
EXT = {"pdf", "png", "jpg", "jpeg"}


# ---- Model --------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    nama = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    @property
    def role_label(self):
        return ROLES[self.role]


class Pengajuan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kode = db.Column(db.String(20), unique=True, nullable=False)
    nama = db.Column(db.String(100), nullable=False)
    nik = db.Column(Terenkripsi, nullable=False)
    tgl_lahir = db.Column(db.Date, nullable=False)
    status_kawin = db.Column(db.String(20), nullable=False)
    nama_pasangan = db.Column(Terenkripsi)
    nik_pasangan = db.Column(Terenkripsi)
    dealer = db.Column(db.String(100), nullable=False)
    merk = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    tipe = db.Column(db.String(50))
    warna = db.Column(db.String(30))
    harga = db.Column(db.Integer, nullable=False)
    asuransi = db.Column(db.String(20), nullable=False)
    dp = db.Column(db.Integer, nullable=False)
    tenor = db.Column(db.Integer, nullable=False)
    angsuran = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default="Diajukan", index=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    dokumen = db.relationship("Dokumen", backref="pengajuan", cascade="all, delete-orphan")
    riwayat = db.relationship("Riwayat", backref="pengajuan", order_by="Riwayat.waktu",
                              cascade="all, delete-orphan")


class Dokumen(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pengajuan_id = db.Column(db.Integer, db.ForeignKey("pengajuan.id"), nullable=False)
    jenis = db.Column(db.String(20), nullable=False)
    file = db.Column(db.String(60), nullable=False)
    asli = db.Column(db.String(150), nullable=False)
    # Isi file terenkripsi. Dipakai agar deployment Vercel tidak bergantung pada filesystem.
    data = db.Column(db.LargeBinary, nullable=True)


class Riwayat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pengajuan_id = db.Column(db.Integer, db.ForeignKey("pengajuan.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    catatan = db.Column(db.String(300), default="")
    waktu = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship("User")


@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


# ---- Helper -------------------------------------------------------------
@app.template_filter("rp")
def rp(n):
    return "Rp{:,.0f}".format(n or 0).replace(",", ".")


@app.context_processor
def konteks():
    return dict(STATUS=STATUS, JENIS_DOK=JENIS_DOK, TRANSISI=TRANSISI, LABEL_AKSI=LABEL_AKSI)


def roles_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return f(*a, **k)
        return wrapper
    return deco


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def ext_ok(nama):
    return "." in nama and nama.rsplit(".", 1)[1].lower() in EXT


def hitung_angsuran(harga, dp, tenor):
    return round((harga - dp) * (1 + BUNGA_FLAT / 100 * tenor / 12) / tenor)


def file_ok(fl):
    """Cek ekstensi DAN magic bytes, bukan hanya nama file."""
    if not fl or not fl.filename or not ext_ok(fl.filename):
        return False
    kepala = fl.stream.read(8)
    fl.stream.seek(0)
    return kepala.startswith(MAGIC[fl.filename.rsplit(".", 1)[1].lower()])


def simpan_file(file, jenis, p):
    """Simpan dokumen terenkripsi di database agar aman untuk runtime serverless."""
    ext = file.filename.rsplit(".", 1)[1].lower()
    nama = f"{uuid.uuid4().hex}.{ext}"
    encrypted = cipher.encrypt(file.read())
    p.dokumen.append(
        Dokumen(
            jenis=jenis,
            file=nama,
            asli=secure_filename(file.filename)[:150],
            data=encrypted,
        )
    )


def catat(p, status, catatan=""):
    p.status = status
    db.session.add(Riwayat(pengajuan=p, user_id=current_user.id, status=status, catatan=catatan))


def ambil(id):
    p = db.get_or_404(Pengajuan, id)
    if current_user.role in OWN_ONLY and p.created_by != current_user.id:
        audit("akses_record_ditolak", id=id)
        abort(404)  # 404 agar keberadaan record tidak bisa ditebak
    return p


def validasi(f, files):
    e = []
    if not re.fullmatch(r"[A-Za-z .,'-]{2,100}", f.get("nama", "").strip()):
        e.append("Nama hanya boleh huruf (2-100 karakter).")
    for k, lbl in (("dealer", "Dealer"), ("merk", "Merk"), ("model", "Model")):
        if not 1 <= len(f.get(k, "").strip()) <= 50:
            e.append(f"{lbl} wajib diisi (maks. 50 karakter).")
    for k in ("tipe", "warna"):
        if len(f.get(k, "")) > 50:
            e.append(f"{k.capitalize()} maksimal 50 karakter.")
    if not re.fullmatch(r"\d{16}", f.get("nik", "")):
        e.append("NIK harus 16 digit angka.")
    try:
        umur = (date.today() - date.fromisoformat(f.get("tgl_lahir", ""))).days / 365.25
        if not 17 <= umur <= 100:
            e.append("Usia konsumen harus 17-100 tahun.")
    except ValueError:
        e.append("Tanggal lahir tidak valid.")
    if f.get("status_kawin") not in KAWIN:
        e.append("Status perkawinan tidak valid.")
    elif f["status_kawin"] == "Kawin" and (not f.get("nama_pasangan", "").strip()
                                           or not re.fullmatch(r"\d{16}", f.get("nik_pasangan", ""))):
        e.append("Nama dan NIK (16 digit) pasangan wajib diisi.")
    if f.get("asuransi") not in ASURANSI:
        e.append("Jenis asuransi tidak valid.")
    harga, dp = to_int(f.get("harga")), to_int(f.get("dp"))
    if not 0 < harga <= 10_000_000_000:
        e.append("Harga kendaraan harus antara 1 dan 10 miliar.")
    elif not 0 <= dp < harga:
        e.append("Down payment harus di antara 0 dan harga kendaraan.")
    if to_int(f.get("tenor")) not in (12, 24, 36, 48):
        e.append("Lama kredit tidak valid.")
    for k in DOK_WAJIB:
        if not file_ok(files.get(k)):
            e.append(f"Dokumen {JENIS_DOK[k]} wajib berupa PDF/JPG/PNG yang valid.")
    return e


# ---- Route --------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}, 200


@app.before_request
def wajib_login():
    """Default-deny: semua endpoint butuh login kecuali yang di-allowlist."""
    if request.endpoint not in ("login", "static", "health") and not current_user.is_authenticated:
        return login_manager.unauthorized()


@app.after_request
def jangan_cache(resp):
    if current_user.is_authenticated:
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(403)
def e403(e):
    audit("akses_ditolak", path=request.path)
    return "Akses ditolak.", 403


for _kode, _pesan in ((400, "Permintaan tidak valid."), (404, "Data tidak ditemukan."),
                      (413, "File terlalu besar (maks. 5 MB)."),
                      (429, "Terlalu banyak percobaan. Coba lagi nanti."), (500, "Terjadi kesalahan pada server.")):
    app.register_error_handler(_kode, lambda e, m=_pesan: (m, getattr(e, "code", 500)))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute; 30 per hour", methods=["POST"])
def login():
    if request.method == "POST":
        if request.form.get("website"):  # honeypot: manusia tidak melihat field ini
            audit("bot_terdeteksi")
            abort(400)
        username = request.form.get("username", "").strip()[:50]
        u = User.query.filter_by(username=username).first()
        # selalu verifikasi hash agar waktu respons tidak membocorkan username valid
        ok = check_password_hash(u.password_hash if u else DUMMY_HASH, request.form.get("password", "")[:200])
        if u and ok:
            session.clear()  # cegah session fixation
            login_user(u)
            session.permanent = True
            audit("login_sukses")
            return redirect(url_for("index"))
        audit("login_gagal", username=username)
        flash("Username atau password salah.", "danger")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    q = Pengajuan.query
    if current_user.role in OWN_ONLY:
        q = q.filter_by(created_by=current_user.id)
    counts = dict(q.with_entities(Pengajuan.status, func.count()).group_by(Pengajuan.status).all())
    aktif = request.args.get("status")
    if aktif in STATUS:
        q = q.filter_by(status=aktif)
    return render_template("index.html", rows=q.order_by(Pengajuan.id.desc()).all(),
                           counts=counts, aktif=aktif)


@app.route("/pengajuan/baru", methods=["GET", "POST"])
@roles_required("dealer", "marketing")
def baru():
    f = request.form
    if request.method == "POST":
        if f.get("website"):
            audit("bot_terdeteksi")
            abort(400)
        err = validasi(f, request.files)
        if not err:
            harga, dp, tenor = int(f["harga"]), int(f["dp"]), int(f["tenor"])
            p = Pengajuan(
                kode="tmp", nama=f["nama"].strip(), nik=f["nik"],
                tgl_lahir=date.fromisoformat(f["tgl_lahir"]), status_kawin=f["status_kawin"],
                nama_pasangan=f["nama_pasangan"].strip()[:100] if f["status_kawin"] == "Kawin" else "",
                nik_pasangan=f["nik_pasangan"] if f["status_kawin"] == "Kawin" else "",
                dealer=f["dealer"].strip(), merk=f["merk"].strip(), model=f["model"].strip(),
                tipe=f.get("tipe", "").strip(), warna=f.get("warna", "").strip(),
                harga=harga, asuransi=f["asuransi"], dp=dp, tenor=tenor,
                angsuran=hitung_angsuran(harga, dp, tenor), created_by=current_user.id)
            db.session.add(p)
            db.session.flush()
            p.kode = f"PGJ-{datetime.now():%y%m}-{p.id:04d}"
            for k in DOK_WAJIB:
                simpan_file(request.files[k], k, p)
            catat(p, "Diajukan")
            db.session.commit()
            audit("pengajuan_dibuat", kode=p.kode)
            flash(f"Pengajuan {p.kode} berhasil dikirim.", "success")
            return redirect(url_for("detail", id=p.id))
        for m in err:
            flash(m, "danger")
    return render_template("form.html", f=f)


@app.route("/pengajuan/<int:id>")
@login_required
def detail(id):
    return render_template("detail.html", p=ambil(id))


@app.post("/pengajuan/<int:id>/aksi")
@login_required
def aksi(id):
    p = ambil(id)
    target = request.form.get("target")
    catatan = request.form.get("catatan", "").strip()[:300]
    if target not in TRANSISI.get(current_user.role, {}).get(p.status, []):
        abort(403)
    if target == "Ditolak" and not catatan:
        flash("Catatan wajib diisi saat menolak pengajuan.", "danger")
        return redirect(url_for("detail", id=id))
    if target == "Sudah TTD":
        fl = request.files.get("ttd")
        if not file_ok(fl):
            flash("Unggah dokumen TTD dalam format PDF/JPG/PNG yang valid.", "danger")
            return redirect(url_for("detail", id=id))
        simpan_file(fl, "ttd", p)
    # kunci optimistis: hanya berhasil jika status belum diubah pengguna lain
    dikunci = Pengajuan.query.filter_by(id=id, status=p.status).update({"status": target})
    if dikunci != 1:
        db.session.rollback()
        flash("Pengajuan sudah diproses pengguna lain. Muat ulang halaman.", "warning")
        return redirect(url_for("detail", id=id))
    catat(p, target, catatan)
    db.session.commit()
    audit("status_berubah", kode=p.kode, ke=target)
    flash(f"Status diperbarui menjadi {target}.", "success")
    return redirect(url_for("detail", id=id))


@app.route("/dokumen/<int:id>")
@login_required
def dokumen(id):
    d = db.get_or_404(Dokumen, id)
    ambil(d.pengajuan_id)  # cek kepemilikan record induk
    if d.data:
        data = cipher.decrypt(bytes(d.data))
    else:
        # Fallback untuk database lokal versi lama yang masih memakai uploads/.
        path = os.path.join(app.config["UPLOAD_FOLDER"], os.path.basename(d.file))
        if not os.path.exists(path):
            abort(404)
        with open(path, "rb") as fh:
            data = cipher.decrypt(fh.read())
    audit("dokumen_diunduh", id=id)
    return send_file(io.BytesIO(data), mimetype=MIME[d.file.rsplit(".", 1)[1]],
                     as_attachment=True, download_name=d.asli)


@app.route("/pengajuan/<int:id>/pdf")
@login_required
def pengajuan_pdf(id):
    """Generate PDF in memory; tidak menulis file ke filesystem Vercel."""
    p = ambil(id)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
        title=f"Laporan Pengajuan {p.kode}",
        author="PT. JKL Kredit Digital",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "JKLTitle", parent=styles["Title"], alignment=TA_CENTER,
        fontSize=16, spaceAfter=8
    )
    subtitle_style = ParagraphStyle(
        "JKLSubtitle", parent=styles["Normal"], alignment=TA_CENTER,
        fontSize=9, textColor=colors.grey, spaceAfter=18
    )

    story = [
        Paragraph("PT. JKL KREDIT DIGITAL", title_style),
        Paragraph(f"LAPORAN PENGAJUAN KREDIT — {p.kode}", subtitle_style),
    ]

    data = [
        ["Kode Pengajuan", p.kode],
        ["Nama Konsumen", p.nama],
        ["NIK", p.nik],
        ["Tanggal Lahir", p.tgl_lahir.strftime("%d/%m/%Y")],
        ["Status Perkawinan", p.status_kawin],
        ["Pasangan", p.nama_pasangan or "-"],
        ["Dealer", p.dealer],
        ["Merk / Model", f"{p.merk} / {p.model}"],
        ["Tipe", p.tipe or "-"],
        ["Warna", p.warna or "-"],
        ["Harga Kendaraan", rp(p.harga)],
        ["Down Payment", rp(p.dp)],
        ["Tenor", f"{p.tenor} bulan"],
        ["Angsuran / Bulan", rp(p.angsuran)],
        ["Asuransi", p.asuransi],
        ["Status", p.status],
        ["Dibuat", p.created_at.strftime("%d/%m/%Y %H:%M") if p.created_at else "-"],
    ]

    table = Table(data, colWidths=[155, 335], repeatRows=0)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeee")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(table)
    story.append(Spacer(1, 18))
    story.append(Paragraph(
        "Dokumen ini dibuat secara otomatis oleh sistem PT. JKL Kredit Digital.",
        styles["Normal"]
    ))

    doc.build(story)
    buffer.seek(0)
    audit("pdf_pengajuan_dibuat", kode=p.kode)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{p.kode}.pdf",
    )


@app.cli.command("seed")
def seed():
    """Buat tabel dan akun awal. Password acak hanya tampil sekali; simpan di password manager."""
    db.create_all()
    for u, n, r in (("dealer1", "Budi (Sales Dealer)", "dealer"), ("marketing1", "Sari (Marketing)", "marketing"),
                    ("atasan1", "Andi (Atasan Marketing)", "atasan"), ("backoffice1", "Rina (Admin Backoffice)", "backoffice")):
        if not User.query.filter_by(username=u).first():
            pw = secrets.token_urlsafe(12)
            db.session.add(User(username=u, nama=n, role=r, password_hash=generate_password_hash(pw)))
            print(f"{u}: {pw}")
    db.session.commit()


if __name__ == "__main__":
    app.run(debug=False)
