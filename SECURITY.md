# Membersihkan secret dari git

1. Anggap semua secret yang pernah ter-commit sudah bocor. ROTASI dulu: SECRET_KEY, password DB, semua API key.
   ENCRYPTION_KEY: jangan langsung diganti, data lama jadi tak terbaca. Re-enkripsi dulu dengan MultiFernet.
2. Cari kebocoran: `gitleaks detect --source . --log-opts="--all"`
3. Hapus dari riwayat: `git filter-repo --invert-paths --path .env --path jkl.db --path uploads`
4. Push ulang: `git push --force --all && git push --force --tags`. Minta semua kolaborator clone ulang.
5. Cegah terulang: `gitleaks protect --staged` sebagai pre-commit hook, dan aktifkan secret scanning di repo.
