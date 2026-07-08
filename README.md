# wptoolsVai

> A single-file, self-contained **WordPress maintenance & recovery toolkit** written in PHP.
> File management, database cleanup, malware scanning, search-replace, admin recovery, backups, and more — all from one page.

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage-guide">Usage Guide</a> •
  <a href="#-security-must-read">Security</a> •
  <a href="https://smtir.github.io/wptoolsVai/">Landing Page</a>
</p>

---

## ⚠️ SECURITY — MUST READ FIRST

**This is an extremely powerful admin tool. Treat it like a loaded weapon.**

`wptoolsVai` can delete any file, run shell commands, read your database, create admin users, and modify core files. If an attacker reaches it, they own your server. **Before you deploy it anywhere public, you MUST:**

1. **Change the default login** (it ships as `admin` / `password` — see [Change the Password](#-change-the-password)).
2. **Restrict access by IP** (see [Restrict by IP](#-restrict-access-by-ip)).
3. **Delete or rename the file the moment you're done** using it. Do not leave it on a live server.
4. **Never commit `wp-config.php`, credentials, backups, or exports** to Git (already handled by `.gitignore`).

> The bundled `$allowed_ips` list may contain an example public IP — **remove it and add your own**.

---

## ✨ Features

| Tool | What it does |
|------|--------------|
| 🗂️ **File / Folder Manager** | Browse, select, and delete files & folders with a browser UI |
| ♻️ **Trash & Restore** | Soft-delete to trash and restore later |
| 💾 **Backup / Restore** | Back up items before deletion; restore from backups |
| 🗜️ **Zip / Unzip** | Create and extract archives |
| 🐛 **Malware Scanner** | Signature-based file scan + quarantine |
| 🧹 **Database Cleaner** | Remove transients, revisions, spam, orphaned meta, autoload bloat |
| 🔁 **DB Search-Replace** | Serialization-safe find & replace (e.g. domain migration), with **Dry Run** |
| 🛡️ **Admin User Manager** | List admins, reset passwords, **create a new admin** (lockout recovery) |
| 📤 **Database Export** | Full `.sql` dump (structure + data), streamed table-by-table |
| 🔎 **Core Integrity Checker** | Compares core files against official WordPress.org checksums |
| 🔐 **Fix Permissions** | Applies recommended WordPress file/folder permissions |
| ❤️ **Health Dashboard** | Disk, memory, PHP, and WordPress status |
| 🖥️ **Command Executor** | Runs read-only diagnostic shell commands (whitelisted) |

**Built for shared/cPanel hosting:** long operations run in **time-budgeted batches** with an adaptive queue, so large jobs never hit PHP timeouts.

---

## 📦 Requirements

- **PHP 7.4+** (tested on PHP 8.0 – 8.5)
- **MySQLi** extension (for database features)
- A WordPress installation (the tool auto-detects `wp-config.php` in its folder or one level up)

---

## 🚀 Installation

1. **Download** `tools.php` and `style.css` from this repository.
2. **Upload both** to your WordPress site — ideally the WordPress root (next to `wp-config.php`), or a subfolder.
3. **Change the default password** (see below) — do this *before* opening it in a browser.
4. Visit `https://your-site.com/tools.php` and log in.
5. **Remove the file** when finished.

```bash
# Example: clone and copy into your site
git clone https://github.com/smtir/wptoolsVai.git
cp wptoolsVai/tools.php wptoolsVai/style.css /path/to/your/wordpress/
```

---

## 🔑 Change the Password

Open `tools.php` and find (near the `--- CONFIGURATION ---` block):

```php
define('USERNAME', 'admin');
define('PASSWORD_HASH', password_hash('password', PASSWORD_DEFAULT));
```

**Do NOT leave this as-is.** Replace it with your own username and a **pre-computed hash** (so your plaintext password never sits in the file):

1. Generate a hash on any machine with PHP:

   ```bash
   php -r "echo password_hash('YOUR_STRONG_PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"
   ```

2. Paste the result:

   ```php
   define('USERNAME', 'yourname');
   define('PASSWORD_HASH', '$2y$10$abcdefg...your-generated-hash...');
   ```

Now the login checks against your hash, and the plaintext password is nowhere in the code.

---

## 🌐 Restrict Access by IP

Find the `$allowed_ips` array and the commented block below it. Put **your** IP in the list and **uncomment** the restriction:

```php
$allowed_ips = [
    '127.0.0.1',
    '::1',
    'YOUR.PUBLIC.IP.HERE',
];

// --- IP RESTRICTION (after login) ---
if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips)) {
    SecurityHelper::jsonError('Access denied: Your IP is not allowed.', 403);
}
```

Remove any example/unknown IPs that shipped in the list.

---

## 📖 Usage Guide

After logging in, use the **Quick Navigation** bar at the top to jump to any tool.

### Deleting files
1. Go to **Delete** → **Browse** to pick files/folders.
2. In **Advanced Options** (always visible near the top), choose:
   - **Dry Run** — preview only, nothing is deleted.
   - **Soft Delete** — move to Trash instead of permanent delete.
   - **Backup** — copy to `backups/` before deleting.
3. Click delete. Large batches run automatically in chunks with a progress bar.

### Database Cleaner
Click **Scan Database** → review each category (transients, revisions, spam, etc.) → **Clean Selected** or **Clean All**.

### DB Search-Replace (safe domain migration)
1. Enter **Search for** / **Replace with** (e.g. old → new domain).
2. Keep **Dry Run** checked and run — see how many rows/cells *would* change.
3. **Export the database first** (below) as a backup.
4. Uncheck Dry Run and run to apply. It is serialization-safe, so serialized settings stay valid.

### Admin User Manager (locked out of wp-admin?)
- **List Admins** to see all administrators.
- **Reset Password** on any admin, or **Create Admin** to make a brand-new one and log into WordPress.

### Database Export / Backup
Click **Export Database** → wait for the table-by-table progress → **Download .sql**. Do this before any destructive DB operation.

### Core Integrity Checker
Click **Check Core Integrity**. It fetches official checksums from WordPress.org for your exact version and reports any **modified** or **missing** core files — a strong signal of a compromise.

### Malware Scanner
Click **Start Scan** → review flagged files → **Quarantine** (safe, reversible) or delete.

### Fix Permissions
Applies WordPress-recommended permissions (dirs `0755`, files `0644`, `wp-config.php` `0640`, `uploads` group-writable).

---

## 🧰 Data & Folders

The tool creates these working folders next to itself (all Git-ignored):

```
trash/  backups/  quarantine/  db_exports/  zips/  presets/
*_sessions/   # batch-job progress state
```

---

## ❓ Troubleshooting

- **"Command execution is blocked"** — your host disabled `shell_exec`/`exec`/`system` in `php.ini`. This is normal on shared hosting; the diagnostic command tool simply won't run.
- **White screen / DB error after Fix Permissions** — some non-suEXEC hosts need `wp-config.php` at `0644`; adjust manually if needed.
- **Integrity check can't fetch checksums** — the host blocks outbound HTTP or `allow_url_fopen`/cURL are disabled.

---

## 📄 License

[MIT](LICENSE) © Tawhidul Islam

---

## 🙅 Disclaimer

This software is provided "as is", without warranty of any kind. You are solely responsible for how and where you deploy it. The authors are not liable for data loss, downtime, or security incidents. **Always keep backups.**
