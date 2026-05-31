# Lightbox Photo Gallery

![Version](https://img.shields.io/badge/version-v0.12-blue)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4)
![License](https://img.shields.io/badge/license-Apache%202.0-green)

A single-file PHP photo gallery for photographers and small portfolio sites. Drop one file onto any PHP server. No database, no build step, no dependencies.

**Live example:** [chrismarquardt.com/photo](https://chrismarquardt.com/photo/)

---

## What it does

Lightbox lets you publish a photo gallery that puts curated series front and centre. Visitors see handpicked collections of your best work first. Albums stay organised in the background as the source for images. A full album overview is always one click away.

### Key features

- **Zero dependencies.** One PHP file, no database, no Composer, no Node.
- **Curated series.** Present edited stories and projects. Pull images from multiple albums without copying files.
- **AI captions.** Generate per-photo captions via Google Gemini (optional). Edit and save them per image or in batch.
- **Auto thumbnails.** Generated on demand from originals. Caches are safe to delete.
- **Multilingual.** English only, or English plus a second language of your choice. Separate titles, descriptions, and captions per language, with language-prefixed clean URLs.
- **Clean URLs.** SEO-friendly `/album/name` and `/series/name` paths. Automatic `.htaccess` on Apache. Verified before enabling.
- **Local analytics.** Anonymous and privacy-conscious. Stored as JSONL files with no external service.
- **Open Graph and sitemap.** Metadata for social sharing and search engines.
- **Admin dashboard.** Settings, cache management, analytics, and visibility toggles, all from the browser.

---

## Getting started

### Requirements

- PHP 7.4 or newer
- PHP GD extension with JPEG/PNG support (WebP recommended)
- A web server: Apache, Caddy + php-fpm, or Nginx + php-fpm
- Write access for the web server user to the gallery directory and `images/`

### Installation

1. Copy `index.php` to a directory served by your web server and make the directory writable by the web server.
2. Open the gallery URL in a browser, for example `https://example.com/gallery/`.

Lightbox creates `images/` automatically and shows a getting started guide. The following files and folders are created as you use the app:

```text
images/                        created on first page load
settings.json                  created when you save settings
series.json                    created when you create a series
analytics/                     created when analytics is first enabled
.lightbox_admin_password.php   created when you set your admin password
```

3. Create one subfolder per album inside `images/` and place your photos in it:

   ```text
   images/
     my-first-album/
       photo-001.jpg
       photo-002.jpg
   ```

4. Reload the gallery. Thumbnails and display images are generated automatically on first view.

### Admin setup

Navigate to `/admin` on your gallery URL:

```
https://example.com/gallery/admin
```

On first access you'll be prompted to create a password. Only a bcrypt hash is stored.

To reset the password, create an empty `reset-pass.txt` file beside `index.php`, then open `/admin` again.

#### Password file location

By default the hash is saved as `.lightbox_admin_password.php` beside `index.php`, inside the web root. This is safe as long as your server executes `.php` files rather than serving them as plain text — PHP will run the file and produce no output. However, placing it in the web root carries risk:

- If PHP is ever misconfigured or removed, the file is served as plain text and the hash is exposed. An attacker could attempt an offline brute-force attack against it.
- A server migration or configuration change can silently break `.php` execution without obvious symptoms.
- The file is not protected by the `.htaccess` block Lightbox writes for Apache.

The safer option is to store it outside the public web root. Set `LIGHTBOX_ADMIN_PASSWORD_FILE` before your first admin login:

```text
LIGHTBOX_ADMIN_PASSWORD_FILE=/home/myuser/private_html/.lightbox_admin_password.php
```

Set this as an environment variable or in your `.env` file. The directory must be writable by the web server so the file can be created, and the file must be readable by the web server so the hash can be verified on login. If you have already set a password, move the existing file to the new location and update the variable before reloading.

### Fonts

Lightbox is designed for Montserrat but works without it. For the intended appearance, place these files beside `index.php`:

```text
fonts/montserrat-latin.woff2
fonts/montserrat-latin-ext.woff2
```

Download from [Google Fonts](https://fonts.google.com/specimen/Montserrat) or [the upstream project](https://github.com/JulietaUla/Montserrat).

---

## Using the gallery

### Lightbox viewer

Click any photo to open it full-screen. Navigate with arrow keys or the on-screen buttons. Press Escape to close. On mobile, swipe left and right to move between photos and pinch to zoom.

### Albums

Albums are folders inside `images/`. Add photos by copying files directly to the server. Images are sorted by EXIF date, with alphabetical fallback. Admin-managed ordering overrides this.

In admin mode, albums have additional controls:

- **Drag and drop** to reorder images. The new order is saved immediately.
- **Star icon** on each thumbnail to set the hero (cover) image for the album tile.
- **Visibility toggle** to hide or show an album from public view without deleting it.
- **Aspect ratio toggle** to switch the grid between square crops and natural proportions.
- **Album Settings** to edit the album title, description, and caption display. The caption display toggle enables or disables captions shown below photos in the lightbox.
- **Series Selection Mode** to add or remove individual photos from any series, using checkboxes directly on the album grid.

### Curated series

Series are the public entry point. From admin mode:

1. Create a series from the home page.
2. Open an album, enable **Series Selection Mode**, and select images.
3. Return to the series editor to set order, title, description, hero image, and visibility.

A series can draw images from multiple albums. The source album links are shown at the bottom of each series page.

### AI captions (optional)

Add a Google AI API key to enable automatic caption generation:

```text
LIGHTBOX_GOOGLE_API_KEY=your-key-here
```

Set this as an environment variable or in a `.env` file beside `index.php`. Once set:

- Use the caption bar in the lightbox to generate or edit captions per image.
- Use **Album Captions** (next to Album Settings) for batch generation across an entire album. Select images, generate, save, or erase in bulk.

Captions are stored in the album's `config.txt` and displayed in the lightbox and optionally on the album grid.

### Clean URLs

Enable clean URLs under **Admin Mode → General Settings → URLs & SEO**. On Apache, Lightbox writes its own `.htaccess` block automatically. On other servers, configure your web server to route missing paths to `index.php`.

Lightbox verifies that rewriting actually works before saving the setting. If the probe fails, the setting is reverted and an error is shown.

> **Note:** URL rewriting is required for image loading regardless of this setting. Lightbox always serves thumbnails and display images through `_lb/thumb/` and `_lb/large/` routes.

For Caddy, add before your PHP block:

```caddyfile
@originals {
    path_regexp originals ^/images/[^/]+/[^/]+$
}
respond @originals 404

route {
    respond @originals 404
    try_files {path} {path}/ /index.php?lb_path={path}&{query}
    php_fastcgi 127.0.0.1:9000
}
```

### Local analytics

Enable under **Admin Mode → General Settings → Privacy & Analytics**. Events are stored as append-only JSONL files in `analytics/`. No cookies, no external service, no full IP addresses.

Reset by deleting `analytics/events-*.jsonl` and `analytics/image-loads-*.jsonl`.

---

## Updating

Replace only `index.php`. Do not overwrite:

```text
images/
settings.json
series.json
analytics/
.lightbox_admin_password.php
```

---

## Security notes

- Admin mode is protected by a password hash stored outside the web root (configurable via `LIGHTBOX_ADMIN_PASSWORD_FILE`).
- All admin write endpoints require a CSRF token.
- Master images are served through `index.php` routes, not directly. The `.htaccess` block blocks direct access when on Apache.
- Hidden albums are not accessible via any route, including image-serving endpoints.

---

## For developers

### Project structure

```text
index.php     the entire application
```

### Running locally

```bash
# Syntax check
php -l index.php
```

### Architecture notes

The app is intentionally a single file. All routing, rendering, admin logic, image processing, analytics, and API integration live in `index.php`. Key internal sections:

- **`apply_clean_route()`** maps incoming URL paths to `$_GET` parameters before any other routing.
- **`page_album()` / `page_series()`** are the main page renderers.
- **`page_caption_editor()`** is the batch caption editor page.
- **`gemini_caption()`** calls the Gemini API. English-first, then translated.
- **`save_album_caption()` / `album_captions()`** handle caption persistence via `config.txt`.
- **`ensure_lightbox_htaccess()`** writes and updates the Apache `.htaccess` block.
- **`atomic_write()`** is used for all file writes to avoid partial writes.

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `LIGHTBOX_ADMIN_PASSWORD_FILE` | No | Path to store the admin password hash. Defaults to `.lightbox_admin_password.php` beside `index.php`. |
| `LIGHTBOX_GOOGLE_API_KEY` | No | Google AI (Gemini) API key for AI caption generation. |

Variables can be set as real environment variables or in a `.env` file beside `index.php`.

---

## Release notes

### v0.12
- Impressum and Privacy pages. Place `IMPRESSUM.md` and `PRIVACY.md` beside `index.php` to enable linked legal pages at `/impressum` and `/privacy`. Both files support bilingual content (German above a `---` separator, English below).
- Admin settings cleanup. Version number moved to the top of the panel, Cache Management split into its own section, background color setting removed, `<hr>` separators between sections.
- Markdown improvements. Lists, horizontal rules, and two-space line breaks now render correctly.

### v0.11
- AI caption generation via Google Gemini. Per-image editor in the lightbox and batch editor page (**Album Captions**).
- Caption display on album thumbnails in admin mode.
- Captions used as `alt` text on tiles and in the lightbox.
- Clean URL rewrite probe. Verifies routing works before enabling. Reverts and warns if not.
- Caption flash fix. Captions are now visible instantly when opening the lightbox.
- Logout returns to the current page instead of the home page.

### v0.10
- Added Clean URLs setting under Admin Mode → General Settings → URLs & SEO.
- Lightbox now writes and updates its own `.htaccess` block on Apache automatically.
- Query-string URLs remain available as fallbacks.

### v0.9
- Inline timeline sparklines on analytics cards.
- New uploads inserted at the front of album order.
- Rebuilt series grid: 3 columns desktop, 2 columns mobile, centered final row.
- Expanded album descriptions to full mobile width.

---

## License

Apache License 2.0. See `LICENSE`.

Created by Chris Marquardt. Built with AI-assisted coding. Provided without guarantees. Review the code and server configuration before deploying, and keep backups of your gallery data.
