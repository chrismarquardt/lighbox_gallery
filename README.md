# Lightbox Photo Gallery

Lightbox is a single-file PHP photo gallery for photographers and small
portfolio sites. Drop `index.php` onto a PHP-capable web server, add albums
under `images/`, and the app builds fast thumbnails and display images on
demand.

The public gallery is curated-series first: visitors initially see named series
instead of a raw album list. Albums remain the source organization underneath,
while the public entry point highlights selected bodies of work, lightbox
viewing, keyboard navigation, multilingual labels, SEO metadata, and optional
privacy-conscious local analytics.

Created by Chris Marquardt (`chris@chrismarquardt.com`). Lightbox was built
mostly with AI-assisted coding, with care taken to keep the code robust,
simple, and security-conscious. It has been running well in production at
`https://chrismarquardt.com/photo/`.

## What It Enables

- Publish a portfolio-style photo gallery without a database or build step.
- Organize photos into albums using normal folders, then present selected
  images as curated series on the public landing page.
- Build curated series from images across one or more albums without
  duplicating the master files.
- Offer an All Photos link from the series landing page to the full album
  overview.
- Show source links on series pages so visitors can jump to the originating
  album or albums.
- Generate thumbnails and large display images automatically from originals.
- Manage uploads, album metadata, series, settings, cache cleanup, and local
  analytics from the browser.
- Keep analytics local as JSONL files, with no external analytics provider.
- Serve SEO-friendly metadata, Open Graph/Twitter cards, and a sitemap.

## Requirements

- PHP 7.4 or newer.
- PHP GD extension with JPEG and PNG support. WebP support is recommended if
  you want to upload WebP files.
- A web server that can run PHP, such as Apache, Caddy with `php-fpm`, or
  Nginx with `php-fpm`.
- Write access for the web server user to:
  - the gallery directory, for `settings.json`, `series.json`, and admin state;
  - `images/` and album folders, for uploads, album settings, image ordering,
    thumbnails, and large display-image caches;
  - `analytics/` if local analytics is enabled.

No database, Composer install, Node install, or external service is required.

## Distribution Contents

A minimal production install needs:

```text
index.php
```

Recommended supporting files:

```text
.htaccess              Apache security and rewrite example
fonts/                 optional local Montserrat webfonts
README.md              this documentation
LICENSE
RELEASENOTES_v*.txt
```

Gallery content and runtime data normally live on the server and should not be
overwritten during app updates:

```text
images/
settings.json
series.json
analytics/
.lightbox_admin_password.php
```

## Installation

1. Copy `index.php` to a directory served by your PHP web server.
2. Create an `images/` directory beside `index.php`.
3. Create one folder per album inside `images/`, for example:

   ```text
   images/my-first-album/
   ```

4. Put JPEG, PNG, or WebP photos into the album folder.
5. Make the gallery directory, `images/`, and all album folders writable by the
   web server user.
6. Open the gallery URL in a browser.

The gallery will discover albums automatically. Generated thumbnails are stored
in `images/<album>/thumbs/ar/`; generated display images are stored in
`images/<album>/large/`. Both folders are caches and can be deleted safely.

## Fonts

Lightbox is designed around Montserrat, but font files are not required for the
app to run and may not be included in every distribution package. For the
intended visual appearance, download Montserrat from Google Fonts
(`https://fonts.google.com/specimen/Montserrat`) or the upstream project
(`https://github.com/JulietaUla/Montserrat`), then place these exact WOFF2
files beside `index.php`:

```text
fonts/montserrat-latin.woff2
fonts/montserrat-latin-ext.woff2
```

If the files are missing, the gallery still works. Browsers will use the next
available sans-serif fallback font, so layout and spacing may look slightly
different from the intended design.

## Admin Setup

Open admin mode by adding `?admin` to the gallery URL:

```text
https://example.com/gallery/?admin
```

On first access, create a long unique password. Lightbox stores only a one-way
password hash.

For stronger isolation, set `LIGHTBOX_ADMIN_PASSWORD_FILE` before first admin
setup to a writable path outside the public web root, for example:

```text
LIGHTBOX_ADMIN_PASSWORD_FILE=/var/www/private/lightbox-admin-password.php
```

Admin mode enables:

- browser uploads for JPEG, PNG, and WebP images;
- new album creation;
- album titles, descriptions, visibility, hero images, and ordering;
- curated series creation and editing;
- multilingual gallery labels and titles;
- visual settings such as spacing, font sizes, image quality, and background;
- thumbnail and display-image cache cleanup;
- optional local analytics dashboard.

To reset the admin password, create an empty `reset-pass.txt` file beside
`index.php`, then open `?admin`. Lightbox removes the reset file, deletes the
stored hash, and shows the password setup screen again.

## Curated Series

Curated series are the main public presentation layer. When at least one
visible series exists, the home page shows the series grid first and does not
show the album overview by default. This lets the gallery lead with edited
stories, portfolios, projects, or themes rather than exposing the folder
structure first.

Albums are still important: they hold the master images, generated caches, and
album metadata. A series can pull images from one album or combine images from
several albums without copying files. Each series page shows a source section at
the bottom with links back to the originating album or albums. The home page
also includes a configurable All Photos link that opens the complete album
overview for visitors who want to browse everything.

Admins create and manage series from `?admin`: create a series, open an album,
enable Series Selection Mode, select the images that belong to the series, then
return to the series editor to set order, title, description, hero image,
visibility, and sources.

## Album Structure

```text
images/
  my-first-album/
    photo-001.jpg
    photo-002.jpg
    config.txt       optional album metadata, managed by admin mode
    thumbs/ar/       generated thumbnails
    large/           generated display images
```

Master images stay directly in `images/<album>/`. Generated folders are caches.
Lightbox sorts images by EXIF `DateTimeOriginal` when available, with an
alphabetical fallback. Admin-managed order overrides are saved in album config.

## Adding and Removing Images

There are two ways to add images.

In admin mode, use **Upload Images**. You can upload JPEG, PNG, or WebP files
to an existing album, or create a new album during upload. The app validates
file type, file size, image dimensions, and batch size before saving the
masters into `images/<album>/`.

On the server, you can also add files directly. Create or choose an album folder
inside `images/`, copy JPEG, PNG, or WebP files into it, make sure the web
server can read the files and write to the album folder, then reload the
gallery. Lightbox discovers the images and generates thumbnails and display
copies when they are first needed.

Removing images from a curated series does not delete the source file. Open the
series editor from admin mode and remove the image there, or open the source
album, enable Series Selection Mode, and uncheck that image for the series. The
master image remains in its album and may still appear in All Photos or another
series.

To permanently remove an individual image from the gallery, delete the master
file from its `images/<album>/` folder on the server. You may also delete the
matching generated files from that album's `thumbs/ar/` and `large/` cache
folders, but that is only cleanup; missing or stale cache files are ignored or
rebuilt as needed. If the image was used in a series, remove it from that series
as well so the curation stays tidy.

To remove a whole album, use the album settings dialog in admin mode. Album
deletion requires two confirmations and permanently removes the album folder,
uploaded master images, generated caches, and related series assignments. Keep
backups before deleting albums or master files.

## Upload Limits

Browser uploads are limited by the app to:

- 80 images per request;
- 30 MB per file;
- 20,000 px maximum long edge;
- 80,000,000 pixels maximum per image.

Your PHP and web server upload limits must also be high enough for the files
you expect to accept.

## Security Notes

Protect master images and runtime data at the web server layer when possible.
Visitors should receive images through `index.php` routes such as
`?a=<album>&t=<file>` and `?a=<album>&i=<file>`.

If you use Apache and allow `.htaccess`, copy the included `.htaccess` file to
the gallery directory. It disables directory indexes, blocks direct access to
master images, blocks raw analytics files, and routes optional clean URLs.

If you use Caddy, place the original-image block before file/PHP serving rules:

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

Generated `thumbs/` and `large/` folders are caches. They may remain directly
web-readable if your server requires that, but Lightbox can serve generated
images through `index.php`.

## Optional Clean URLs

Query-string URLs always work:

```text
?a=<album>
?a=<album>&i=<file>
?s=s1
?sitemap=1
```

To prefer clean album and image URLs, enable clean URLs in admin settings or set
this in `settings.json`:

```json
{
  "clean_urls": true
}
```

Then configure your web server to rewrite missing files and directories to
`index.php`. Supported clean public routes are:

```text
/<album>
/<album>/<image-file>
```

Series routes remain `?s=s1` through `?s=s6`.

## Local Analytics

Local analytics can be enabled from Admin Mode > General Settings > Privacy &
Analytics. Events are written as append-only JSONL files in `analytics/`:

```text
analytics/events-YYYY-MM-DD.jsonl
analytics/image-loads-YYYY-MM-DD.jsonl
analytics/admin-visits.json
```

Tracked data includes anonymous visitor/session IDs, album views, series views,
source-link clickthroughs, photo views, photo dwell time, image load timing, and
image load failures.

Lightbox does not use Google Analytics, external analytics services, full IP
addresses, full user agents, cookies, secrets, or admin-only URLs for analytics.

Reset analytics by deleting:

```text
analytics/events-*.jsonl
analytics/image-loads-*.jsonl
```

## Updating

For a normal update, replace only:

```text
index.php
```

Do not overwrite server-owned gallery content or runtime files unless you are
intentionally migrating or restoring them:

```text
images/
settings.json
series.json
analytics/
.lightbox_admin_password.php
```

This repository includes `deploy.sh` for rsync-based deployments. Configure:

```text
LIGHTBOX_DEPLOY_HOST=user@example.com
LIGHTBOX_DEPLOY_PATH=/path/to/gallery
```

Then preview or deploy:

```bash
./deploy.sh --dry-run
./deploy.sh
```

## Development

Run the standard checks from the repository root:

```bash
php -l index.php
php tests/run.php
```

The test harness creates temporary gallery data and does not modify your real
`images/` directory.

For local Caddy + `php-fpm` development, the included `Caddyfile` serves the
gallery at `https://localhost:3024`.

## License

Lightbox is distributed under the Apache License 2.0. See `LICENSE`.

This software is provided without guarantees. Use it at your own risk, review
the code and server configuration before deploying it, and keep backups of your
gallery data. Chris Marquardt cannot be held responsible for damage, data loss,
security issues, downtime, or anything else that happens to your system.
