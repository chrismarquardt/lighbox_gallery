<?php
declare(strict_types=1);

const IMG_DIR    = 'images';
const THUMB_AR_MAX = 600;
const DEFAULT_THUMB_QUALITY = 85;
const DEFAULT_DISPLAY_LONG_EDGE = 2000;
const DEFAULT_DISPLAY_QUALITY = 78;
const DEFAULT_SITE_TITLE = 'Photo Gallery';
const DEFAULT_SITE_DESC  = 'Photo gallery';
const APP_VERSION = 'v0.10';
const SETTINGS_FILE = 'settings.json';
const SERIES_FILE = 'series.json';
const ANALYTICS_DIR = 'analytics';
const ANALYTICS_MAX_DWELL_MS = 600000;
const SERIES_IDS  = ['s1','s2','s3','s4','s5','s6'];
const UPLOAD_MAX_FILES = 80;
const UPLOAD_MAX_BYTES = 30_000_000;
const UPLOAD_MAX_PIXELS = 80_000_000;
const UPLOAD_MAX_LONG_EDGE = 20000;
const GEMINI_MODEL = 'gemini-3.5-flash';

if (defined('LIGHTBOX_TEST_MODE') && LIGHTBOX_TEST_MODE) {
    return;
}

register_shutdown_function(function (): void {
    $err = error_get_last();
    if (!$err || !in_array($err['type'] ?? 0, [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) return;
    $msg = 'Lightbox fatal error: ' . ($err['message'] ?? 'unknown error') . ' in ' . ($err['file'] ?? 'unknown file') . ':' . ($err['line'] ?? 0);
    error_log($msg);
    if (headers_sent()) return;
    http_response_code(500);
    header('Cache-Control: no-store');
    $is_image_request = isset($_GET['t']) || isset($_GET['i']);
    if ($is_image_request) {
        header('Content-Type: text/plain; charset=utf-8');
        echo "Lightbox image generation failed.\n";
        echo htmlspecialchars($msg);
        return;
    }
    header('Content-Type: text/html; charset=utf-8');
    $safe = htmlspecialchars($msg, ENT_QUOTES);
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Lightbox Error</title>';
    echo '<style>html,body{background:#000;color:#fff;font-family:sans-serif;margin:0;min-height:100%;display:flex;align-items:center;justify-content:center}.box{max-width:760px;padding:32px;line-height:1.5}code{background:#111;border:1px solid #333;padding:2px 5px;word-break:break-word}</style>';
    echo '<script data-cfasync="false">console.error("[Lightbox] PHP fatal error:", ' . json_encode($msg) . ');</script>';
    echo '</head><body><div class="box"><h1>Lightbox could not finish loading</h1><p>The server returned a PHP error. Check the browser console and PHP error log for details.</p><p><code>' . $safe . '</code></p></div></body></html>';
});

// ─── security headers (sent before any output) ───────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self'; script-src 'self' 'unsafe-inline' https://js-agent.newrelic.com; connect-src 'self' https://bam.nr-data.net");
header('X-Rocket-Loader: disabled');

apply_clean_route();

// ─── language ────────────────────────────────────────────────────────────────
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en', 'de'], true) && empty($_SERVER['LB_LANG_FROM_PATH'])) {
    $target_lang = (string)$_GET['lang'];
    setcookie('lb_lang', $_GET['lang'], ['expires' => time() + 60*60*24*365, 'path' => '/', 'samesite' => 'Lax', 'secure' => true, 'httponly' => false]);
    if (clean_urls_enabled()) {
        header('Location: ' . lang_url($target_lang));
        exit;
    }
    $uri = (string)($_SERVER['REQUEST_URI'] ?? './');
    $path = (string)(parse_url($uri, PHP_URL_PATH) ?: './');
    $query = (string)(parse_url($uri, PHP_URL_QUERY) ?? '');
    parse_str($query, $params);
    unset($params['lang']);
    header('Location: ' . $path . ($params ? '?' . http_build_query($params) : ''));
    exit;
}

// Route public image work before session/admin setup. This keeps thumbnail and
// display-image generation off the session path and avoids session cookies on
// cacheable image responses.
$a = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
$t = isset($_GET['t']) ? safe_seg($_GET['t']) : null;
$i = isset($_GET['i']) ? safe_seg($_GET['i']) : null;
$og = isset($_GET['og_image']) ? safe_seg($_GET['og_image']) : null;

if ($a !== null && (isset($_GET['gen_thumbs']) || isset($_GET['gen_large']) || $t !== null || $i !== null || $og !== null)) {
    $cfg = parse_config(IMG_DIR . '/' . $a);
    if (($cfg['hidden'] ?? '') === '1') { http_response_code(404); exit; }
}

if (isset($_GET['gen_thumbs']) && $a !== null) { route_gen_thumbs($a); }
if (isset($_GET['gen_large']) && $a !== null) { route_gen_large($a); }
if ($a !== null && $og !== null) { serve_og_image($a, $og); exit; }
if ($a !== null && $t !== null) { serve_thumb_ar($a, $t); exit; }
if ($a !== null && $i !== null) { serve_image($a, $i); exit; }

// Privacy-conscious, append-only analytics endpoint. It intentionally runs
// before session setup so public tracking never creates an admin/session cookie.
if (isset($_GET['analytics_event'])) {
    route_analytics_event();
}

// ─── session (needed for admin and page rendering) ───────────────────────────
session_cache_limiter('');
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'cookie_secure'   => true,
    'name'            => 'lb_sess',
]);

// ─── admin route ─────────────────────────────────────────────────────────────
if (isset($_GET['admin'])) {
    $reset_msg = '';
    if (admin_password_reset_requested()) {
        reset_admin_password();
        clear_admin_login_failures();
        $_SESSION = [];
        session_regenerate_id(true);
        $reset_msg = 'Password reset requested. Create a new password.';
    }
    if (!admin_password_configured()) {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $pass = (string)($_POST['pass'] ?? '');
            $pass2 = (string)($_POST['pass2'] ?? '');
            if ($pass !== $pass2) {
                page_admin_password_setup('Passwords do not match.');
                exit;
            }
            if (strlen($pass) < 10 || strlen($pass) > 200) {
                page_admin_password_setup('Use 10 to 200 characters.');
                exit;
            }
            $err = '';
            if (!save_admin_password_hash(password_hash($pass, PASSWORD_DEFAULT), $err)) {
                page_admin_password_setup($err ?: 'Could not save password.');
                exit;
            }
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            $_SESSION['csrf']  = bin2hex(random_bytes(16));
            header('Location: ./');
            exit;
        }
        page_admin_password_setup($reset_msg);
        exit;
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (admin_login_rate_limited()) {
            http_response_code(429);
            page_login(false, 'Too many attempts — try again in 5 minutes.');
            exit;
        }
        $pass = $_POST['pass'] ?? '';
        $hash = admin_password_hash();
        if (is_string($hash) && strlen((string)$pass) < 200 && password_verify((string)$pass, $hash)) {
            clear_admin_login_failures();
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            $_SESSION['csrf']  = bin2hex(random_bytes(16));
            header('Location: ./');
            exit;
        }
        record_admin_login_failure();
        page_login(true);
    } else {
        page_login(false);
    }
    exit;
}
if (isset($_POST['logout']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (hash_equals($_SESSION['csrf'] ?? '', $csrf)) {
        session_destroy();
    }
    header('Location: ./');
    exit;
}
if (isset($_GET['admin_status'])) {
    header('Content-Type: application/json');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(['ok' => true, 'admin' => is_admin()]);
    exit;
}
if (isset($_GET['analytics_admin'])) {
    if (!is_admin()) { header('Location: ' . admin_url()); exit; }
    $range = (int)($_GET['range'] ?? 7);
    page_admin_analytics(in_array($range, [7, 30], true) ? $range : 7);
    exit;
}

// ─── admin action: upload images ─────────────────────────────────────────────
if (isset($_GET['upload_images']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf'] ?? '');
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    header('Content-Type: application/json');

    $mode = $_POST['target_mode'] ?? 'existing';
    $album = null;
    $album_title = '';
    if ($mode === 'new') {
        $album_title = substr(trim((string)($_POST['new_album_name'] ?? '')), 0, 160);
        $raw_slug = trim((string)($_POST['new_album_slug'] ?? ''));
        $album = unique_album_slug($raw_slug !== '' ? $raw_slug : $album_title);
        if ($album_title === '' || $album === null) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Enter a new album name.']);
            exit;
        }
    } else {
        $album = isset($_POST['album']) ? safe_seg((string)$_POST['album']) : null;
        if (!$album || !is_dir(IMG_DIR . '/' . $album)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Choose an existing album.']);
            exit;
        }
    }

    $files = normalize_upload_files($_FILES['images'] ?? null);
    if (!$files) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Choose at least one image.']);
        exit;
    }
    if (count($files) > UPLOAD_MAX_FILES) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Upload at most ' . UPLOAD_MAX_FILES . ' images at once.']);
        exit;
    }

    $album_dir = IMG_DIR . '/' . $album;
    if (!ensure_writable_dir($album_dir)) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'Could not create album folder.']);
        exit;
    }
    if (!is_writable($album_dir)) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'Album folder is not writable.']);
        exit;
    }

    $saved = [];
    $errors = [];
    foreach ($files as $file) {
        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            $errors[] = ($file['name'] ?? 'File') . ': upload failed.';
            continue;
        }
        if ((int)($file['size'] ?? 0) > UPLOAD_MAX_BYTES) {
            $errors[] = ($file['name'] ?? 'File') . ': file is larger than ' . format_bytes(UPLOAD_MAX_BYTES) . '.';
            continue;
        }
        $tmp = (string)($file['tmp_name'] ?? '');
        if ($tmp === '' || !is_uploaded_file($tmp)) {
            $errors[] = ($file['name'] ?? 'File') . ': invalid upload.';
            continue;
        }
        $limit_error = upload_dimension_limit_error($tmp);
        if ($limit_error !== '') {
            $errors[] = ($file['name'] ?? 'File') . ': ' . $limit_error;
            continue;
        }
        $ext = upload_image_extension($tmp);
        if ($ext === null) {
            $errors[] = ($file['name'] ?? 'File') . ': unsupported image type.';
            continue;
        }
        $base_name = upload_filename_base((string)($file['name'] ?? 'image'));
        $dest_name = unique_image_filename($album_dir, $base_name, $ext);
        if (!@move_uploaded_file($tmp, $album_dir . '/' . $dest_name)) {
            $errors[] = ($file['name'] ?? 'File') . ': could not save.';
            continue;
        }
        @chmod($album_dir . '/' . $dest_name, 0664);
        $saved[] = $dest_name;
    }

    if (!$saved) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => $errors[0] ?? 'No images were uploaded.', 'errors' => $errors]);
        exit;
    }

    $cfg = parse_config($album_dir);
    if ($mode === 'new') {
        $cfg['name'] = $album_title;
        if (!multilingual_enabled()) $cfg['name_en'] = $album_title;
    }
    $existing = images_in($album);
    $ordered = uploaded_images_first_order($existing, $saved);
    $cfg['order'] = implode(',', $ordered);
    write_config($album_dir, $cfg);
    @unlink(album_order_cache_file($album));
    if ($mode === 'new') {
        promote_album_to_overview_front($album);
    }

    echo json_encode([
        'ok' => true,
        'album' => $album,
        'uploaded' => count($saved),
        'errors' => $errors,
        'url' => album_url($album),
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── admin action: set hero ───────────────────────────────────────────────────
if (isset($_GET['set_hero']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf'] ?? '');
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
    $hf = isset($_GET['f']) ? safe_seg($_GET['f']) : null;
    if (!$ha || !$hf || !is_file(source_image_path($ha, $hf))) { http_response_code(400); exit; }
    $cfg = parse_config(IMG_DIR . '/' . $ha);
    $cfg['hero'] = pathinfo($hf, PATHINFO_FILENAME);
    write_config(IMG_DIR . '/' . $ha, $cfg);
    @unlink(album_order_cache_file($ha));
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: save settings ─────────────────────────────────────────────
if (isset($_GET['save_settings']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $allowed_bg = ['#000', '#888', '#fff'];
    $defaults = default_settings();
    $raw_bg = $_POST['bg_color'] ?? $defaults['bg_color'];
    $lang_label = trim((string)($_POST['primary_lang_label'] ?? $defaults['primary_lang_label']));
    $lang_label = preg_replace('/[^\p{L}\p{N} ._-]/u', '', $lang_label) ?? '';
    $s = array_merge(load_settings(), [
        'site_title'             => substr(trim($_POST['site_title'] ?? $defaults['site_title']), 0, 120),
        'site_title_en'          => substr(trim($_POST['site_title_en'] ?? $defaults['site_title_en']), 0, 120),
        'series_label'           => substr(trim($_POST['series_label'] ?? $defaults['series_label']), 0, 80) ?: $defaults['series_label'],
        'series_label_en'        => substr(trim($_POST['series_label_en'] ?? $defaults['series_label_en']), 0, 80) ?: $defaults['series_label_en'],
        'all_photos_label'       => substr(trim($_POST['all_photos_label'] ?? $defaults['all_photos_label']), 0, 80) ?: $defaults['all_photos_label'],
        'all_photos_label_en'    => substr(trim($_POST['all_photos_label_en'] ?? $defaults['all_photos_label_en']), 0, 80) ?: $defaults['all_photos_label_en'],
        'share_label'            => substr(trim($_POST['share_label'] ?? $defaults['share_label']), 0, 80) ?: $defaults['share_label'],
        'share_label_en'         => substr(trim($_POST['share_label_en'] ?? $defaults['share_label_en']), 0, 80) ?: $defaults['share_label_en'],
        'copied_label'           => substr(trim($_POST['copied_label'] ?? $defaults['copied_label']), 0, 80) ?: $defaults['copied_label'],
        'copied_label_en'        => substr(trim($_POST['copied_label_en'] ?? $defaults['copied_label_en']), 0, 80) ?: $defaults['copied_label_en'],
        'album_label'            => substr(trim($_POST['album_label'] ?? $defaults['album_label']), 0, 80) ?: $defaults['album_label'],
        'album_label_en'         => substr(trim($_POST['album_label_en'] ?? $defaults['album_label_en']), 0, 80) ?: $defaults['album_label_en'],
        'albums_label'           => substr(trim($_POST['albums_label'] ?? $defaults['albums_label']), 0, 80) ?: $defaults['albums_label'],
        'albums_label_en'        => substr(trim($_POST['albums_label_en'] ?? $defaults['albums_label_en']), 0, 80) ?: $defaults['albums_label_en'],
        'source_label'           => substr(trim($_POST['source_label'] ?? $defaults['source_label']), 0, 80) ?: $defaults['source_label'],
        'source_label_en'        => substr(trim($_POST['source_label_en'] ?? $defaults['source_label_en']), 0, 80) ?: $defaults['source_label_en'],
        'sources_label'          => substr(trim($_POST['sources_label'] ?? $defaults['sources_label']), 0, 80) ?: $defaults['sources_label'],
        'sources_label_en'       => substr(trim($_POST['sources_label_en'] ?? $defaults['sources_label_en']), 0, 80) ?: $defaults['sources_label_en'],
        'multilingual'           => ($_POST['multilingual'] ?? '0') === '1',
        'primary_lang_label'     => substr($lang_label !== '' ? $lang_label : $defaults['primary_lang_label'], 0, 16),
        'gap'                    => max(0, min(40, (int)($_POST['gap'] ?? $defaults['gap']))),
        'content_padding'        => max(0, min(80, (int)($_POST['content_padding'] ?? $defaults['content_padding']))),
        'nav_font_size'          => preg_replace('/[^0-9.a-z%]/', '', $_POST['nav_font_size'] ?? $defaults['nav_font_size']),
        'tile_label_font_size'   => preg_replace('/[^0-9.a-z%]/', '', $_POST['tile_label_font_size'] ?? $defaults['tile_label_font_size']),
        'desc_font_size'         => preg_replace('/[^0-9.a-z%]/', '', $_POST['desc_font_size'] ?? $defaults['desc_font_size']),
        'series_row_gap'         => preg_replace('/[^0-9.a-z%]/', '', $_POST['series_row_gap'] ?? $defaults['series_row_gap']),
        'series_width_desktop'   => max(0, (int)($_POST['series_width_desktop'] ?? $defaults['series_width_desktop'])),
        'series_padding_mobile'  => max(0, (int)($_POST['series_padding_mobile'] ?? $defaults['series_padding_mobile'])),
        'thumb_quality'          => clamp_int($_POST['thumb_quality'] ?? $defaults['thumb_quality'], 40, 100),
        'display_long_edge'      => clamp_int($_POST['display_long_edge'] ?? $defaults['display_long_edge'], 800, 8000),
        'display_quality'        => clamp_int($_POST['display_quality'] ?? $defaults['display_quality'], 40, 100),
        'analytics_enabled'      => ($_POST['analytics_enabled'] ?? '0') === '1',
        'clean_urls'             => ($_POST['clean_urls'] ?? '0') === '1',
        'bg_color'               => in_array($raw_bg, $allowed_bg, true) ? $raw_bg : $defaults['bg_color'],
    ]);
    atomic_write(SETTINGS_FILE, json_encode($s, JSON_PRETTY_PRINT));
    $response = ['ok' => true];
    if (!empty($s['clean_urls'])) {
        $htaccess = ensure_lightbox_htaccess();
        $response['htaccess'] = $htaccess['status'];
        if (!$htaccess['ok']) {
            $response['warning'] = $htaccess['message'];
        }
    }
    header('Content-Type: application/json');
    echo json_encode($response, JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── admin action: reset thumbnails ──────────────────────────────────────────
if (isset($_GET['reset_thumbs']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
    if (!$ha) { http_response_code(400); exit; }
    $result = cache_clear_response(clear_thumb_cache($ha));
    header('Content-Type: application/json');
    if (!$result['ok']) http_response_code(500);
    echo json_encode($result, JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── admin action: reset display images ─────────────────────────────────────
if (isset($_GET['reset_large']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
    if (!$ha) { http_response_code(400); exit; }
    $result = cache_clear_response(clear_large_cache($ha));
    header('Content-Type: application/json');
    if (!$result['ok']) http_response_code(500);
    echo json_encode($result, JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── admin action: reset all thumbnails ─────────────────────────────────────
if (isset($_GET['reset_all_thumbs']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $result = empty_cache_clear_result();
    foreach (album_slugs_for_cache_reset() as $slug) {
        $result = merge_cache_clear_result($result, clear_thumb_cache($slug));
    }
    $result = cache_clear_response($result);
    header('Content-Type: application/json');
    if (!$result['ok']) http_response_code(500);
    echo json_encode($result, JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── admin action: reset all display images ─────────────────────────────────
if (isset($_GET['reset_all_large']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $result = empty_cache_clear_result();
    foreach (album_slugs_for_cache_reset() as $slug) {
        $result = merge_cache_clear_result($result, clear_large_cache($slug));
    }
    $result = cache_clear_response($result);
    header('Content-Type: application/json');
    if (!$result['ok']) http_response_code(500);
    echo json_encode($result, JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── admin action: list missing thumbnails ───────────────────────────────────
if (isset($_GET['missing_thumbs']) && is_admin()) {
    header('Content-Type: application/json');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    $results = [];
    $scanned_albums = 0;
    $scanned_images = 0;
    $total_missing = 0;
    foreach (album_slugs_for_cache_reset() as $album) {
        $scanned_albums++;
        $missing = [];
        foreach (images_in($album) as $img) {
            $scanned_images++;
            if (!thumb_current($album, $img)) $missing[] = $img;
        }
        if ($missing) {
            $results[$album] = $missing;
            $total_missing += count($missing);
        }
    }
    echo json_encode(['ok' => true, 'results' => $results, 'total_missing' => $total_missing, 'scanned_albums' => $scanned_albums, 'scanned_images' => $scanned_images, 'generated_at' => time()], JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── admin action: list missing large images ──────────────────────────────────
if (isset($_GET['missing_large']) && is_admin()) {
    header('Content-Type: application/json');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    $results = [];
    $scanned_albums = 0;
    $scanned_images = 0;
    $total_missing = 0;
    foreach (album_slugs_for_cache_reset() as $album) {
        $scanned_albums++;
        $missing = [];
        foreach (images_in($album) as $img) {
            $scanned_images++;
            $src = source_image_path($album, $img);
            $dst = large_path($album, $img);
            $key = large_cache_key($src);
            if (!derivative_current($src, $dst, $key)) $missing[] = $img;
        }
        if ($missing) {
            $results[$album] = $missing;
            $total_missing += count($missing);
        }
    }
    echo json_encode(['ok' => true, 'results' => $results, 'total_missing' => $total_missing, 'scanned_albums' => $scanned_albums, 'scanned_images' => $scanned_images, 'generated_at' => time()], JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── admin action: reset hero ─────────────────────────────────────────────────
if (isset($_GET['reset_hero']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
    if (!$ha) { http_response_code(400); exit; }
    $cfg = parse_config(IMG_DIR . '/' . $ha);
    unset($cfg['hero']);
    if ($cfg) {
        write_config(IMG_DIR . '/' . $ha, $cfg);
    } else {
        $cfg_path = IMG_DIR . '/' . $ha . '/config.txt';
        if (is_file($cfg_path)) unlink($cfg_path);
    }
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: save album order ──────────────────────────────────────────
if (isset($_GET['save_album_order']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $slugs = array_filter(array_map('trim', explode(',', $_POST['order'] ?? '')),
        fn($s) => safe_seg($s) !== null);
    $cfg = parse_config(IMG_DIR);
    $cfg['order'] = implode(',', $slugs);
    write_config(IMG_DIR, $cfg);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: save image order ──────────────────────────────────────────
if (isset($_GET['save_image_order']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
    if (!$ha) { http_response_code(400); exit; }
    $files = array_filter(array_map('trim', explode(',', $_POST['order'] ?? '')),
        fn($s) => safe_seg($s) !== null && is_file(source_image_path($ha, $s)));
    $cfg = parse_config(IMG_DIR . '/' . $ha);
    $cfg['order'] = implode(',', $files);
    write_config(IMG_DIR . '/' . $ha, $cfg);
    @unlink(album_order_cache_file($ha));
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: save album name ───────────────────────────────────────────
if (isset($_GET['save_album_name']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf'] ?? '');
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
    $new_name = trim($_POST['name'] ?? '');
    if (!$ha || $new_name === '') { http_response_code(400); exit; }
    $cfg = parse_config(IMG_DIR . '/' . $ha);
    $cfg['name'] = $new_name;
    $new_name_en = trim($_POST['name_en'] ?? '');
    if ($new_name_en !== '') { $cfg['name_en'] = $new_name_en; } else { unset($cfg['name_en']); }
    $new_desc    = trim(str_replace(["\r\n", "\r", "\n"], ' ', $_POST['description'] ?? ''));
    $new_desc_en = trim(str_replace(["\r\n", "\r", "\n"], ' ', $_POST['description_en'] ?? ''));
    if ($new_desc !== '')    { $cfg['description'] = $new_desc; }    else { unset($cfg['description']); }
    if ($new_desc_en !== '') { $cfg['description_en'] = $new_desc_en; } else { unset($cfg['description_en']); }
    if (($_POST['captions'] ?? '0') === '1') { $cfg['captions'] = '1'; } else { unset($cfg['captions']); }
    write_config(IMG_DIR . '/' . $ha, $cfg);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: delete album ──────────────────────────────────────────────
if (isset($_GET['delete_album']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf'] ?? '');
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
    if (!$ha || !is_dir(IMG_DIR . '/' . $ha)) { http_response_code(400); exit; }
    if (($_POST['confirm'] ?? '') !== 'DELETE_UPLOADED_IMAGES') { http_response_code(400); exit; }
    $album_dir = IMG_DIR . '/' . $ha;
    if (!delete_album_dir($album_dir)) { http_response_code(500); exit; }
    remove_album_from_series($ha);
    remove_album_from_overview_order($ha);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: save series display order ─────────────────────────────────
if (isset($_GET['save_series_order']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $raw = array_filter(array_map('trim', explode(',', $_POST['order'] ?? '')));
    $valid = array_values(array_filter($raw, fn($id) => in_array($id, SERIES_IDS, true)));
    $missing = array_values(array_diff(SERIES_IDS, $valid));
    $s = load_settings();
    $s['series_order'] = array_merge($valid, $missing);
    atomic_write(SETTINGS_FILE, json_encode($s, JSON_PRETTY_PRINT));
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: create series ─────────────────────────────────────────────
if (isset($_GET['create_series']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $sdata = load_series();
    $id = first_empty_series_id($sdata);
    header('Content-Type: application/json');
    if ($id === null) {
        http_response_code(409);
        echo '{"ok":false,"error":"No empty series slots left."}';
        exit;
    }
    $title    = substr(trim($_POST['title'] ?? ''), 0, 200);
    $title_en = substr(trim($_POST['title_en'] ?? ''), 0, 200);
    if (!multilingual_enabled()) {
        if ($title_en === '') $title_en = $title;
        if ($title === '') $title = $title_en;
    }
    if ($title === '' && $title_en === '') {
        http_response_code(400);
        echo '{"ok":false,"error":"Please enter a series title."}';
        exit;
    }
    $allowed_sbg = ['', '#000', '#888', '#fff'];
    $sbg = in_array($_POST['bg_color'] ?? '', $allowed_sbg, true) ? $_POST['bg_color'] : '';
    $sdata[$id] = array_merge(empty_series_record(), [
        'title' => $title,
        'title_en' => $title_en,
        'bg_color' => $sbg,
    ]);
    save_series_data($sdata);
    echo json_encode(['ok' => true, 'id' => $id, 'edit' => series_editor_url($id)], JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── admin action: delete series ─────────────────────────────────────────────
if (isset($_GET['delete_series']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $id = $_POST['id'] ?? '';
    if (!in_array($id, SERIES_IDS, true)) { http_response_code(400); exit; }
    $sdata = load_series();
    $sdata[$id] = empty_series_record();
    save_series_data($sdata);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: save series ───────────────────────────────────────────────
if (isset($_GET['save_series']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $id = $_POST['id'] ?? '';
    if (!in_array($id, SERIES_IDS, true)) { http_response_code(400); exit; }
    $title    = substr(trim($_POST['title'] ?? ''), 0, 200);
    $title_en = substr(trim($_POST['title_en'] ?? ''), 0, 200);
    $desc     = substr($_POST['description'] ?? '', 0, 5000);
    $desc_en  = substr($_POST['description_en'] ?? '', 0, 5000);
    $order_raw = array_filter(array_map('trim', explode(',', $_POST['order'] ?? '')));
    $images = [];
    foreach ($order_raw as $entry) {
        $eparts = explode('/', $entry, 2);
        if (count($eparts) !== 2) continue;
        [$alb_e, $file_e] = $eparts;
        if (!safe_seg($alb_e) || !safe_seg($file_e)) continue;
        if (!is_file(IMG_DIR . '/' . $alb_e . '/' . $file_e)) continue;
        $images[] = $alb_e . '/' . $file_e;
    }
    $allowed_sbg = ['', '#000', '#888', '#fff'];
    $sbg = in_array($_POST['bg_color'] ?? '', $allowed_sbg, true) ? $_POST['bg_color'] : '';
    $sdata = load_series();
    $dfs = preg_replace('/[^0-9.a-z%]/', '', $_POST['desc_font_size'] ?? '');
    $sdata[$id] = ['title' => $title, 'title_en' => $title_en, 'description' => $desc, 'description_en' => $desc_en, 'images' => $images, 'bg_color' => $sbg, 'desc_font_size' => $dfs, 'hidden' => $sdata[$id]['hidden'] ?? false, 'hero' => $sdata[$id]['hero'] ?? '', 'captions' => ($_POST['captions'] ?? '0') === '1'];
    save_series_data($sdata);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: assign series ─────────────────────────────────────────────
if (isset($_GET['assign_series']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $id  = $_POST['id'] ?? '';
    $alb = isset($_POST['a']) ? safe_seg($_POST['a']) : null;
    $fil = isset($_POST['f']) ? safe_seg($_POST['f']) : null;
    if (!in_array($id, SERIES_IDS, true) || !$alb || !$fil || !is_file(source_image_path($alb, $fil))) { http_response_code(400); exit; }
    $entry   = $alb . '/' . $fil;
    $checked = ($_POST['checked'] ?? '0') === '1';
    $sdata   = load_series();
    $imgs    = $sdata[$id]['images'] ?? [];
    if ($checked) {
        if (!in_array($entry, $imgs, true)) $imgs[] = $entry;
    } else {
        $imgs = array_values(array_filter($imgs, fn($e) => $e !== $entry));
    }
    $sdata[$id]['images'] = $imgs;
    save_series_data($sdata);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: generate AI caption ──────────────────────────────────────
if (isset($_GET['ai_caption']) && is_admin()) {
    set_time_limit(60);
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf'] ?? '');
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
    $hf = isset($_GET['f']) ? safe_seg($_GET['f']) : null;
    if (!$ha || !$hf || !source_image_allowed($hf) || !is_file(source_image_path($ha, $hf))) { http_response_code(400); exit; }
    ob_start();
    header('Content-Type: application/json');
    try {
        if (!caption_api_key()) {
            ob_end_clean();
            echo json_encode(['ok' => false, 'error' => 'no_api_key']);
            exit;
        }
        $bytes = compress_for_api(source_image_path($ha, $hf));
        if ($bytes === null) {
            ob_end_clean();
            echo json_encode(['ok' => false, 'error' => 'Could not compress image for API']);
            exit;
        }
        $result = gemini_caption($bytes, multilingual_enabled(), primary_lang_label());
        ob_end_clean();
        echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } catch (Throwable $e) {
        ob_end_clean();
        echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

// ─── admin action: save caption ──────────────────────────────────────────────
if (isset($_GET['save_caption']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf'] ?? '');
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
    $hf = isset($_GET['f']) ? safe_seg($_GET['f']) : null;
    if (!$ha || !$hf) { http_response_code(400); exit; }
    $de = trim(str_replace(["\r\n", "\r", "\n"], ' ', $_POST['caption'] ?? ''));
    $en = trim(str_replace(["\r\n", "\r", "\n"], ' ', $_POST['caption_en'] ?? ''));
    save_album_caption($ha, $hf, $de, $en);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: set album hidden ──────────────────────────────────────────
if (isset($_GET['set_album_hidden']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $ha = isset($_POST['a']) ? safe_seg($_POST['a']) : null;
    if (!$ha || !is_dir(IMG_DIR . '/' . $ha)) { http_response_code(400); exit; }
    $cfg = parse_config(IMG_DIR . '/' . $ha);
    if (($_POST['hidden'] ?? '') === '1') { $cfg['hidden'] = '1'; } else { unset($cfg['hidden']); }
    write_config(IMG_DIR . '/' . $ha, $cfg);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: set series hidden ─────────────────────────────────────────
if (isset($_GET['set_series_hidden']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $id = $_POST['id'] ?? '';
    if (!in_array($id, SERIES_IDS, true)) { http_response_code(400); exit; }
    $sdata = load_series();
    $sdata[$id]['hidden'] = ($_POST['hidden'] ?? '') === '1';
    save_series_data($sdata);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// ─── admin action: set series hero ───────────────────────────────────────────
if (isset($_GET['set_series_hero']) && is_admin()) {
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) { http_response_code(403); exit; }
    $id = $_POST['id'] ?? '';
    if (!in_array($id, SERIES_IDS, true)) { http_response_code(400); exit; }
    $f = trim($_POST['f'] ?? '');
    $sdata = load_series();
    if ($f && in_array($f, $sdata[$id]['images'] ?? [], true)) {
        $sdata[$id]['hero'] = $f;
    } else {
        $sdata[$id]['hero'] = '';
    }
    save_series_data($sdata);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    exit;
}

// Release PHP's session file lock for read-only page, image and thumbnail
// requests. Cold thumbnail rebuilds can otherwise block every same-session
// image request until the first request completes.
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

// ─── routing ─────────────────────────────────────────────────────────────────
$a = isset($_GET['a']) ? safe_seg($_GET['a']) : null;
$t = isset($_GET['t']) ? safe_seg($_GET['t']) : null;
$i = isset($_GET['i']) ? safe_seg($_GET['i']) : null;

if (isset($_GET['sitemap'])) { sitemap(); exit; }

// ─── thumb generation endpoint ────────────────────────────────────────────────
if (isset($_GET['gen_thumbs']) && $a !== null) {
    route_gen_thumbs($a);
}

// ─── large display-image generation endpoint ─────────────────────────────────
if (isset($_GET['gen_large']) && $a !== null) {
    route_gen_large($a);
}

// ─── series display-image generation endpoint ────────────────────────────────
if (isset($_GET['gen_series_large'])) {
    $sid = in_array($_GET['s'] ?? '', SERIES_IDS, true) ? (string)$_GET['s'] : '';
    if ($sid === '') { http_response_code(400); exit; }
    $sdata = load_series();
    $series = $sdata[$sid] ?? null;
    if (!$series || (!is_admin() && ($series['hidden'] ?? false))) { http_response_code(404); exit; }
    set_time_limit(300);
    ini_set('memory_limit', '512M');
    $made = 0;
    foreach (series_valid_images($series, is_admin()) as $img) {
        if (ensure_large_image($img['album'], $img['file'])) $made++;
    }
    header('Content-Type: application/json');
    echo json_encode(['ok' => true, 'count' => $made]);
    exit;
}

if ($a !== null && ($t !== null || $i !== null || $og !== null) && !is_admin()) {
    $_hcfg = parse_config(IMG_DIR . '/' . $a);
    if (($_hcfg['hidden'] ?? '') === '1') { http_response_code(404); exit; }
}
if ($a !== null && $og !== null) { serve_og_image($a, $og); exit; }
if ($a !== null && $t !== null) { serve_thumb_ar($a, $t); exit; }
if ($a !== null && $i !== null) { serve_image($a, $i); exit; }

if (isset($_GET['a']) && $a === null) { http_response_code(404); exit; }
if (isset($_GET['t']) && $t === null) { http_response_code(400); exit; }

if (isset($_GET['s'])) {
    $sid = in_array($_GET['s'], SERIES_IDS, true) ? $_GET['s'] : null;
    if ($sid) { page_series($sid); exit; }
    http_response_code(404); exit;
}
if (isset($_GET['edit_series'])) {
    if (!is_admin()) { header('Location: ./'); exit; }
    $sid = in_array($_GET['edit_series'], SERIES_IDS, true) ? $_GET['edit_series'] : null;
    if ($sid) { page_series_editor($sid); exit; }
    http_response_code(404); exit;
}
if (isset($_GET['caption_editor'])) {
    if (!is_admin()) { header('Location: ./'); exit; }
    $ca = safe_seg((string)$_GET['caption_editor']);
    if ($ca !== null && is_dir(IMG_DIR . '/' . $ca) && images_in($ca)) { page_caption_editor($ca); exit; }
    http_response_code(404); exit;
}

header('Cache-Control: no-cache, must-revalidate');

if ($a !== null) {
    $cfg  = parse_config(IMG_DIR . '/' . $a);
    if (($cfg['hidden'] ?? '') === '1' && !is_admin()) {
        http_response_code(404);
        echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Not Found</title><style>*{margin:0;padding:0;box-sizing:border-box}html,body{background:#000;color:#fff;font-family:sans-serif;height:100vh;display:flex;align-items:center;justify-content:center;text-transform:uppercase;letter-spacing:.15em;font-size:.7rem}</style></head><body>Not Found</body></html>';
        exit;
    }
    $imgs = images_in($a);
    if (!$imgs) { http_response_code(404); exit; }
    $share_image = isset($_GET['share_image']) ? safe_seg((string)$_GET['share_image']) : null;
    if ($share_image !== null && !in_array($share_image, $imgs, true)) { http_response_code(404); exit; }
    page_album($a, $cfg, $imgs, $share_image);
} else {
    page_overview();
}

// ─── helpers ─────────────────────────────────────────────────────────────────

function safe_seg(string $s): ?string {
    if ($s === '' || $s[0] === '.' || $s[0] === '_') return null;
    return preg_match('/^[\p{L}\p{N}._ ()\[\]\'!,&+-]+$/u', $s) ? $s : null;
}

function clean_route_segments(): array {
    $uri = (string)($_SERVER['REQUEST_URI'] ?? '');
    $path = rawurldecode((string)parse_url($uri, PHP_URL_PATH));
    return clean_route_segments_from_path($path);
}

function route_path_parts(string $path): array {
    $script = (string)($_SERVER['SCRIPT_NAME'] ?? '');
    $base = rtrim(str_replace('\\', '/', dirname($script)), '/');
    if ($base !== '' && $base !== '/' && strpos($path, $base . '/') === 0) {
        $path = substr($path, strlen($base));
    }
    $path = trim($path, '/');
    if ($path === '' || $path === 'index.php') return [];
    if (strpos($path, 'index.php/') === 0) {
        $path = substr($path, strlen('index.php/'));
    }
    return array_values(array_filter(explode('/', $path), 'strlen'));
}

function clean_route_segments_from_path(string $path): array {
    $parts = route_path_parts($path);
    if (count($parts) > 2) return [];
    $out = [];
    foreach ($parts as $part) {
        $seg = safe_seg($part);
        if ($seg === null) return [];
        $out[] = $seg;
    }
    return $out;
}

function apply_clean_route(): void {
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) return;
    $route_path = '';
    if (isset($_GET['lb_path'])) {
        $route_path = (string)$_GET['lb_path'];
        unset($_GET['lb_path']);
    } else {
        $route_path = (string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
        if (!route_path_parts(rawurldecode($route_path))) return;
    }
    $raw_parts = route_path_parts(rawurldecode($route_path));
    $route_lang = null;
    if ($raw_parts && in_array($raw_parts[0], public_langs(), true)) {
        $route_lang = array_shift($raw_parts);
        $_GET['lang'] = $route_lang;
        $_SERVER['LB_LANG_FROM_PATH'] = '1';
    }
    if (count($raw_parts) === 4 && $raw_parts[0] === '_lb' && in_array($raw_parts[1], ['thumb', 'large', 'og'], true)) {
        $album = safe_seg($raw_parts[2]);
        $file = safe_seg($raw_parts[3]);
        if ($album !== null && $file !== null) {
            $_GET['a'] = $album;
            if ($raw_parts[1] === 'thumb') {
                $_GET['t'] = $file;
                $_GET['ar'] = '1';
            } elseif ($raw_parts[1] === 'large') {
                $_GET['i'] = $file;
            } else {
                $_GET['og_image'] = $file;
            }
        }
        return;
    }
    if (count($raw_parts) === 1 && $raw_parts[0] === 'all') {
        $_GET['all'] = '1';
        return;
    }
    if (count($raw_parts) === 1 && $raw_parts[0] === 'admin') {
        $_GET['admin'] = '1';
        return;
    }
    if (count($raw_parts) === 2 && $raw_parts[0] === 'admin' && $raw_parts[1] === 'analytics') {
        $_GET['analytics_admin'] = '1';
        return;
    }
    if (count($raw_parts) === 3 && $raw_parts[0] === 'admin' && $raw_parts[1] === 'series') {
        $_GET['edit_series'] = $raw_parts[2];
        return;
    }
    if (count($raw_parts) === 1 && in_array($raw_parts[0], ['sitemap', 'sitemap.xml'], true)) {
        $_GET['sitemap'] = '1';
        return;
    }
    if (count($raw_parts) === 2 && $raw_parts[0] === 'series') {
        $sid = resolve_series_seo_slug($raw_parts[1], $route_lang);
        if ($sid !== null) $_GET['s'] = $sid;
        return;
    }
    if (count($raw_parts) === 2 && $raw_parts[0] === 'album') {
        $album = resolve_album_seo_slug($raw_parts[1], $route_lang);
        if ($album !== null) $_GET['a'] = $album;
        return;
    }
    if (count($raw_parts) === 4 && $raw_parts[0] === 'album' && $raw_parts[2] === 'photo') {
        $album = resolve_album_seo_slug($raw_parts[1], $route_lang);
        $file = $album !== null ? resolve_photo_seo_slug($album, $raw_parts[3]) : null;
        if ($album !== null && $file !== null) {
            $_GET['a'] = $album;
            $_GET['share_image'] = $file;
        }
        return;
    }
    if ($_GET) return;
    $parts = clean_route_segments_from_path($route_path);
    if (!$parts) return;
    $_GET['a'] = $parts[0];
    if (isset($parts[1])) {
        $_GET['share_image'] = $parts[1];
    }
}

function clean_urls_enabled(): bool {
    return !empty(load_settings()['clean_urls']);
}

function lightbox_htaccess_block(): string {
    return "# BEGIN Lightbox\n"
        . "Options -Indexes\n"
        . "<IfModule mod_rewrite.c>\n"
        . "  RewriteEngine On\n"
        . "\n"
        . "  RewriteRule ^images/[^/]+/(?!thumbs/|large/).+ - [R=404,L]\n"
        . "  RewriteRule ^analytics/ - [R=404,L]\n"
        . "\n"
        . "  RewriteCond %{REQUEST_FILENAME} !-f\n"
        . "  RewriteCond %{REQUEST_FILENAME} !-d\n"
        . "  RewriteRule ^ index.php [L,QSA]\n"
        . "</IfModule>\n"
        . "# END Lightbox";
}

function ensure_lightbox_htaccess(?string $path = null): array {
    $path = $path ?? (__DIR__ . '/.htaccess');
    $block = lightbox_htaccess_block();
    $begin = '# BEGIN Lightbox';
    $end = '# END Lightbox';
    $current = '';
    $exists = is_file($path);
    if ($exists) {
        $contents = @file_get_contents($path);
        if ($contents === false) {
            return [
                'ok' => false,
                'status' => 'read_failed',
                'message' => 'Clean URLs are enabled, but Lightbox could not read .htaccess. Add the rewrite rules manually.',
            ];
        }
        $current = $contents;
    }
    $pattern = '/' . preg_quote($begin, '/') . '.*?' . preg_quote($end, '/') . '\R?/s';
    if (preg_match($pattern, $current)) {
        $next = preg_replace($pattern, $block . "\n", $current, 1);
        if (!is_string($next)) $next = $current;
        $status = 'updated';
    } else {
        $trimmed = rtrim($current);
        $next = ($trimmed === '' ? '' : $trimmed . "\n\n") . $block . "\n";
        $status = $exists ? 'appended' : 'created';
    }
    if ($next === $current) {
        return ['ok' => true, 'status' => 'current', 'message' => 'Clean URL rewrite rules are already current.'];
    }
    if (!atomic_write($path, $next, 0664)) {
        return [
            'ok' => false,
            'status' => 'write_failed',
            'message' => 'Clean URLs are enabled, but Lightbox could not write .htaccess. Add the rewrite rules manually or make the gallery folder writable.',
        ];
    }
    return ['ok' => true, 'status' => $status, 'message' => 'Clean URL rewrite rules were written to .htaccess.'];
}

function path_url_encode(string $seg): string {
    return str_replace('%2F', '/', rawurlencode($seg));
}

function seo_strip_html_suffix(string $slug): string {
    return preg_replace('/\.html$/i', '', trim($slug)) ?? trim($slug);
}

function seo_slugify(string $name, string $fallback = 'item'): string {
    $name = trim($name);
    if ($name === '') $name = $fallback;
    $ascii = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $name);
    if (is_string($ascii) && $ascii !== '') $name = $ascii;
    $name = strtolower($name);
    $name = preg_replace('/[^a-z0-9]+/', '-', $name) ?? '';
    $name = trim($name, '-');
    return $name !== '' ? substr($name, 0, 90) : $fallback;
}

function seo_unique_slug_map(array $labels): array {
    $out = [];
    $used = [];
    foreach ($labels as $key => $label) {
        $base = seo_slugify((string)$label, (string)$key);
        $slug = $base;
        $n = 2;
        while (isset($used[$slug])) {
            $slug = substr($base, 0, 82) . '-' . $n++;
        }
        $used[$slug] = true;
        $out[(string)$key] = $slug;
    }
    return $out;
}

function public_langs(): array {
    return ['de', 'en'];
}

function normalize_public_lang(?string $lang = null): string {
    $lang = $lang ?? current_lang();
    return $lang === 'en' ? 'en' : 'de';
}

function lang_prefix_enabled(): bool {
    return clean_urls_enabled() && multilingual_enabled();
}

function lang_path_prefix(?string $lang = null): string {
    return lang_prefix_enabled() ? normalize_public_lang($lang) . '/' : '';
}

function localized_label(array $data, string $key, string $lang, string $fallback = ''): string {
    if ($lang === 'en') {
        $v = trim((string)($data[$key . '_en'] ?? ''));
        if ($v !== '') return $v;
    }
    $v = trim((string)($data[$key] ?? ''));
    if ($v !== '') return $v;
    if ($lang !== 'en') {
        $v = trim((string)($data[$key . '_en'] ?? ''));
        if ($v !== '') return $v;
    }
    return $fallback;
}

function album_seo_slug_map(?string $lang = null): array {
    static $maps = [];
    $lang = normalize_public_lang($lang);
    if (isset($maps[$lang])) return $maps[$lang];
    $labels = [];
    foreach (albums() as $al) {
        $slug = (string)$al['slug'];
        $labels[$slug] = localized_label($al, 'name', $lang, default_album_name($slug));
    }
    return $maps[$lang] = seo_unique_slug_map($labels);
}

function album_seo_slug(string $album, ?string $lang = null): string {
    $map = album_seo_slug_map($lang);
    return $map[$album] ?? seo_slugify(default_album_name($album), $album);
}

function resolve_album_seo_slug(string $slug, ?string $lang = null): ?string {
    $slug = seo_strip_html_suffix($slug);
    if (!preg_match('/^[a-z0-9-]+$/', $slug)) return null;
    foreach (album_seo_slug_map($lang) as $album => $seo_slug) {
        if ($seo_slug === $slug) return safe_seg($album);
    }
    if ($lang !== null) {
        foreach (public_langs() as $fallback_lang) {
            if ($fallback_lang === normalize_public_lang($lang)) continue;
            foreach (album_seo_slug_map($fallback_lang) as $album => $seo_slug) {
                if ($seo_slug === $slug) return safe_seg($album);
            }
        }
    }
    return null;
}

function series_title_for_lang(array $series, string $lang, string $fallback = ''): string {
    return localized_label($series, 'title', $lang, $fallback);
}

function series_seo_slug_map(?string $lang = null): array {
    static $maps = [];
    $lang = normalize_public_lang($lang);
    if (isset($maps[$lang])) return $maps[$lang];
    $labels = [];
    foreach (load_series() as $sid => $series) {
        if (!in_array($sid, SERIES_IDS, true)) continue;
        if (!series_has_admin_content($series)) continue;
        $labels[$sid] = series_title_for_lang($series, $lang, $sid);
    }
    return $maps[$lang] = seo_unique_slug_map($labels);
}

function series_seo_slug(string $id, ?string $lang = null): string {
    $map = series_seo_slug_map($lang);
    return $map[$id] ?? seo_slugify($id, $id);
}

function resolve_series_seo_slug(string $slug, ?string $lang = null): ?string {
    $slug = seo_strip_html_suffix($slug);
    if (!preg_match('/^[a-z0-9-]+$/', $slug)) return null;
    foreach (series_seo_slug_map($lang) as $id => $seo_slug) {
        if ($seo_slug === $slug) return in_array($id, SERIES_IDS, true) ? $id : null;
    }
    if ($lang !== null) {
        foreach (public_langs() as $fallback_lang) {
            if ($fallback_lang === normalize_public_lang($lang)) continue;
            foreach (series_seo_slug_map($fallback_lang) as $id => $seo_slug) {
                if ($seo_slug === $slug) return in_array($id, SERIES_IDS, true) ? $id : null;
            }
        }
    }
    return null;
}

function photo_seo_slug_map(string $album): array {
    static $maps = [];
    if (isset($maps[$album])) return $maps[$album];
    $labels = [];
    foreach (images_in($album) as $file) {
        $stem = substr(seo_slugify(pathinfo($file, PATHINFO_FILENAME), 'photo'), 0, 72);
        $labels[$file] = $stem . '-' . substr(sha1($file), 0, 8);
    }
    return $maps[$album] = seo_unique_slug_map($labels);
}

function photo_seo_slug(string $album, string $file): string {
    $map = photo_seo_slug_map($album);
    return $map[$file] ?? seo_slugify(pathinfo($file, PATHINFO_FILENAME) . '-' . substr(sha1($file), 0, 8), $file);
}

function resolve_photo_seo_slug(string $album, string $slug): ?string {
    $slug = seo_strip_html_suffix($slug);
    if (!preg_match('/^[a-z0-9-]+$/', $slug)) return null;
    foreach (photo_seo_slug_map($album) as $file => $seo_slug) {
        if ($seo_slug === $slug) return safe_seg($file);
    }
    return null;
}

function series_url(string $id, ?string $lang = null): string {
    if (clean_urls_enabled()) return public_url(lang_path_prefix($lang) . 'series/' . path_url_encode(series_seo_slug($id, $lang)));
    return public_url('?s=' . urlencode($id));
}

function all_photos_url(?string $lang = null): string {
    return clean_urls_enabled() ? public_url(lang_path_prefix($lang) . 'all') : public_url('?all');
}

function admin_url(?string $lang = null): string {
    return clean_urls_enabled() ? public_url(lang_path_prefix($lang) . 'admin') : public_url('?admin');
}

function analytics_admin_url(int $range = 0, ?string $lang = null): string {
    $url = clean_urls_enabled() ? public_url(lang_path_prefix($lang) . 'admin/analytics') : public_url('?analytics_admin=1');
    return $range > 0 ? add_url_param($url, 'range', (string)$range) : $url;
}

function series_editor_url(string $id, ?string $lang = null): string {
    return clean_urls_enabled() ? public_url(lang_path_prefix($lang) . 'admin/series/' . path_url_encode($id)) : public_url('?edit_series=' . urlencode($id));
}

function sitemap_url(?string $lang = null): string {
    return clean_urls_enabled() ? public_url(lang_path_prefix($lang) . 'sitemap.xml') : public_url('?sitemap=1');
}

function json_response(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function slugify_album(string $name): ?string {
    $name = trim($name);
    if ($name === '') return null;
    $ascii = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $name);
    if (is_string($ascii) && $ascii !== '') $name = $ascii;
    $name = strtolower($name);
    $name = preg_replace('/[^a-z0-9]+/', '-', $name) ?? '';
    $name = trim($name, '-');
    return $name !== '' ? substr($name, 0, 80) : null;
}

function unique_album_slug(string $name): ?string {
    $base = slugify_album($name);
    if ($base === null) return null;
    $slug = $base;
    $n = 2;
    while (is_dir(IMG_DIR . '/' . $slug)) {
        $slug = substr($base, 0, 72) . '-' . $n++;
    }
    return safe_seg($slug);
}

function normalize_upload_files($input): array {
    if (!is_array($input) || !isset($input['name'])) return [];
    if (!is_array($input['name'])) return [$input];
    $files = [];
    foreach ($input['name'] as $idx => $name) {
        $files[] = [
            'name' => $name,
            'type' => $input['type'][$idx] ?? '',
            'tmp_name' => $input['tmp_name'][$idx] ?? '',
            'error' => $input['error'][$idx] ?? UPLOAD_ERR_NO_FILE,
            'size' => $input['size'][$idx] ?? 0,
        ];
    }
    return $files;
}

function upload_image_extension(string $tmp): ?string {
    $info = @getimagesize($tmp);
    if (!$info) return null;
    $mime = $info['mime'] ?? '';
    if ($mime === 'image/jpeg') return 'jpg';
    if ($mime === 'image/png') return 'png';
    if ($mime === 'image/webp') return 'webp';
    return null;
}

function upload_dimension_limit_error(string $tmp): string {
    $info = @getimagesize($tmp);
    if (!$info) return 'unsupported image type.';
    $w = (int)($info[0] ?? 0);
    $h = (int)($info[1] ?? 0);
    if ($w < 1 || $h < 1) return 'invalid image dimensions.';
    if ($w * $h > UPLOAD_MAX_PIXELS) return 'image has more than ' . number_format(UPLOAD_MAX_PIXELS) . ' pixels.';
    if (max($w, $h) > UPLOAD_MAX_LONG_EDGE) return 'long edge exceeds ' . UPLOAD_MAX_LONG_EDGE . ' px.';
    return '';
}

function format_bytes(int $bytes): string {
    if ($bytes >= 1000000) return rtrim(rtrim(number_format($bytes / 1000000, 1), '0'), '.') . ' MB';
    if ($bytes >= 1000) return rtrim(rtrim(number_format($bytes / 1000, 1), '0'), '.') . ' KB';
    return $bytes . ' bytes';
}

function upload_filename_base(string $name): string {
    $base = pathinfo($name, PATHINFO_FILENAME);
    $base = trim($base);
    $ascii = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $base);
    if (is_string($ascii) && $ascii !== '') $base = $ascii;
    $base = preg_replace('/[^A-Za-z0-9._ -]+/', '-', $base) ?? '';
    $base = trim($base, ". \t\n\r\0\x0B-_");
    return $base !== '' ? substr($base, 0, 120) : 'image';
}

function unique_image_filename(string $dir, string $base, string $ext): string {
    $name = $base . '.' . $ext;
    $n = 2;
    while (is_file($dir . '/' . $name)) {
        $name = substr($base, 0, 112) . '-' . $n++ . '.' . $ext;
    }
    return $name;
}

function clamp_int($value, int $min, int $max): int {
    return max($min, min($max, (int)$value));
}

function ensure_writable_dir(string $dir, int $mode = 0775): bool {
    if (is_dir($dir)) {
        @chmod($dir, $mode);
        if (is_writable($dir)) return true;
        error_log('Lightbox: directory is not writable: ' . $dir);
        return false;
    }
    $parent = dirname($dir);
    if ($parent !== $dir && !is_dir($parent) && !ensure_writable_dir($parent, $mode)) {
        return false;
    }
    if (!is_dir($dir) && !@mkdir($dir, $mode)) {
        error_log('Lightbox: could not create directory: ' . $dir);
        return false;
    }
    @chmod($dir, $mode);
    if (is_dir($dir) && is_writable($dir)) return true;
    error_log('Lightbox: created directory is not writable: ' . $dir);
    return false;
}

function repair_generated_cache_dir(string $dir, int $mode = 0775): bool {
    if (ensure_writable_dir($dir, $mode)) return true;
    if (!is_dir($dir)) return false;
    $parent = dirname($dir);
    if (!is_writable($parent)) {
        error_log('Lightbox: cannot repair cache dir because parent is not writable: ' . $parent);
        return false;
    }
    $backup = $dir . '.broken-' . date('Ymd-His') . '-' . substr(bin2hex(random_bytes(3)), 0, 6);
    if (!@rename($dir, $backup)) {
        error_log('Lightbox: could not move broken cache dir aside: ' . $dir);
        return false;
    }
    error_log('Lightbox: moved broken cache dir aside: ' . $dir . ' -> ' . $backup);
    return ensure_writable_dir($dir, $mode);
}

function cache_error_response(string $kind, string $album): void {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Lightbox could not create or write the ' . $kind . ' cache for album "' . $album . '". ';
    echo 'Make sure the album folder and its generated cache folders are writable by the web server.';
    exit;
}

function is_admin(): bool { return !empty($_SESSION['admin']); }

function admin_password_file(): string {
    $env = trim((string)(getenv('LIGHTBOX_ADMIN_PASSWORD_FILE') ?: ''));
    if ($env !== '') {
        if ($env[0] === '/' || preg_match('/^[A-Za-z]:[\/\\\\]/', $env)) return $env;
        return __DIR__ . '/' . $env;
    }
    return __DIR__ . '/.lightbox_admin_password.php';
}

function admin_password_reset_file(): string {
    return __DIR__ . '/reset-pass.txt';
}

function admin_password_reset_requested(): bool {
    return is_file(admin_password_reset_file());
}

function lightbox_env(string $key): ?string {
    $v = getenv($key);
    if ($v !== false && $v !== '') return $v;
    static $envs = null;
    if ($envs === null) {
        $envs = [];
        foreach ([__DIR__ . '/.env', '/home/master/applications/chrismarquardt/private_html/.env'] as $f) {
            if (!is_readable($f)) continue;
            foreach (@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') continue;
                $eq = strpos($line, '=');
                if ($eq === false) continue;
                $k = trim(substr($line, 0, $eq));
                $val = trim(substr($line, $eq + 1));
                if (strlen($val) >= 2 && ($val[0] === '"' || $val[0] === "'") && $val[strlen($val) - 1] === $val[0]) {
                    $val = substr($val, 1, -1);
                }
                if ($k !== '') $envs[$k] = $val;
            }
        }
    }
    return isset($envs[$key]) && $envs[$key] !== '' ? $envs[$key] : null;
}

function caption_api_key(): ?string {
    return lightbox_env('LIGHTBOX_GOOGLE_API_KEY');
}

function compress_for_api(string $src): ?string {
    ini_set('memory_limit', '512M');
    $max = 1024;
    foreach ([80, 65, 50, 40] as $q) {
        $res = resized_jpeg_resource($src, $max, false);
        if (!$res) return null;
        ob_start();
        imagejpeg($res, null, $q);
        $bytes = ob_get_clean();
        gd_destroy($res);
        if (strlen($bytes) < 100000) return $bytes;
        $max = 800;
    }
    return null;
}

function gemini_caption(string $jpegBytes, bool $multi, string $primaryLabel): array {
    $key = caption_api_key();
    if (!$key) return ['ok' => false, 'de' => '', 'en' => '', 'error' => 'no_api_key'];
    if (!function_exists('curl_init')) return ['ok' => false, 'de' => '', 'en' => '', 'error' => 'cURL not available'];
    $langMap = ['DE'=>'German','FR'=>'French','ES'=>'Spanish','IT'=>'Italian','NL'=>'Dutch','PT'=>'Portuguese','PL'=>'Polish','SV'=>'Swedish','NO'=>'Norwegian','DA'=>'Danish'];
    $primaryLangName = $langMap[strtoupper($primaryLabel)] ?? $primaryLabel;
    $b64 = base64_encode($jpegBytes);
    $url = 'https://generativelanguage.googleapis.com/v1beta/models/' . GEMINI_MODEL . ':generateContent?key=' . urlencode($key);
    $post = function(array $parts) use ($url): string {
        $body = json_encode(['contents' => [['parts' => $parts]], 'generationConfig' => ['temperature' => 0.4]], JSON_UNESCAPED_SLASHES);
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>$body, CURLOPT_HTTPHEADER=>['Content-Type: application/json'], CURLOPT_TIMEOUT=>30]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        unset($ch);
        if ($resp === false || $code < 200 || $code >= 300) return '';
        $d = @json_decode($resp, true);
        $t = trim((string)($d['candidates'][0]['content']['parts'][0]['text'] ?? ''));
        $t = (string)preg_replace('/[\x00-\x1F\x7F]/u', ' ', $t);
        return trim($t, '"\'` ');
    };
    $en = $post([
        ['text' => 'Write a one-sentence caption (max 150 characters) for this photo in English. Plain text only, nothing else.'],
        ['inline_data' => ['mime_type' => 'image/jpeg', 'data' => $b64]],
    ]);
    if ($en === '') return ['ok' => false, 'de' => '', 'en' => '', 'error' => 'Empty response from Gemini'];
    if (!$multi) return ['ok' => true, 'de' => '', 'en' => $en, 'error' => ''];
    $de = $post([
        ['text' => 'Translate the following photo caption to ' . $primaryLangName . '. Keep it to one sentence, max 150 characters. Plain text only, nothing else.' . "\n\n" . $en],
    ]);
    if ($de === '') $de = $en;
    return ['ok' => true, 'de' => $de, 'en' => $en, 'error' => ''];
}

function reset_admin_password(): void {
    $reset_file = admin_password_reset_file();
    if (is_file($reset_file)) @unlink($reset_file);
    $password_file = admin_password_file();
    if (is_file($password_file)) @unlink($password_file);
}

function admin_password_hash(): ?string {
    $file = admin_password_file();
    if (!is_file($file) || !is_readable($file)) return null;
    $hash = include $file;
    $info = is_string($hash) ? password_get_info($hash) : ['algo' => null];
    return is_string($hash) && !empty($info['algo']) ? $hash : null;
}

function admin_password_configured(): bool {
    return admin_password_hash() !== null;
}

function save_admin_password_hash(string $hash, string &$err = ''): bool {
    $file = admin_password_file();
    $dir = dirname($file);
    if (!ensure_writable_dir($dir)) {
        $err = 'Password folder is not writable.';
        return false;
    }
    $php = "<?php\nreturn " . var_export($hash, true) . ";\n";
    if (@file_put_contents($file, $php, LOCK_EX) === false) {
        $err = 'Could not write password file.';
        return false;
    }
    @chmod($file, 0600);
    return true;
}

function admin_login_rate_file(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return sys_get_temp_dir() . '/lb_loginfail_' . hash('sha256', (string)$ip);
}

function admin_login_failures(): array {
    $file = admin_login_rate_file();
    $now = time();
    $data = @json_decode((string)@file_get_contents($file), true);
    if (!is_array($data)) $data = [];
    return array_values(array_filter($data, fn($t) => is_int($t) && $t > $now - 300));
}

function admin_login_rate_limited(): bool {
    return count(admin_login_failures()) >= 5;
}

function record_admin_login_failure(): void {
    $failures = admin_login_failures();
    $failures[] = time();
    @file_put_contents(admin_login_rate_file(), json_encode($failures), LOCK_EX);
}

function clear_admin_login_failures(): void {
    @unlink(admin_login_rate_file());
}

function icon_eye_open(): string {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><ellipse cx="8" cy="8" rx="6.5" ry="4" stroke="currentColor" stroke-width="1.4" fill="none"/><circle cx="8" cy="8" r="2" fill="currentColor"/></svg>';
}
function icon_eye_closed(): string {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><ellipse cx="8" cy="8" rx="6.5" ry="4" stroke="currentColor" stroke-width="1.4" fill="none" opacity=".4"/><circle cx="8" cy="8" r="2" fill="currentColor" opacity=".4"/><line x1="2" y1="13" x2="14" y2="3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';
}
function icon_arrow_left(): string {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" fill-rule="evenodd" d="M14.75 8a.75.75 0 0 1-.75.75H3.81l2.72 2.72a.75.75 0 1 1-1.06 1.06l-4-4a.75.75 0 0 1 0-1.06l4-4a.75.75 0 0 1 1.06 1.06L3.81 7.25H14a.75.75 0 0 1 .75.75" clip-rule="evenodd"/></svg>';
}
function icon_arrow_right(): string {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 16 16" aria-hidden="true" style="transform:scaleX(-1)"><path fill="currentColor" fill-rule="evenodd" d="M14.75 8a.75.75 0 0 1-.75.75H3.81l2.72 2.72a.75.75 0 1 1-1.06 1.06l-4-4a.75.75 0 0 1 0-1.06l4-4a.75.75 0 0 1 1.06 1.06L3.81 7.25H14a.75.75 0 0 1 .75.75" clip-rule="evenodd"/></svg>';
}
function icon_trash(): string {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="none" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" fill-rule="evenodd" d="M6.5 1.75a.25.25 0 0 0-.25.25V3h3.5V2a.25.25 0 0 0-.25-.25zM4.5 3V2A1.75 1.75 0 0 1 6.25.25h3.5A1.75 1.75 0 0 1 11.5 2v1H14a.75.75 0 0 1 0 1.5h-.25v9.75A1.75 1.75 0 0 1 12 16H4a1.75 1.75 0 0 1-1.75-1.75V4.5H2a.75.75 0 0 1 0-1.5zM4 4.5h8v9.75a.25.25 0 0 1-.25.25H4.25a.25.25 0 0 1-.25-.25z" clip-rule="evenodd"/></svg>';
}
function icon_rotate(): string {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="none" viewBox="0 0 16 16" overflow="visible" aria-hidden="true"><path fill="currentColor" fill-rule="evenodd" d="M8 2.5A5.5 5.5 0 1 0 11.95 4H10.5a.75.75 0 0 1 0-1.5H13A.75.75 0 0 1 13.75 3.25v2.5a.75.75 0 0 1-1.5 0V4.628A7 7 0 1 1 8 1a.75.75 0 0 1 0 1.5z" clip-rule="evenodd"/></svg>';
}

function default_settings(): array {
    return [
        'site_title'             => 'New Photo Gallery',
        'site_title_en'          => 'New Photo Gallery',
        'series_label'           => 'SERIES',
        'series_label_en'        => 'SERIES',
        'all_photos_label'       => 'Alle Fotos',
        'all_photos_label_en'    => 'All Photos',
        'share_label'            => 'Teilen',
        'share_label_en'         => 'Share',
        'copied_label'           => 'Kopiert',
        'copied_label_en'        => 'Copied',
        'album_label'            => 'Album',
        'album_label_en'         => 'Album',
        'albums_label'           => 'ALBUMS',
        'albums_label_en'        => 'ALBUMS',
        'source_label'           => 'Quelle',
        'source_label_en'        => 'Source',
        'sources_label'          => 'Quellen',
        'sources_label_en'       => 'Sources',
        'multilingual'           => false,
        'primary_lang_label'     => 'DE',
        'gap'                    => 3,
        'content_padding'        => 3,
        'nav_font_size'          => '1rem',
        'tile_label_font_size'   => '.8rem',
        'desc_font_size'         => '1.1rem',
        'series_row_gap'         => '1rem',
        'series_width_desktop'   => 800,
        'series_padding_mobile'  => 16,
        'thumb_quality'          => DEFAULT_THUMB_QUALITY,
        'display_long_edge'      => DEFAULT_DISPLAY_LONG_EDGE,
        'display_quality'        => DEFAULT_DISPLAY_QUALITY,
        'analytics_enabled'      => true,
        'bg_color'               => '#fff',
        'clean_urls'             => false,
        'series_order'           => SERIES_IDS,
    ];
}

function load_settings(): array {
    static $c = null;
    if ($c !== null) return $c;
    $d = default_settings();
    if (!is_file(SETTINGS_FILE)) return $c = $d;
    $s = @json_decode((string)file_get_contents(SETTINGS_FILE), true);
    return $c = is_array($s) ? array_merge($d, $s) : $d;
}

function multilingual_enabled(): bool {
    return (bool)(load_settings()['multilingual'] ?? false);
}

function primary_lang_label(): string {
    $label = trim((string)(load_settings()['primary_lang_label'] ?? 'DE'));
    $label = preg_replace('/[^\p{L}\p{N} ._-]/u', '', $label) ?? '';
    return $label !== '' ? substr($label, 0, 16) : 'DE';
}

function primary_html_lang_attr(): string {
    $label = primary_lang_label();
    return preg_match('/^[a-z]{2,3}$/i', $label) ? strtolower($label) : 'und';
}

function html_lang_attr(): string {
    return current_lang() === 'en' ? 'en' : primary_html_lang_attr();
}

function thumb_quality(): int {
    return clamp_int(load_settings()['thumb_quality'] ?? DEFAULT_THUMB_QUALITY, 40, 100);
}

function display_long_edge(): int {
    return clamp_int(load_settings()['display_long_edge'] ?? DEFAULT_DISPLAY_LONG_EDGE, 800, 8000);
}

function display_quality(): int {
    return clamp_int(load_settings()['display_quality'] ?? DEFAULT_DISPLAY_QUALITY, 40, 100);
}

function site_title_text(): string {
    $title = trim(lf(load_settings(), 'site_title'));
    return $title !== '' ? $title : DEFAULT_SITE_TITLE;
}

function site_title_html(): string {
    $s = load_settings();
    return bi($s['site_title'] ?? DEFAULT_SITE_TITLE, $s['site_title_en'] ?? '');
}

function thumb_allows_legacy(): bool {
    return thumb_quality() === DEFAULT_THUMB_QUALITY;
}

function current_lang(): string {
    if (!multilingual_enabled()) return 'en';
    if (isset($_GET['lang']) && in_array($_GET['lang'], ['en', 'de'], true)) return $_GET['lang'];
    return ($_COOKIE['lb_lang'] ?? 'de') === 'en' ? 'en' : 'de';
}
function t(string $de, string $en): string {
    return current_lang() === 'en' ? $en : $de;
}
function lf(array $data, string $key): string {
    if (current_lang() === 'en') {
        $v = $data[$key . '_en'] ?? '';
        if ($v !== '') return $v;
    }
    return $data[$key] ?? '';
}
function lang_url(string $lang): string {
    $lang = normalize_public_lang($lang);
    if (clean_urls_enabled()) {
        if (isset($_GET['a'])) {
            $album = safe_seg((string)$_GET['a']);
            if ($album !== null && isset($_GET['share_image'])) {
                $file = safe_seg((string)$_GET['share_image']);
                if ($file !== null) return image_clean_url($album, $file, $lang);
            }
            if ($album !== null) return album_url($album, $lang);
        }
        if (isset($_GET['s']) && in_array($_GET['s'], SERIES_IDS, true)) return series_url((string)$_GET['s'], $lang);
        if (isset($_GET['all'])) return all_photos_url($lang);
        if (isset($_GET['analytics_admin'])) return analytics_admin_url((int)($_GET['range'] ?? 0), $lang);
        if (isset($_GET['edit_series']) && in_array($_GET['edit_series'], SERIES_IDS, true)) return series_editor_url((string)$_GET['edit_series'], $lang);
        if (isset($_GET['admin'])) return admin_url($lang);
        return public_url(lang_path_prefix($lang));
    }
    $params = $_GET;
    $params['lang'] = $lang;
    return '?' . http_build_query($params);
}

function current_lang_param(): string {
    if (clean_urls_enabled()) return '';
    return multilingual_enabled() ? '&lang=' . urlencode(current_lang()) : '';
}

function analytics_enabled(): bool {
    return !empty(load_settings()['analytics_enabled']);
}

function analytics_dir(): string {
    return __DIR__ . '/' . ANALYTICS_DIR;
}

function analytics_ensure_dir(): bool {
    $dir = analytics_dir();
    if (!ensure_writable_dir($dir)) return false;
    $ht = $dir . '/.htaccess';
    if (!is_file($ht)) {
        @file_put_contents($ht, "Options -Indexes\nRequire all denied\nDeny from all\n", LOCK_EX);
        @chmod($ht, 0664);
    }
    $readme = $dir . '/README.txt';
    if (!is_file($readme)) {
        $txt = "Lightbox analytics\n\nStores append-only JSONL event files.\nTracked: anonymous visitor/session IDs, album/photo views, photo dwell times, and image load success/failure timings.\nNot tracked: full IP addresses, user agents, cookies, secrets, or admin-only URLs.\nReset: delete events-*.jsonl and image-loads-*.jsonl.\nDisable: Admin Mode > General Settings > Privacy & Analytics.\n";
        @file_put_contents($readme, $txt, LOCK_EX);
        @chmod($readme, 0664);
    }
    return true;
}

function analytics_date_file(string $prefix, ?int $ts = null): string {
    $ts = $ts ?? time();
    return analytics_dir() . '/' . $prefix . '-' . date('Y-m-d', $ts) . '.jsonl';
}

function analytics_safe_id($v): string {
    $s = is_string($v) ? $v : '';
    return preg_match('/^[A-Za-z0-9_-]{12,80}$/', $s) ? $s : '';
}

function analytics_safe_text($v, int $max = 160): string {
    $s = trim((string)$v);
    $s = preg_replace('/[\x00-\x1F\x7F]+/', ' ', $s) ?? '';
    return substr($s, 0, $max);
}

function analytics_safe_path($v): string {
    $s = analytics_safe_text($v, 260);
    if ($s === '') return '';
    $parts = parse_url($s);
    $path = is_array($parts) ? (string)($parts['path'] ?? '') : $s;
    $query = is_array($parts) ? (string)($parts['query'] ?? '') : '';
    if (strpos($path, '..') !== false || preg_match('/[\x00-\x1F]/', $path)) return '';
    if ($query !== '') {
        parse_str($query, $q);
        $safe_q = [];
        foreach (['a', 't', 'i', 'ar'] as $k) {
            if (isset($q[$k]) && is_string($q[$k])) $safe_q[$k] = substr($q[$k], 0, 120);
        }
        $query = $safe_q ? '?' . http_build_query($safe_q) : '';
    }
    return substr($path . $query, 0, 260);
}

function analytics_album_exists(string $album): bool {
    return $album !== '' && safe_seg($album) === $album && is_dir(IMG_DIR . '/' . $album);
}

function analytics_photo_exists(string $album, string $photo): bool {
    return analytics_album_exists($album) && safe_seg($photo) === $photo && in_array($photo, images_in($album), true);
}

function analytics_write_line(string $prefix, array $row): bool {
    if (!analytics_ensure_dir()) return false;
    $path = analytics_date_file($prefix);
    $json = json_encode($row, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) return false;
    $ok = @file_put_contents($path, $json . "\n", FILE_APPEND | LOCK_EX) !== false;
    if ($ok) @chmod($path, 0664);
    return $ok;
}

function analytics_recent_duplicate(array $row): bool {
    $type = $row['type'] ?? '';
    if (!in_array($type, ['album_view', 'series_view', 'photo_view', 'series_source_click'], true)) return false;
    $file = analytics_date_file('events');
    if (!is_file($file) || filesize($file) > 5_000_000) return false;
    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) return false;
    $session = $row['sid'] ?? '';
    $album = $row['album'] ?? '';
    $photo = $row['photo'] ?? '';
    $series = $row['series'] ?? '';
    $now = (int)($row['ts'] ?? time());
    for ($i = count($lines) - 1, $seen = 0; $i >= 0 && $seen < 80; $i--, $seen++) {
        $ev = json_decode($lines[$i], true);
        if (!is_array($ev)) continue;
        if ($now - (int)($ev['ts'] ?? 0) > 10) break;
        if (($ev['type'] ?? '') === $type && ($ev['sid'] ?? '') === $session && ($ev['album'] ?? '') === $album && ($ev['photo'] ?? '') === $photo && ($ev['series'] ?? '') === $series) return true;
    }
    return false;
}

function route_analytics_event(): void {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    if (!analytics_enabled() || is_probable_bot()) { echo '{"ok":true}'; exit; }
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { http_response_code(405); echo '{"ok":false}'; exit; }
    $raw = (string)file_get_contents('php://input');
    if ($raw === '' || strlen($raw) > 12000) { http_response_code(400); echo '{"ok":false}'; exit; }
    $payload = json_decode($raw, true);
    if (!is_array($payload)) { http_response_code(400); echo '{"ok":false}'; exit; }
    $events = isset($payload[0]) ? $payload : [$payload];
    $ok = 0;
    foreach (array_slice($events, 0, 20) as $ev) {
        if (!is_array($ev)) continue;
        $type = (string)($ev['type'] ?? '');
        if (!in_array($type, ['album_view', 'series_view', 'photo_view', 'photo_dwell', 'image_load', 'series_source_click', 'share_click'], true)) continue;
        $vid = analytics_safe_id($ev['vid'] ?? '');
        $sid = analytics_safe_id($ev['sid'] ?? '');
        if ($vid === '' || $sid === '') continue;
        $album = analytics_safe_text($ev['album'] ?? '', 120);
        $photo = analytics_safe_text($ev['photo'] ?? '', 160);
        $series = in_array($ev['series'] ?? '', SERIES_IDS, true) ? (string)$ev['series'] : '';
        if ($album !== '' && !analytics_album_exists($album)) continue;
        if (in_array($type, ['photo_view', 'photo_dwell'], true) && !analytics_photo_exists($album, $photo)) continue;
        $row = [
            'ts' => time(),
            'type' => $type,
            'vid' => $vid,
            'sid' => $sid,
        ];
        if ($album !== '') $row['album'] = $album;
        if ($photo !== '') $row['photo'] = $photo;
        if ($series !== '') $row['series'] = $series;
        if (isset($ev['album_title'])) $row['album_title'] = analytics_safe_text($ev['album_title'], 160);
        if (isset($ev['photo_title'])) $row['photo_title'] = analytics_safe_text($ev['photo_title'], 180);
        if (isset($ev['series_title'])) $row['series_title'] = analytics_safe_text($ev['series_title'], 180);
        if (isset($ev['share_url'])) $row['share_url'] = analytics_safe_path($ev['share_url']);
        if (isset($ev['share_title'])) $row['share_title'] = analytics_safe_text($ev['share_title'], 180);
        if (isset($ev['page_type'])) $row['page_type'] = analytics_safe_text($ev['page_type'], 40);
        if (isset($ev['index'])) $row['idx'] = max(0, min(100000, (int)$ev['index']));
        if (isset($ev['total'])) $row['total'] = max(0, min(100000, (int)$ev['total']));
        if ($type === 'photo_dwell') {
            $dur = max(0, min(ANALYTICS_MAX_DWELL_MS, (int)($ev['duration_ms'] ?? 0)));
            if ($dur < 1000) continue;
            $row['duration_ms'] = $dur;
        }
        if ($type === 'image_load') {
            $dur = max(0, min(120000, (int)($ev['duration_ms'] ?? 0)));
            $success = !empty($ev['success']);
            $img_type = in_array($ev['image_type'] ?? '', ['thumbnail', 'medium', 'full', 'unknown'], true) ? (string)$ev['image_type'] : 'unknown';
            $row['duration_ms'] = $dur;
            $row['success'] = $success;
            $row['image_type'] = $img_type;
            $row['src'] = analytics_safe_path($ev['src'] ?? '');
            if (analytics_write_line('image-loads', $row)) $ok++;
            continue;
        }
        if (analytics_recent_duplicate($row)) { $ok++; continue; }
        if (analytics_write_line('events', $row)) $ok++;
    }
    echo json_encode(['ok' => true, 'written' => $ok]);
    exit;
}

function is_probable_bot(): bool {
    $ua = strtolower((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    return $ua !== '' && (bool)preg_match('/bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|curl|wget|python|httpclient/', $ua);
}

function setting_label_html(string $key, string $de_default, string $en_default): string {
    $s = load_settings();
    $de = trim((string)($s[$key] ?? $de_default)) ?: $de_default;
    $en = trim((string)($s[$key . '_en'] ?? $en_default)) ?: $en_default;
    return bi($de, $en);
}

function album_thumb_dir(string $album): string {
    return IMG_DIR . '/' . $album . '/thumbs';
}

function album_thumb_dir_ar(string $album): string {
    return IMG_DIR . '/' . $album . '/thumbs/ar';
}

function album_large_dir(string $album): string {
    return IMG_DIR . '/' . $album . '/large';
}

function album_order_cache_file(string $album): string {
    return album_thumb_dir_ar($album) . '/.order.json';
}

function ensure_album_cache_dir(string $album, string $kind): bool {
    if ($kind === 'thumb') {
        return repair_generated_cache_dir(album_thumb_dir($album)) && repair_generated_cache_dir(album_thumb_dir_ar($album));
    }
    if ($kind === 'large') {
        return repair_generated_cache_dir(album_large_dir($album));
    }
    return false;
}

function empty_cache_clear_result(): array {
    return ['deleted' => 0, 'deleted_meta' => 0, 'failed' => [], 'missing' => [], 'unreadable' => []];
}

function merge_cache_clear_result(array $a, array $b): array {
    $a['deleted'] = (int)($a['deleted'] ?? 0) + (int)($b['deleted'] ?? 0);
    $a['deleted_meta'] = (int)($a['deleted_meta'] ?? 0) + (int)($b['deleted_meta'] ?? 0);
    foreach (['failed', 'missing', 'unreadable'] as $key) {
        $a[$key] = array_merge($a[$key] ?? [], $b[$key] ?? []);
    }
    return $a;
}

function clear_cache_dir(string $dir): array {
    $result = empty_cache_clear_result();
    if (!is_dir($dir)) {
        $result['missing'][] = $dir;
        return $result;
    }
    $files = @scandir($dir);
    if ($files === false) {
        $result['unreadable'][] = $dir;
        return $result;
    }
    foreach ($files as $f) {
        if ($f === '.' || $f === '..') continue;
        $fp = $dir . '/' . $f;
        if (!is_file($fp)) continue;
        $is_meta = in_array($f, ['.meta.json', '.order.json'], true);
        if (@unlink($fp)) {
            if ($is_meta) $result['deleted_meta']++;
            else $result['deleted']++;
        } else {
            $result['failed'][] = [
                'path' => $fp,
                'metadata_file' => $is_meta,
                'dir_writable' => is_writable($dir),
                'file_writable' => is_writable($fp),
            ];
        }
    }
    return $result;
}

function cache_clear_response(array $result): array {
    $failed = $result['failed'] ?? [];
    $unreadable = $result['unreadable'] ?? [];
    $ok = !$failed && !$unreadable;
    $response = [
        'ok' => $ok,
        'deleted' => (int)($result['deleted'] ?? 0),
        'deleted_meta' => (int)($result['deleted_meta'] ?? 0),
        'failed_count' => count($failed),
        'unreadable_count' => count($unreadable),
        'missing_count' => count($result['missing'] ?? []),
    ];
    if ($ok) return $response;

    $examples = [];
    foreach (array_slice($failed, 0, 5) as $item) {
        $examples[] = [
            'path' => $item['path'] ?? '',
            'metadata_file' => (bool)($item['metadata_file'] ?? false),
            'directory_writable' => (bool)($item['dir_writable'] ?? false),
            'file_writable' => (bool)($item['file_writable'] ?? false),
        ];
    }
    $response['error'] = 'Some generated cache files could not be removed.';
    $response['hint'] = 'Check ownership and write permissions for the album thumbs/ and large/ folders. The web server user must be able to delete files inside those folders.';
    if ($unreadable) $response['unreadable_directories'] = array_slice($unreadable, 0, 5);
    if ($examples) $response['failed_examples'] = $examples;
    return $response;
}

function clear_thumb_cache(string $album): array {
    $result = empty_cache_clear_result();
    foreach ([album_thumb_dir($album), album_thumb_dir_ar($album)] as $dir) {
        $result = merge_cache_clear_result($result, clear_cache_dir($dir));
    }
    return $result;
}

function clear_large_cache(string $album): array {
    return clear_cache_dir(album_large_dir($album));
}

function album_slugs_for_cache_reset(): array {
    if (!is_dir(IMG_DIR)) return [];
    $slugs = [];
    foreach (scandir(IMG_DIR) ?: [] as $name) {
        if ($name[0] === '.' || $name[0] === '_') continue;
        if (!safe_seg($name)) continue;
        if (is_dir(IMG_DIR . '/' . $name)) $slugs[] = $name;
    }
    return $slugs;
}

function delete_album_dir(string $dir): bool {
    $root = realpath(IMG_DIR);
    $target = realpath($dir);
    if (!$root || !$target || !is_dir($target)) return false;
    if (strpos($target, $root . DIRECTORY_SEPARATOR) !== 0) return false;
    $items = scandir($target);
    if ($items === false) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $target . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path) && !is_link($path)) {
            if (!delete_album_dir($path)) return false;
        } else {
            if (!@unlink($path)) return false;
        }
    }
    return @rmdir($target);
}

function remove_album_from_overview_order(string $album): void {
    $cfg = parse_config(IMG_DIR);
    if (empty($cfg['order'])) return;
    $order = array_values(array_filter(array_map('trim', explode(',', (string)$cfg['order'])), fn($slug) => $slug !== $album));
    if ($order) {
        $cfg['order'] = implode(',', $order);
    } else {
        unset($cfg['order']);
    }
    write_config(IMG_DIR, $cfg);
}

function uploaded_images_first_order(array $existing, array $saved): array {
    return array_values(array_unique(array_merge($saved, array_values(array_diff($existing, $saved)))));
}

function promote_album_to_overview_front(string $album): void {
    $cfg = parse_config(IMG_DIR);
    $slugs = array_map(fn(array $al) => $al['slug'], albums());
    $order = array_values(array_unique(array_merge([$album], array_filter($slugs, fn($slug) => $slug !== $album))));
    if ($order) {
        $cfg['order'] = implode(',', $order);
        write_config(IMG_DIR, $cfg);
    }
}

function remove_album_from_series(string $album): void {
    $sdata = load_series();
    $changed = false;
    foreach (SERIES_IDS as $sid) {
        $series = $sdata[$sid] ?? empty_series_record();
        $images = is_array($series['images'] ?? null) ? $series['images'] : [];
        $filtered = array_values(array_filter($images, fn($key) => strpos((string)$key, $album . '/') !== 0));
        if ($filtered !== $images) {
            $series['images'] = $filtered;
            if (isset($series['hero']) && strpos((string)$series['hero'], $album . '/') === 0) {
                unset($series['hero']);
            }
            $sdata[$sid] = $series;
            $changed = true;
        }
    }
    if ($changed) save_series_data($sdata);
}

function base_url(): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = (string)($_SERVER['HTTP_HOST'] ?? 'localhost:3024');
    if (!preg_match('/^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/', $host)) $host = 'localhost:3024';
    $path   = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
    return $scheme . '://' . $host . $path;
}

function origin_url(): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = (string)($_SERVER['HTTP_HOST'] ?? 'localhost:3024');
    if (!preg_match('/^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/', $host)) $host = 'localhost:3024';
    return $scheme . '://' . $host;
}

function public_base_path(): string {
    $script = str_replace('\\', '/', (string)($_SERVER['SCRIPT_NAME'] ?? ''));
    $dir = trim(dirname($script), '/');
    return $dir === '' || $dir === '.' ? '' : '/' . $dir;
}

function public_url(string $path = ''): string {
    $base = public_base_path();
    $home = $base === '' ? '/' : $base . '/';
    if ($path === '' || $path === '/') return $home;
    if ($path[0] === '?') return $home . $path;
    return ($base === '' ? '' : $base) . '/' . ltrim($path, '/');
}

function atomic_write(string $path, string $data, int $mode = 0664): bool {
    $dir = dirname($path);
    if (!is_dir($dir)) {
        if (!ensure_writable_dir($dir)) return false;
    } elseif (!is_writable($dir)) {
        return false;
    }
    $tmp = tempnam($dir, '.lbtmp-');
    if ($tmp === false) return false;
    $ok = @file_put_contents($tmp, $data, LOCK_EX) !== false && @rename($tmp, $path);
    if ($ok) {
        @chmod($path, $mode);
        return true;
    }
    @unlink($tmp);
    return false;
}

function write_config(string $dir, array $cfg): void {
    $path = $dir . '/config.txt';
    $lines = array_map(fn($k, $v) => "$k: $v", array_keys($cfg), $cfg);
    if ($lines) {
        atomic_write($path, implode("\n", $lines) . "\n");
    } elseif (is_file($path)) {
        @unlink($path);
    }
}

function parse_config(string $dir): array {
    $f = $dir . '/config.txt';
    if (!is_file($f)) return [];
    $out = [];
    foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $p = strpos($line, ':');
        if ($p === false || $line[0] === '#') continue;
        $out[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1));
    }
    return $out;
}

function album_captions(string $album): array {
    $cfg = parse_config(IMG_DIR . '/' . $album);
    $raw = $cfg['caption_data'] ?? '';
    if ($raw === '') return [];
    $d = @json_decode($raw, true);
    return is_array($d) ? $d : [];
}

function save_album_caption(string $album, string $file, string $de, string $en): void {
    $cfg = parse_config(IMG_DIR . '/' . $album);
    $caps = [];
    if (isset($cfg['caption_data']) && $cfg['caption_data'] !== '') {
        $d = @json_decode($cfg['caption_data'], true);
        if (is_array($d)) $caps = $d;
    }
    if ($de !== '' || $en !== '') {
        $entry = [];
        if ($de !== '') $entry['caption'] = $de;
        if ($en !== '') $entry['caption_en'] = $en;
        $caps[$file] = $entry;
    } else {
        unset($caps[$file]);
    }
    if ($caps) {
        $cfg['caption_data'] = json_encode($caps, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    } else {
        unset($cfg['caption_data']);
    }
    write_config(IMG_DIR . '/' . $album, $cfg);
}

function caption_pair(string $album, string $file): array {
    $caps = album_captions($album);
    $entry = $caps[$file] ?? [];
    return ['de' => (string)($entry['caption'] ?? ''), 'en' => (string)($entry['caption_en'] ?? '')];
}

function caption_html(string $album, string $file): string {
    $pair = caption_pair($album, $file);
    if ($pair['de'] === '' && $pair['en'] === '') return '';
    return bi($pair['de'], $pair['en']);
}

function caption_editor_html(): void {
    $has_key  = caption_api_key() !== null;
    $ai_attr  = $has_key ? '' : ' disabled title="Add LIGHTBOX_GOOGLE_API_KEY to .env to enable AI captions"';
    $pl       = htmlspecialchars(primary_lang_label());
    $multi    = multilingual_enabled();
    echo '<div id="lb-cap-edit">';
    echo '<button type="button" id="lb-cap-ai"' . $ai_attr . ' onclick="capAI()">&#10024; AI</button>';
    echo '<div id="lb-cap-inputs">';
    if ($multi) {
        echo '<input type="text" id="lb-cap-de" class="cap-in" placeholder="Caption (' . $pl . ')">';
        echo '<input type="text" id="lb-cap-en" class="cap-in" placeholder="Caption (EN)">';
    } else {
        echo '<input type="text" id="lb-cap-en" class="cap-in" placeholder="Caption">';
    }
    echo '</div>';
    echo '<button type="button" id="lb-cap-save" disabled onclick="capSave()">Save</button>';
    if (!$has_key) {
        echo '<span class="cap-no-key">Add <code>LIGHTBOX_GOOGLE_API_KEY</code> to <code>.env</code> for AI captions</span>';
    }
    echo '</div>';
}

function caption_editor_js(): void {
    echo <<<'JS'
function capCheckDirty(){
  var btn=document.getElementById('lb-cap-save');if(!btn)return;
  var deEl=document.getElementById('lb-cap-de'),enEl=document.getElementById('lb-cap-en');
  var saved=window.CAPTIONS_DATA&&CAPTIONS_DATA[cur]||{de:'',en:''};
  var de=deEl?deEl.value.trim():'',en=enEl?enEl.value.trim():'';
  btn.disabled=(de===(saved.de||'')&&en===(saved.en||''));
}
function capLoadForImage(i){
  var deEl=document.getElementById('lb-cap-de'),enEl=document.getElementById('lb-cap-en');
  var data=window.CAPTIONS_DATA&&CAPTIONS_DATA[i]||{de:'',en:''};
  if(deEl)deEl.value=data.de||'';
  if(enEl)enEl.value=data.en||'';
  capCheckDirty();
}
function capAI(){
  var file=FILES[cur];if(!file)return;
  var album=window.ALBUMS?ALBUMS[cur]:ALBUM;
  var btn=document.getElementById('lb-cap-ai');
  var orig=btn.textContent;
  btn.disabled=true;btn.textContent='…';
  fetch('?ai_caption=1&a='+encodeURIComponent(album)+'&f='+encodeURIComponent(file),{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'csrf='+encodeURIComponent(CTX_CSRF)
  }).then(function(r){return r.json();}).then(function(d){
    if(d.ok===false){
      showSeriesToast(d.error==='no_api_key'?'Add a Google AI API key to .env':d.error||'AI caption failed');
      return;
    }
    var deEl=document.getElementById('lb-cap-de'),enEl=document.getElementById('lb-cap-en');
    if(deEl&&d.de)deEl.value=d.de;
    if(enEl&&d.en)enEl.value=d.en;
    else if(enEl&&!document.getElementById('lb-cap-de')&&d.en)enEl.value=d.en;
    capCheckDirty();
    showSeriesToast('caption generated');
  }).catch(function(){showSeriesToast('AI caption failed');})
  .finally(function(){btn.disabled=false;btn.textContent=orig;});
}
function capSave(){
  var file=FILES[cur];if(!file)return;
  var album=window.ALBUMS?ALBUMS[cur]:ALBUM;
  var btn=document.getElementById('lb-cap-save');
  var deEl=document.getElementById('lb-cap-de'),enEl=document.getElementById('lb-cap-en');
  var de=deEl?deEl.value.trim():'',en=enEl?enEl.value.trim():'';
  btn.disabled=true;
  fetch('?save_caption=1&a='+encodeURIComponent(album)+'&f='+encodeURIComponent(file),{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'caption='+encodeURIComponent(de)+'&caption_en='+encodeURIComponent(en)+'&csrf='+encodeURIComponent(CTX_CSRF)
  }).then(function(r){
    if(r.ok){
      if(window.CAPTIONS_DATA)CAPTIONS_DATA[cur]={de:de,en:en};
      showSeriesToast('caption saved');
    }else{showSeriesToast('save failed');}
  })
  .catch(function(){showSeriesToast('save failed');})
  .finally(function(){capCheckDirty();});
}
['lb-cap-de','lb-cap-en'].forEach(function(id){var el=document.getElementById(id);if(el)el.addEventListener('input',capCheckDirty);});
JS;
}

function default_album_name(string $slug): string {
    $name = trim((string)preg_replace('/[\s._-]+/', ' ', $slug));
    return $name === '' ? $slug : ucwords(strtolower($name));
}

function images_in(string $album): array {
    $dir        = IMG_DIR . '/' . $album;
    if (!is_dir($dir)) return [];

    $cfg_file   = $dir . '/config.txt';
    $cache_file = album_order_cache_file($album);
    $cache_key  = (int)@filemtime($dir) . ':' . (int)@filemtime($cfg_file);

    if (is_file($cache_file)) {
        $c = @json_decode((string)file_get_contents($cache_file), true);
        if (is_array($c) && ($c['key'] ?? '') === $cache_key) return $c['files'];
    }

    $all = [];
    foreach (scandir($dir) ?: [] as $f) {
        if ($f[0] === '.' || $f[0] === '_') continue;
        if (!source_image_allowed($f)) continue;
        $all[$f] = $f;
    }

    $cfg = parse_config($dir);
    if (($cfg['order'] ?? '') !== '') {
        $custom = array_map('trim', explode(',', $cfg['order']));
        $names  = [];
        foreach ($custom as $f) {
            if (isset($all[$f])) { $names[] = $f; unset($all[$f]); }
        }
        $names = array_merge($names, array_keys($all));
    } else {
        $files = [];
        foreach ($all as $f) {
            $ts = 0;
            if (preg_match('/\.jpe?g$/i', $f)) {
                $ts = jpeg_datetime_original_ts($dir . '/' . $f);
            }
            $files[] = ['name' => $f, 'ts' => $ts];
        }
        usort($files, function (array $a, array $b): int {
            if ($a['ts'] && $b['ts']) return $a['ts'] <=> $b['ts'];
            if ($a['ts']) return -1;
            if ($b['ts']) return 1;
            return strcasecmp($a['name'], $b['name']);
        });
        $names = array_column($files, 'name');
    }

    if (ensure_writable_dir(album_thumb_dir_ar($album))) {
        @file_put_contents($cache_file, json_encode(['key' => $cache_key, 'files' => $names]));
        @chmod($cache_file, 0664);
    }
    return $names;
}

function resolve_hero(string $album, array $cfg, array $imgs): string {
    $needle = $cfg['hero'] ?? '';
    if ($needle !== '') {
        $sorted = $imgs;
        usort($sorted, 'strcasecmp');
        foreach ($sorted as $img) {
            if (stripos($img, $needle) !== false) return $img;
        }
    }
    $sorted = $imgs;
    usort($sorted, 'strcasecmp');
    return $sorted[0];
}

function dir_birthtime(string $path): int {
    $out = [];
    if (PHP_OS_FAMILY === 'Darwin') {
        @exec('stat -f %B ' . escapeshellarg($path), $out);
    } else {
        @exec('stat --format %W ' . escapeshellarg($path), $out);
    }
    $t = isset($out[0]) ? (int)$out[0] : 0;
    return $t > 0 ? $t : (int)filemtime($path);
}

function albums(): array {
    if (!is_dir(IMG_DIR)) return [];
    $root_cfg     = parse_config(IMG_DIR);
    $custom_order = ($root_cfg['order'] ?? '') !== ''
        ? array_map('trim', explode(',', $root_cfg['order'])) : null;

    $out = [];
    foreach (scandir(IMG_DIR) ?: [] as $name) {
        if ($name[0] === '.' || $name[0] === '_') continue;
        $path = IMG_DIR . '/' . $name;
        if (!is_dir($path)) continue;
        $cfg  = parse_config($path);
        $imgs = images_in($name);
        if (!$imgs) continue;
        $out[] = [
            'slug'    => $name,
            'name'    => $cfg['name'] ?? default_album_name($name),
            'name_en' => $cfg['name_en'] ?? '',
            'hero'    => resolve_hero($name, $cfg, $imgs),
            'count'   => count($imgs),
            'btime'   => dir_birthtime($path),
            'hidden'  => ($cfg['hidden'] ?? '') === '1',
        ];
    }

    if ($custom_order !== null) {
        $by_slug = array_column($out, null, 'slug');
        $ordered = [];
        foreach ($custom_order as $slug) {
            if (isset($by_slug[$slug])) { $ordered[] = $by_slug[$slug]; unset($by_slug[$slug]); }
        }
        return array_merge($ordered, array_values($by_slug));
    }

    usort($out, fn(array $a, array $b) =>
        $b['btime'] !== $a['btime'] ? $b['btime'] <=> $a['btime'] : strcasecmp($a['slug'], $b['slug'])
    );
    return $out;
}

function thumb_url_ar(string $album, string $file): string {
    $url = '_lb/thumb/' . path_url_encode($album) . '/' . path_url_encode($file);
    $src = source_image_path($album, $file);
    if (is_file($src)) $url .= '?v=' . derivative_url_version(thumb_cache_key($src));
    return public_url($url);
}

function image_url(string $album, string $file): string {
    $url = '_lb/large/' . path_url_encode($album) . '/' . path_url_encode($file);
    $src = source_image_path($album, $file);
    if (is_file($src)) $url .= '?v=' . derivative_url_version(large_cache_key($src));
    return public_url($url);
}

function album_url(string $album, ?string $lang = null): string {
    if (clean_urls_enabled()) return public_url(lang_path_prefix($lang) . 'album/' . path_url_encode(album_seo_slug($album, $lang)));
    return public_url('?a=' . urlencode($album));
}

function add_url_param(string $url, string $key, string $value): string {
    $sep = strpos($url, '?') === false ? '?' : '&';
    return $url . $sep . urlencode($key) . '=' . urlencode($value);
}

function image_clean_url(string $album, string $file, ?string $lang = null): string {
    return public_url(lang_path_prefix($lang) . 'album/' . path_url_encode(album_seo_slug($album, $lang)) . '/photo/' . path_url_encode(photo_seo_slug($album, $file)));
}

function og_image_url(string $album, string $file): string {
    return absolute_url(public_url('_lb/og/' . path_url_encode($album) . '/' . path_url_encode($file)));
}

function canonical_album_url(string $album): string {
    return absolute_url(album_url($album));
}

function canonical_image_url(string $album, string $file): string {
    $lang = current_lang_param();
    if (clean_urls_enabled()) {
        return absolute_url(image_clean_url($album, $file));
    }
    return absolute_url(public_url('?a=' . urlencode($album) . '&share_image=' . urlencode($file) . $lang));
}

function absolute_url(string $url): string {
    if (preg_match('/^https?:\/\//i', $url)) return $url;
    if (isset($url[0]) && $url[0] === '/') return origin_url() . $url;
    return rtrim(base_url(), '/') . '/' . ltrim($url, './');
}

function thumb_path(string $album, string $file): string {
    return album_thumb_dir_ar($album) . '/' . pathinfo($file, PATHINFO_FILENAME) . '.jpg';
}

function large_path(string $album, string $file): string {
    return album_large_dir($album) . '/' . pathinfo($file, PATHINFO_FILENAME) . '.jpg';
}

function source_image_path(string $album, string $file): string {
    return IMG_DIR . '/' . $album . '/' . $file;
}

function source_image_allowed(string $file): bool {
    return (bool)preg_match('/\.(jpe?g|png|webp)$/i', $file);
}

function source_cache_key(string $src): string {
    return (int)filemtime($src) . ':' . (int)filesize($src);
}

function thumb_cache_key(string $src): string {
    return 'thumb-ar-v2:' . THUMB_AR_MAX . ':' . thumb_quality() . ':' . source_cache_key($src);
}

function large_cache_key(string $src): string {
    return 'large-v1:' . display_long_edge() . ':' . display_quality() . ':' . source_cache_key($src);
}

function derivative_url_version(string $key): string {
    return substr(sha1($key), 0, 10);
}

function derivative_meta_cache(string $dir, ?array $set = null): array {
    static $cache = [];
    if ($set !== null) {
        $cache[$dir] = $set;
        return $cache[$dir];
    }
    if (array_key_exists($dir, $cache)) return $cache[$dir];
    $path = $dir . '/.meta.json';
    if (!is_file($path)) return $cache[$dir] = [];
    $data = @json_decode((string)file_get_contents($path), true);
    return $cache[$dir] = is_array($data) ? $data : [];
}

function read_derivative_meta(string $dir): array {
    return derivative_meta_cache($dir);
}

function mark_derivative_current(string $dst, string $key): void {
    $dir = dirname($dst);
    if (!ensure_writable_dir($dir)) return;
    $path = $dir . '/.meta.json';
    $fp = @fopen($path, 'c+');
    if (!$fp) return;

    $meta = [];
    if (@flock($fp, LOCK_EX)) {
        rewind($fp);
        $raw = stream_get_contents($fp);
        $data = @json_decode(is_string($raw) ? $raw : '', true);
        if (is_array($data)) $meta = $data;
        $meta[basename($dst)] = $key;
        rewind($fp);
        ftruncate($fp, 0);
        fwrite($fp, json_encode($meta, JSON_PRETTY_PRINT));
        fflush($fp);
        @flock($fp, LOCK_UN);
        @chmod($path, 0664);
        derivative_meta_cache($dir, $meta);
    }
    fclose($fp);
}

function jpeg_datetime_original_ts(string $src): int {
    $exif = @exif_read_data($src, 'EXIF', true, false);
    $dt = is_array($exif) ? (string)($exif['EXIF']['DateTimeOriginal'] ?? '') : '';
    if ($dt === '') return 0;
    return (int)@strtotime(substr($dt, 0, 4) . '-' . substr($dt, 5, 2) . '-' . substr($dt, 8, 2) . ' ' . substr($dt, 11));
}

function jpeg_orientation(string $src): int {
    $exif = @exif_read_data($src, 'IFD0', true, false);
    return is_array($exif) ? (int)($exif['IFD0']['Orientation'] ?? 1) : 1;
}

function derivative_current(string $src, string $dst, string $key, bool $allow_legacy = false): bool {
    if (!is_file($dst) || filemtime($dst) < filemtime($src)) return false;
    $meta = read_derivative_meta(dirname($dst));
    $name = basename($dst);
    if (isset($meta[$name])) return $meta[$name] === $key;
    if ($allow_legacy) {
        mark_derivative_current($dst, $key);
        return true;
    }
    return false;
}

function thumb_current(string $album, string $file): bool {
    $src = source_image_path($album, $file);
    if (!is_file($src)) return false;
    return derivative_current($src, thumb_path($album, $file), thumb_cache_key($src), thumb_allows_legacy());
}

function ensure_large_image(string $album, string $file): bool {
    if (!source_image_allowed($file)) return false;
    $src = source_image_path($album, $file);
    if (!is_file($src)) return false;
    $dst = large_path($album, $file);
    $key = large_cache_key($src);
    if (!derivative_current($src, $dst, $key)) {
        if (!make_display_image($src, $dst, display_long_edge(), display_quality())) return false;
        mark_derivative_current($dst, $key);
    }
    return true;
}

function route_gen_thumbs(string $album): void {
    set_time_limit(60);
    ini_set('memory_limit', '256M');
    $json_headers = function (): void {
        header('Content-Type: application/json');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
    };
    $limit = clamp_int($_GET['limit'] ?? 6, 1, 12);
    $cursor = max(0, (int)($_GET['cursor'] ?? 0));
    $single_file = isset($_GET['f']) ? safe_seg((string)$_GET['f']) : null;
    if ($single_file !== null) {
        if (!source_image_allowed($single_file) || !is_file(source_image_path($album, $single_file))) { http_response_code(404); exit; }
        $src = source_image_path($album, $single_file);
        $dst = thumb_path($album, $single_file);
        $key = thumb_cache_key($src);
        if (!derivative_current($src, $dst, $key, thumb_allows_legacy())) {
            if (make_thumb_ar($src, $dst, THUMB_AR_MAX, thumb_quality())) {
                mark_derivative_current($dst, $key);
            }
        }
        $json_headers();
        echo json_encode([
            'ok' => thumb_current($album, $single_file),
            'generated' => thumb_current($album, $single_file) ? [$single_file] : [],
            'remaining' => 0,
            'next_cursor' => 0,
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $imgs = images_in($album);
    $tdar = album_thumb_dir_ar($album);
    $generated = [];
    $next_cursor = 0;
    $count = count($imgs);
    for ($idx = min($cursor, $count); $idx < $count; $idx++) {
        $img = $imgs[$idx];
        $stem = pathinfo($img, PATHINFO_FILENAME);
        $src  = source_image_path($album, $img);
        $dstar = $tdar . '/' . $stem . '.jpg';
        $key = thumb_cache_key($src);
        if (derivative_current($src, $dstar, $key, thumb_allows_legacy())) continue;
        if (make_thumb_ar($src, $dstar, THUMB_AR_MAX, thumb_quality())) {
            mark_derivative_current($dstar, $key);
            $generated[] = $img;
        }
        if (count($generated) >= $limit) {
            $next_cursor = $idx + 1;
            break;
        }
    }
    $remaining = 0;
    foreach ($imgs as $img) {
        if (!thumb_current($album, $img)) $remaining++;
    }
    $json_headers();
    echo json_encode([
        'ok' => true,
        'generated' => $generated,
        'remaining' => $remaining,
        'next_cursor' => $remaining > 0 ? ($next_cursor >= $count ? 0 : $next_cursor) : 0,
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

function route_gen_large(string $album): void {
    set_time_limit(60);
    ini_set('memory_limit', '512M');
    $json_headers = function (): void {
        header('Content-Type: application/json');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
    };
    $file = isset($_GET['f']) ? safe_seg((string)$_GET['f']) : null;
    if ($file !== null) {
        if (!source_image_allowed($file) || !is_file(source_image_path($album, $file))) { http_response_code(404); exit; }
        $json_headers();
        echo json_encode(['ok' => ensure_large_image($album, $file), 'generated' => [$file], 'remaining' => 0, 'next_cursor' => 0], JSON_UNESCAPED_SLASHES);
        exit;
    }
    $limit = clamp_int($_GET['limit'] ?? 3, 1, 6);
    $cursor = max(0, (int)($_GET['cursor'] ?? 0));
    $imgs = images_in($album);
    $count = count($imgs);
    $generated = [];
    $next_cursor = 0;
    ensure_album_cache_dir($album, 'large');
    for ($idx = min($cursor, $count); $idx < $count; $idx++) {
        $img = $imgs[$idx];
        $src = source_image_path($album, $img);
        $dst = large_path($album, $img);
        $key = large_cache_key($src);
        if (derivative_current($src, $dst, $key)) continue;
        if (ensure_large_image($album, $img)) {
            $generated[] = $img;
        }
        if (count($generated) >= $limit) {
            $next_cursor = $idx + 1;
            break;
        }
    }
    $remaining = 0;
    foreach ($imgs as $img) {
        $src = source_image_path($album, $img);
        $dst = large_path($album, $img);
        $key = large_cache_key($src);
        if (!derivative_current($src, $dst, $key)) $remaining++;
    }
    $json_headers();
    echo json_encode([
        'ok' => true,
        'generated' => $generated,
        'remaining' => $remaining,
        'next_cursor' => $remaining > 0 ? ($next_cursor >= $count ? 0 : $next_cursor) : 0,
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── image serving ───────────────────────────────────────────────────────────

function serve_thumb_ar(string $album, string $file): void {
    if (!source_image_allowed($file)) { http_response_code(404); exit; }
    $src = source_image_path($album, $file);
    if (!is_file($src)) { http_response_code(404); exit; }
    $dst = thumb_path($album, $file);
    $key = thumb_cache_key($src);
    if (!derivative_current($src, $dst, $key, thumb_allows_legacy())) {
        ini_set('memory_limit', '256M');
        ensure_album_cache_dir($album, 'thumb');
        if (!make_thumb_ar($src, $dst, THUMB_AR_MAX, thumb_quality())) {
            if (serve_uncached_resized_jpeg($src, THUMB_AR_MAX, thumb_quality(), true, 'thumbnail')) exit;
            cache_error_response('thumbnail', $album);
        }
        mark_derivative_current($dst, $key);
    }
    serve_static($dst, 'image/jpeg');
}

function serve_image(string $album, string $file): void {
    ini_set('memory_limit', '512M');
    if (!source_image_allowed($file)) { http_response_code(404); exit; }
    $src = source_image_path($album, $file);
    if (!is_file($src)) { http_response_code(404); exit; }
    ensure_album_cache_dir($album, 'large');
    if (!ensure_large_image($album, $file)) {
        if (serve_uncached_resized_jpeg($src, display_long_edge(), display_quality(), false, 'large display image')) exit;
        cache_error_response('large display image', $album);
    }
    serve_static(large_path($album, $file), 'image/jpeg');
}

function serve_og_image(string $album, string $file): void {
    serve_thumb_ar($album, $file);
}

function serve_static(string $path, string $mime): void {
    $mtime = (int)filemtime($path);
    $size  = (int)filesize($path);
    $etag  = '"' . dechex($mtime) . '-' . dechex($size) . '"';
    if (($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $etag) {
        http_response_code(304); exit;
    }
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . $size);
    header('ETag: ' . $etag);
    header('Cache-Control: public, max-age=31536000, immutable');
    header_remove('Expires');
    header_remove('Pragma');
    readfile($path);
}

function make_thumb_ar(string $src, string $dst, int $max = THUMB_AR_MAX, int $quality = DEFAULT_THUMB_QUALITY): bool {
    return make_resized_jpeg($src, $dst, $max, $quality, true);
}

function make_display_image(string $src, string $dst, int $max, int $quality): bool {
    return make_resized_jpeg($src, $dst, $max, $quality, false);
}

function resized_jpeg_resource(string $src, int $max, bool $allow_upscale) {
    $loaded = load_gd_source($src);
    if (!$loaded) return false;
    [$img, $w, $h] = $loaded;

    $scale = $max / max($w, $h);
    if (!$allow_upscale) $scale = min(1, $scale);
    $nw = max(1, (int)round($w * $scale));
    $nh = max(1, (int)round($h * $scale));

    $out = imagecreatetruecolor($nw, $nh);
    if (!$out) {
        gd_destroy($img);
        return false;
    }
    $bg = imagecolorallocate($out, 0, 0, 0);
    imagefilledrectangle($out, 0, 0, $nw, $nh, $bg);
    imagecopyresampled($out, $img, 0, 0, 0, 0, $nw, $nh, $w, $h);
    gd_destroy($img);
    imageinterlace($out, PHP_VERSION_ID >= 80500 ? true : 1);
    return $out;
}

function make_resized_jpeg(string $src, string $dst, int $max, int $quality, bool $allow_upscale): bool {
    $out = resized_jpeg_resource($src, $max, $allow_upscale);
    if (!$out) return false;
    if (!ensure_writable_dir(dirname($dst))) {
        gd_destroy($out);
        error_log('Lightbox: cache directory unavailable for ' . $dst);
        return false;
    }
    $ok = imagejpeg($out, $dst, clamp_int($quality, 40, 100));
    gd_destroy($out);
    if ($ok) {
        @chmod($dst, 0664);
    } else {
        error_log('Lightbox: could not write generated image: ' . $dst);
    }
    return $ok;
}

function serve_uncached_resized_jpeg(string $src, int $max, int $quality, bool $allow_upscale, string $kind): bool {
    $out = resized_jpeg_resource($src, $max, $allow_upscale);
    if (!$out) return false;
    header('Content-Type: image/jpeg');
    header('Cache-Control: no-store');
    header('X-Lightbox-Cache: bypass');
    header('X-Lightbox-Cache-Reason: write-failed');
    error_log('Lightbox: serving uncached ' . $kind . ' because cache write failed for source: ' . $src);
    $ok = imagejpeg($out, null, clamp_int($quality, 40, 100));
    gd_destroy($out);
    return $ok;
}

function gd_destroy($img): void {
    if (PHP_VERSION_ID < 80000 && is_resource($img)) {
        @imagedestroy($img);
    }
}

function load_gd_source(string $src): ?array {
    $info = @getimagesize($src);
    if (!$info) return null;
    [$w, $h, , $mime_str] = [$info[0], $info[1], $info[2], $info['mime']];

    if ($mime_str === 'image/jpeg')      $img = @imagecreatefromjpeg($src);
    elseif ($mime_str === 'image/png')   $img = @imagecreatefrompng($src);
    elseif ($mime_str === 'image/webp')  $img = @imagecreatefromwebp($src);
    else                                 $img = false;
    if (!$img) return null;

    if ($mime_str === 'image/jpeg') {
        $orient = jpeg_orientation($src);
        if ($orient > 1) {
            $oriented = orient_image($img, $orient);
            if (!$oriented) {
                gd_destroy($img);
                return null;
            }
            if ($oriented !== $img) gd_destroy($img);
            $img = $oriented;
            if ($orient >= 5) [$w, $h] = [$h, $w];
        }
    }

    return [$img, $w, $h];
}

function orient_image($img, int $orient) {
    switch ($orient) {
        case 2: imageflip($img, IMG_FLIP_HORIZONTAL);            return $img;
        case 3: return imagerotate($img, 180, 0);
        case 4: imageflip($img, IMG_FLIP_VERTICAL);              return $img;
        case 5: imageflip($img, IMG_FLIP_VERTICAL);              return imagerotate($img, -90, 0);
        case 6:                                                  return imagerotate($img, -90, 0);
        case 7: imageflip($img, IMG_FLIP_HORIZONTAL);            return imagerotate($img, -90, 0);
        case 8:                                                  return imagerotate($img, 90, 0);
        default:                                                 return $img;
    }
}

// ─── sitemap ─────────────────────────────────────────────────────────────────

function sitemap(): void {
    header('Content-Type: application/xml; charset=utf-8');
    $base = base_url();
    $langs = (clean_urls_enabled() && multilingual_enabled()) ? public_langs() : [null];
    echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
    echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";
    xml_url($base . '/');
    if (clean_urls_enabled() && multilingual_enabled()) {
        foreach ($langs as $lang) xml_url(absolute_url(public_url(lang_path_prefix($lang))));
        foreach ($langs as $lang) xml_url(absolute_url(all_photos_url($lang)));
    }
    foreach (albums() as $al) {
        if (!is_admin() && ($al['hidden'] ?? false)) continue;
        foreach ($langs as $lang) {
            xml_url($lang === null ? canonical_album_url($al['slug']) : absolute_url(album_url($al['slug'], $lang)));
            foreach (images_in($al['slug']) as $img) {
                xml_url($lang === null ? canonical_image_url($al['slug'], $img) : absolute_url(image_clean_url($al['slug'], $img, $lang)));
            }
        }
    }
    $sdata = load_series();
    foreach (SERIES_IDS as $sid) {
        $series = $sdata[$sid] ?? empty_series_record();
        if (($series['hidden'] ?? false) || !series_title_value($series, '') || !series_valid_images($series, false)) continue;
        foreach ($langs as $lang) xml_url(absolute_url(series_url($sid, $lang)));
    }
    echo '</urlset>';
}

function xml_url(string $url): void {
    echo '<url><loc>' . htmlspecialchars($url, ENT_XML1) . '</loc></url>' . "\n";
}

function description_with_ellipsis(string $desc): string {
    $desc = trim(preg_replace('/\s+/', ' ', $desc) ?? $desc);
    if ($desc === '') return '...';
    if (substr($desc, -3) === '...') return $desc;
    return rtrim($desc, ". \t\n\r\0\x0B") . '...';
}

function meta_description(string $desc, string $fallback = DEFAULT_SITE_DESC): string {
    $desc = trim(strip_tags($desc));
    $desc = trim(preg_replace('/\s+/', ' ', $desc) ?? $desc);
    if ($desc === '') $desc = $fallback;
    if (strlen($desc) > 220) $desc = rtrim(substr($desc, 0, 217), " \t\n\r\0\x0B.,;") . '...';
    return $desc;
}

// ─── HTML layout ─────────────────────────────────────────────────────────────

function html_head(string $title, string $desc, string $og_image = '', string $canonical = '', array $meta = []): void {
    $base = base_url();
    if (!$canonical) $canonical = $base . '/' . $_SERVER['REQUEST_URI'];
    $og_image = $og_image ? absolute_url($og_image) : ($base . '/');
    $desc = meta_description($desc);
    $og_desc = description_with_ellipsis($desc);
    $site_name = site_title_text();
    $og_type = $meta['og_type'] ?? 'website';
    $og_image_type = $meta['og_image_type'] ?? 'image/jpeg';
    $og_locale = html_lang_attr() === 'en' ? 'en_US' : 'de_DE';
    ?>
<!DOCTYPE html>
<html lang="<?= html_lang_attr() ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= htmlspecialchars($title) ?></title>
<meta name="description" content="<?= htmlspecialchars($desc) ?>">
<link rel="canonical" href="<?= htmlspecialchars($canonical) ?>">
<?php if (clean_urls_enabled() && multilingual_enabled()): ?>
<link rel="alternate" hreflang="de" href="<?= htmlspecialchars(absolute_url(lang_url('de'))) ?>">
<link rel="alternate" hreflang="en" href="<?= htmlspecialchars(absolute_url(lang_url('en'))) ?>">
<link rel="alternate" hreflang="x-default" href="<?= htmlspecialchars(absolute_url(lang_url('en'))) ?>">
<?php endif ?>
<!-- OpenGraph -->
<meta property="og:type" content="<?= htmlspecialchars($og_type) ?>">
<meta property="og:site_name" content="<?= htmlspecialchars($site_name) ?>">
<meta property="og:locale" content="<?= htmlspecialchars($og_locale) ?>">
<meta property="og:title" content="<?= htmlspecialchars($title) ?>">
<meta property="og:description" content="<?= htmlspecialchars($og_desc) ?>">
<meta property="og:image" content="<?= htmlspecialchars($og_image) ?>">
<meta property="og:image:secure_url" content="<?= htmlspecialchars($og_image) ?>">
<meta property="og:image:type" content="<?= htmlspecialchars($og_image_type) ?>">
<meta property="og:url" content="<?= htmlspecialchars($canonical) ?>">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="<?= htmlspecialchars($title) ?>">
<meta name="twitter:description" content="<?= htmlspecialchars($og_desc) ?>">
<meta name="twitter:image" content="<?= htmlspecialchars($og_image) ?>">
<!-- Fonts -->
<style>
@font-face{font-family:'Montserrat';font-style:normal;font-weight:400 700;font-display:swap;src:url('<?= htmlspecialchars(public_url('fonts/montserrat-latin-ext.woff2')) ?>') format('woff2');unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}
@font-face{font-family:'Montserrat';font-style:normal;font-weight:400 700;font-display:swap;src:url('<?= htmlspecialchars(public_url('fonts/montserrat-latin.woff2')) ?>') format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
</style>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{background:#000;color:#fff;font-family:'Montserrat',sans-serif;text-transform:uppercase;letter-spacing:.05em;min-height:100%}
body{opacity:0;animation:pgIn .15s ease forwards}
body.lb-lock{position:fixed;width:100%;overflow-y:scroll}
@keyframes pgIn{to{opacity:1}}
a{color:inherit;text-decoration:none}
/* grid */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:0;padding:0}
@media(max-width:520px){#overview-grid{grid-template-columns:repeat(2,1fr)}}
#series-main,.series-strip{--series-tile-size:var(--series-desktop-tile-size);--series-row-width:var(--series-desktop-few-width);display:flex;flex-wrap:wrap;justify-content:center;align-items:flex-start;width:var(--series-row-width);max-width:100%;padding-left:0;padding-right:0}
#series-main.series-count-many,.series-strip.series-count-many{--series-row-width:var(--series-desktop-many-width)}
#series-main .tile,.series-strip .tile{width:var(--series-tile-size);height:var(--series-tile-size);aspect-ratio:auto}
#series-main .tile>img,.series-strip .tile>img{position:absolute;inset:0;width:100%;height:100%;max-width:none;object-fit:cover}
.series-strip.series-strip{padding-left:0;padding-right:0}
.series-strip--all .tile{width:var(--series-tile-size);height:var(--series-tile-size)}
@media(max-width:520px){#series-main,.series-strip,#series-main.series-count-many,.series-strip.series-count-many{--series-tile-size:var(--series-mobile-tile-size);--series-row-width:var(--series-mobile-row-width)}.all-photos-link-wrap{padding-top:.35rem!important}}
#series-home-wrap{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center}
#series-home-wrap #series-main{max-width:100%}
body.page-home{display:flex;flex-direction:column;min-height:100vh}
#overview-nav{justify-content:center;position:relative}
#overview-nav .lang-switch{position:absolute;right:16px;margin-left:0}
.series-strip{margin-bottom:1.5rem}
.overview-section-title{padding:1.4rem 24px .75rem;font-size:.68rem;font-weight:700;letter-spacing:.16em;opacity:.55;text-align:center}
.overview-section-title a{display:inline-flex;align-items:center;font-size:.62rem;font-weight:400;letter-spacing:.08em;text-transform:none;margin-left:.55em;vertical-align:.08em;text-decoration:underline;text-decoration-color:#888;text-decoration-thickness:1px;text-underline-offset:.16em}
.lang-switch{display:flex;gap:8px;font-size:.6rem;letter-spacing:.12em;font-family:inherit;margin-left:auto}
.lang-switch a{opacity:.35;transition:opacity .2s;text-decoration:none;color:inherit}
.lang-switch a.ls-on{opacity:1}
.lang-switch a:hover{opacity:.75}
.nav-tools{position:absolute;right:24px;top:50%;transform:translateY(-50%);display:flex;flex-direction:column;align-items:flex-end;gap:4px}
#overview-nav .nav-tools{right:16px}
.nav-tools .lang-switch{position:static!important;transform:none!important;margin-left:0}
.share-link{background:none;border:none;color:inherit;cursor:pointer;font:inherit;font-size:.6rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;opacity:.45;padding:0}
.share-link:hover{opacity:.8}
.lang-de .t-en{display:none!important}
.lang-en .t-de{display:none!important}
.tile{position:relative;aspect-ratio:1;overflow:hidden;display:block;cursor:pointer;border:none;padding:0;margin:0;background:none;border-radius:0}
.tile::before{content:'...';position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:.75rem;font-weight:440;letter-spacing:.25em;opacity:0;pointer-events:none;transition:opacity .3s;z-index:2}
.tile.thumb-pending::before{animation:thumbDots 1.1s ease-in-out infinite}
@keyframes thumbDots{0%,100%{opacity:.45;transform:translate(-50%,-50%) scale(.98)}50%{opacity:.9;transform:translate(-50%,-50%) scale(1.04)}}
.tile img{width:100%;height:100%;object-fit:cover;display:block;transition:transform .4s ease}
#gallery .tile img{position:relative;z-index:1;opacity:0;object-fit:contain;transition:opacity .3s,transform .4s ease}
#gallery .tile.loaded img{opacity:1}
img{pointer-events:none;-webkit-user-drag:none}
body.is-admin img{pointer-events:auto}
@media(hover:hover){.tile:hover img{transform:scale(1.05)}#series-gallery .tile:hover img{transform:none}}
.tile:active img{opacity:.6;transform:scale(1)}
/* album label */
.tile-label{position:absolute;bottom:0;left:0;right:0;padding:8px 10px 10px;background:linear-gradient(transparent,rgba(0,0,0,.75));font-size:.85rem;font-weight:700;letter-spacing:.1em}
/* nav */
.nav{display:flex;align-items:center;justify-content:center;gap:16px;padding:0 24px;min-height:60px;font-size:.75rem;font-weight:700;letter-spacing:.13em;position:relative;text-align:center}
.nav a:hover{opacity:.6}
.nav-sep{opacity:.3}
.nav .lang-switch{position:absolute;right:24px;top:50%;transform:translateY(-50%);margin-left:0}
@media(max-width:700px){body.has-float-back #page-nav{min-height:112px;padding-top:62px;align-items:flex-start}body.has-float-back #page-nav .nav-back{max-width:100%;justify-content:center}body.has-float-back #page-nav .nav-title{overflow-wrap:anywhere}body.has-float-back #page-nav .nav-tools{top:22px;transform:none}}
@media(max-width:520px){#page-nav{background:#000}.nav{padding-left:56px;padding-right:56px}.nav-sep{display:none}.nav-album{display:none}#page-nav.lb-hidden{display:none}.nav .nav-tools{right:12px;gap:8px}}
.float-back{position:fixed;top:14px;left:14px;width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.72);color:#fff;box-shadow:0 2px 14px rgba(0,0,0,.25);opacity:.58;visibility:visible;pointer-events:auto;transition:opacity .22s ease,visibility .22s ease;z-index:450}
.float-back svg{display:block;width:18px;height:18px}
.float-back:hover{opacity:1}
body.lb-lock .float-back{opacity:0;visibility:hidden;pointer-events:none}
/* lightbox */
#lb{display:flex;position:fixed;inset:0;background:#000;z-index:1000;opacity:0;visibility:hidden;transition:opacity .2s,visibility .2s}
#lb.open{opacity:1;visibility:visible}
#lb img{width:100vw;height:100vh;object-fit:contain;user-select:none;display:block;transition:opacity .25s;touch-action:manipulation}
#lb img.lb-hi-fade{position:fixed;inset:0;width:100vw;height:100vh;max-width:none;max-height:none;object-fit:contain;opacity:0;z-index:0;pointer-events:none}
#lb.zoomed img{position:fixed;left:0;top:0;width:auto;height:auto;max-width:none;max-height:none;object-fit:fill;cursor:grab;touch-action:none}
#lb.zoomed img.is-panning{cursor:grabbing}
#lb-prev,#lb-next{position:fixed;top:0;bottom:0;width:64px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:2rem;color:#fff;text-shadow:0 0 6px #000,0 0 12px #000;opacity:.45;transition:opacity .2s;user-select:none;z-index:1}
#lb-prev:hover,#lb-next:hover{opacity:.9}
#lb-prev{left:0}
#lb-next{right:0}
@media(hover:none),(pointer:coarse){#lb.zoomed #lb-prev,#lb.zoomed #lb-next{opacity:0;visibility:hidden;pointer-events:none}}
@media(max-width:700px){#lb.zoomed #lb-prev,#lb.zoomed #lb-next{display:none}}
#lb-close{position:fixed;top:14px;left:14px;width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.72);color:#fff;box-shadow:0 2px 14px rgba(0,0,0,.25);cursor:pointer;opacity:.45;line-height:1;z-index:2;transition:opacity .2s}
#lb-close svg{display:block;width:18px;height:18px}
#lb-close:hover{opacity:.95}
#lb-counter{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);font-size:.65rem;color:#fff;text-shadow:0 0 4px #000,0 0 8px #000;opacity:.3;letter-spacing:.13em}
#lb-share{position:fixed;top:24px;right:28px;z-index:3;color:#fff;text-shadow:0 0 4px #000,0 0 8px #000}
/* album name edit */
.nav-edit{background:none;border:1px solid currentColor;color:#fff;cursor:pointer;font-size:.62rem;padding:5px 9px;opacity:.55;line-height:1;vertical-align:middle;font-family:inherit;font-weight:700;letter-spacing:.12em;text-transform:uppercase;white-space:nowrap}
.nav-edit:hover{opacity:1}
#an-modal,#ns-modal,#up-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:2000;align-items:center;justify-content:center}
#an-modal.open,#ns-modal.open,#up-modal.open{display:flex}
#an-box,#ns-box,#up-box{background:#111;padding:28px;width:min(440px,90vw)}
.an-label{font-size:.65rem;letter-spacing:.15em;margin:0 0 12px;opacity:.6}
#an-input,#an-input-en,#ns-title,#ns-title-en,#up-album,#up-new-name,#up-new-slug{width:100%;background:#000;border:1px solid #444;color:#fff;padding:8px 10px;font-family:inherit;font-size:.85rem;letter-spacing:.05em;box-sizing:border-box;text-transform:uppercase}
#an-desc,#an-desc-en{width:100%;background:#000;border:1px solid #444;color:#fff;padding:8px 10px;font-family:inherit;font-size:.85rem;letter-spacing:.05em;box-sizing:border-box;text-transform:none;resize:vertical;min-height:56px}
.ns-help,.ns-error{font-size:.66rem;line-height:1.5;letter-spacing:normal;text-transform:none;margin-top:14px}
.ns-help{opacity:.55}
.ns-error{display:none;color:#c33;font-weight:700}
.up-targets{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px}
.up-targets label{display:flex;align-items:center;gap:7px;font-size:.7rem;font-weight:700;letter-spacing:.12em;cursor:pointer}
.up-targets input{accent-color:currentColor}
#up-file{width:100%;border:1px dashed #555;padding:18px 12px;box-sizing:border-box;font-family:inherit;font-size:.76rem;color:#fff;background:#000}
.up-new-fields{display:none}
.up-progress{height:4px;background:#333;margin-top:14px;overflow:hidden}
.up-progress span{display:block;height:100%;width:0;background:#fff;transition:width .2s}
.up-status{font-size:.66rem;line-height:1.45;letter-spacing:normal;text-transform:none;margin-top:10px;min-height:1.2em;opacity:.65}
.album-h1-row{display:flex;align-items:center;justify-content:center;gap:10px;padding:2rem 24px .8rem;text-align:center}.album-h1-row--nodesc{padding-bottom:1.5rem}
.album-h1{font-size:1rem;font-weight:700;letter-spacing:.12em;margin:0;text-align:center}
.album-desc{max-width:50%;padding:0 24px 1.5rem;line-height:1.6;text-transform:none;letter-spacing:normal}
@media(max-width:520px){.album-desc{width:100%;max-width:none;padding-left:16px;padding-right:16px}}
.album-aspect-row{display:flex;justify-content:flex-end;padding:0 24px 14px}
.empty-guide{width:min(720px,100%);margin:9vh auto 0;padding:0 24px 4rem;text-transform:none;letter-spacing:normal;line-height:1.65}
.empty-guide h1{text-transform:uppercase;letter-spacing:.12em;font-size:1rem;margin-bottom:1rem}
.empty-guide h2{text-transform:uppercase;letter-spacing:.1em;font-size:.82rem;margin:1.4rem 0 .7rem}
.empty-guide p{opacity:.68;margin-bottom:1.1rem}
.empty-guide .readme-callout{border:1px solid rgba(255,255,255,.36);background:rgba(255,255,255,.1);padding:14px 16px;margin-bottom:1.5rem;opacity:1;font-weight:700}
.empty-guide ol,.empty-guide ul{margin-left:1.25rem;opacity:.78}
.empty-guide li{margin-bottom:.7rem}
.empty-guide code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.92em;padding:.12rem .35rem;background:rgba(127,127,127,.18);border:1px solid rgba(127,127,127,.25);border-radius:3px}
.empty-guide a{text-decoration:underline;text-decoration-color:rgba(127,127,127,.5);text-underline-offset:3px;text-decoration-thickness:1px}
.an-btns{display:flex;gap:10px;margin-top:16px;justify-content:flex-end}
.an-btns button{background:none;border:1px solid #555;color:#fff;padding:6px 18px;font-family:inherit;font-size:.65rem;letter-spacing:.13em;cursor:pointer;text-transform:uppercase}
.an-btns .an-save{background:#fff;color:#000;border-color:#fff}
.an-btns .an-delete{border-color:rgba(200,0,0,.75);color:#ff7777;margin-right:auto}
.an-btns .an-delete:hover{background:rgba(180,0,0,.16);border-color:#ff7777}
/* aspect-ratio toggle */
.nav-toggle{background:none;border:none;color:#fff;cursor:pointer;padding:0;opacity:.5;line-height:1;vertical-align:middle;display:flex;align-items:center}
.nav-toggle:hover{opacity:1}
.nav-toggle svg{display:block}
/* preparing overlay */
#prep{position:fixed;inset:0;background:#000;z-index:500;display:flex;align-items:center;justify-content:center;font-size:.7rem;letter-spacing:.2em;transition:opacity .5s,visibility .5s}
#prep.done{opacity:0;visibility:hidden;pointer-events:none}
/* drag-and-drop */
.tile[draggable="true"]{cursor:grab}
.tile.dnd-over{outline:2px solid rgba(255,255,255,.7);outline-offset:-2px}
.tile.dnd-drag{opacity:.3}
/* admin */
.admin-star{position:absolute;top:8px;left:8px;font-size:1.4rem;line-height:1;z-index:10;pointer-events:auto;cursor:pointer;color:rgba(255,255,255,.75);text-shadow:0 0 4px #000,0 0 10px #000;transition:color .15s,opacity .15s}
.admin-star.is-hero{color:#FFD700;text-shadow:0 0 4px #000,0 0 10px #000}
.admin-star:hover{color:#fff;opacity:1}
.admin-star.is-hero:hover{color:#FFE44D}
.admin-bar{position:sticky;top:0;z-index:600;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:7px 20px;background:#d96c00;color:#fff}
.admin-bar-label{font-size:.58rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase;opacity:.9;white-space:nowrap}
.admin-bar-version{opacity:.7}
.admin-bar-actions{display:flex;align-items:center;gap:20px;flex-wrap:wrap;justify-content:flex-end}
.admin-bar a{color:#fff;font-size:.6rem;font-weight:700;letter-spacing:.13em;text-transform:uppercase;opacity:.85}
.admin-bar a:hover{opacity:1}
/* settings modal */
#sm{display:none;position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:4000;overflow-y:auto}
#sm.open{display:flex;align-items:flex-start;justify-content:center;padding:40px 16px}
#sm-panel{background:#111;border:1px solid #2a2a2a;width:100%;max-width:680px}
#sm-head{display:flex;justify-content:space-between;align-items:center;padding:20px 26px;border-bottom:1px solid #222}
#sm-head span{font-size:.95rem;font-weight:700;letter-spacing:.1em}
#sm-head button{background:none;border:none;color:#fff;font-size:1.35rem;cursor:pointer;opacity:.4;padding:0;line-height:1}
#sm-head button:hover{opacity:1}
#sm-body{padding:24px 26px 30px}
.sm-group:first-child .sm-section-head{border-top:none;margin-top:0;padding-top:0}
.sm-group summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:6px}
.sm-group summary::-webkit-details-marker{display:none}
.sm-group summary::before{content:'▶';font-size:.62rem;transition:transform .2s;display:inline-block}
.sm-group[open] summary::before{transform:rotate(90deg)}
.sm-row{display:flex;align-items:center;gap:14px;margin-bottom:13px}
.sm-label{flex:0 0 190px;font-size:.72rem;letter-spacing:.1em;opacity:.58;font-weight:700}
.sm-input{width:100%;background:#000;border:1px solid #2a2a2a;color:#fff;padding:10px 12px;font-family:inherit;font-size:.9rem;outline:none;text-transform:none;letter-spacing:normal}
.sm-input:focus{border-color:#555}
.sm-check{width:100%;display:flex;align-items:center;gap:10px;font-size:.82rem;font-weight:700;letter-spacing:.08em;cursor:pointer}
.sm-check input{accent-color:currentColor;margin:0}
.bg-choice-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;width:100%;margin:1px 0}
.bg-choice{display:inline-flex;align-items:center;gap:8px;color:inherit;cursor:pointer;font-size:.78rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;line-height:1}
.bg-choice input{margin:0;accent-color:currentColor;cursor:pointer}
.bg-swatch{width:28px;height:28px;border:1px solid #555;box-sizing:border-box;display:inline-block}
.bg-swatch-black{background:#000;border-color:#555}
.bg-swatch-grey{background:#888;border-color:#000}
.bg-swatch-white{background:#fff;border-color:#000}
.bg-swatch-default{background:linear-gradient(135deg,transparent 0 45%,currentColor 45% 55%,transparent 55% 100%);border-color:#777}
.sm-section-head{font-size:.78rem;letter-spacing:.1em;font-weight:700;opacity:.5;padding:22px 0 10px;border-top:1px solid #1e1e1e;margin-top:8px}
.sm-section-desc{font-size:.76rem;line-height:1.5;letter-spacing:normal;text-transform:none;opacity:.5;margin:-2px 0 16px}
.sm-readonly{font-size:.82rem;font-weight:700;letter-spacing:.08em}
.sm-action-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
.sm-btn{background:none;border:1px solid #2a2a2a;color:#fff;font-family:inherit;font-size:.68rem;letter-spacing:.08em;font-weight:700;text-transform:uppercase;padding:6px 10px;cursor:pointer;white-space:nowrap}
.sm-btn:hover{background:#1e1e1e;border-color:#444}
.sm-field-hint{font-size:.7rem;line-height:1.45;letter-spacing:normal;text-transform:none;opacity:.45;margin:-8px 0 14px}
.sm-img-btn-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
.sm-img-btn-grid .sm-btn{display:inline-flex;align-items:center;gap:6px;width:100%;white-space:normal;text-align:left;padding:9px 10px;min-height:38px}
.sm-img-btn-grid .sm-btn svg{flex-shrink:0}
#sm-missing-list{background:rgba(255,255,255,.045);border:1px solid rgba(255,255,255,.08);padding:10px 12px;overflow-y:scroll;scrollbar-gutter:stable}
#sm-save{width:100%;background:#fff;color:#000;border:none;padding:13px;font-family:inherit;font-size:.82rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;margin-top:26px}
#sm-save:hover{background:#ddd}
@media(max-width:520px){#an-box,#ns-box,#up-box{width:calc(100vw - 24px);max-height:calc(100vh - 24px);overflow:auto;padding:22px}.an-btns{justify-content:stretch}.an-btns button{flex:1;padding:10px 12px}.album-aspect-row{padding-left:16px;padding-right:16px}.sm-row{align-items:stretch;flex-direction:column;gap:5px}.sm-label{flex:auto}.sm-action-row{align-items:stretch;flex-direction:column}.sm-btn{width:100%}.sm-img-btn-grid{grid-template-columns:1fr}}
/* series selection mode */
.series-checks{display:none;position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,.75);padding:4px 6px;flex-wrap:wrap;gap:6px;z-index:5}
#gallery.series-mode .series-checks{display:flex}
.sc-label{font-size:.55rem;letter-spacing:.08em;display:flex;align-items:center;gap:3px;cursor:pointer;color:#fff;text-transform:uppercase;pointer-events:auto;max-width:100%}
.sc-label span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:11rem}
.sc-label input{margin:0;cursor:pointer;accent-color:#fff}
#series-toast{position:fixed;top:14px;left:50%;transform:translate(-50%,-8px);z-index:9999;background:rgba(0,0,0,.86);color:#fff;border:1px solid rgba(255,255,255,.22);padding:9px 14px;font-size:.68rem;font-weight:700;letter-spacing:.08em;text-transform:none;opacity:0;pointer-events:none;transition:opacity .16s ease,transform .16s ease;box-shadow:0 10px 24px rgba(0,0,0,.35);max-width:calc(100vw - 32px);text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#series-toast.show{opacity:1;transform:translate(-50%,0)}
.series-empty-hint{font-size:.64rem;letter-spacing:.08em;opacity:.5;padding:0 24px 16px;text-transform:none}
.nav-back{display:inline-flex;align-items:center;gap:6px}
.series-nav{gap:14px;min-height:70px;padding:0}
.series-h1{font-size:1rem;font-weight:700;letter-spacing:.12em;margin:0}
.series-h1-row{display:flex;align-items:center;justify-content:center;gap:10px;margin-top:2rem;margin-bottom:1.2rem;text-align:center}
.series-grid{grid-template-columns:1fr;padding-bottom:4rem}
#series-gallery .tile{aspect-ratio:unset;overflow:visible}
#series-gallery .tile img{height:auto;width:100%;object-fit:unset;position:static;z-index:auto;opacity:0;transition:opacity .3s}
#series-gallery .tile.loaded img{opacity:1}
.series-desc{margin-bottom:32px;line-height:1.6;text-transform:none;letter-spacing:normal}
.series-desc p{margin-bottom:.75em}
.markdown-content a,.series-mehr a{text-decoration:underline;text-decoration-color:#888;text-decoration-thickness:1px;text-underline-offset:.16em}
.vis-btn{position:absolute;top:6px;left:6px;background:rgba(0,0,0,.55);border:none;color:#fff;cursor:pointer;padding:3px 5px;line-height:1;z-index:3;display:flex;align-items:center}
.vis-btn:hover{background:rgba(0,0,0,.85)}
.tile-hidden{opacity:.3}
.tile-hidden .vis-btn{opacity:1}
.series-desc h1,.series-desc h2,.series-desc h3{letter-spacing:.1em;text-transform:uppercase;margin:1.2em 0 .4em;font-size:1rem;font-weight:700}
.album-badge{position:absolute;bottom:6px;left:6px;font-size:.58rem;letter-spacing:.08em;font-weight:700;color:#fff;text-shadow:0 1px 2px #000,0 0 6px #000,0 0 10px #000;padding:2px 5px;pointer-events:none;text-transform:uppercase;z-index:5}
.se-remove{position:absolute;top:6px;right:6px;background:rgba(0,0,0,.65);border:none;color:#fff;font-size:.8rem;cursor:pointer;line-height:1;padding:3px 6px;z-index:5}
.se-remove:hover{background:rgba(180,0,0,.7)}
.se-inputs{padding:0 24px 24px;max-width:720px;margin:0 auto}
.se-field-label{display:block;font-size:.58rem;letter-spacing:.13em;opacity:.5;margin-bottom:5px;font-weight:700}
.se-inputs input[type=text],.se-inputs textarea{width:100%;background:#000;border:1px solid #2a2a2a;color:#fff;padding:8px 10px;font-family:inherit;font-size:.8rem;letter-spacing:.05em;margin-bottom:12px;text-transform:none;outline:none}
.se-inputs input[type=text]:focus,.se-inputs textarea:focus{border-color:#555}
.se-inputs textarea{height:140px;resize:vertical}
.se-inputs .bg-choice-row{margin-bottom:12px}
.se-aspect-row{display:flex;justify-content:flex-end;margin:10px 0 0}
.se-save-btn{background:#fff;color:#000;border:none;padding:9px 24px;font-family:inherit;font-size:.65rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;cursor:pointer}
.se-save-btn:hover{background:#ddd}
.se-copy-btn{background:none;border:1px solid #444;color:#fff;padding:9px 18px;font-family:inherit;font-size:.65rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;cursor:pointer}
.se-copy-btn:hover{border-color:#aaa}
.se-delete-btn{background:none;border:1px solid rgba(200,0,0,.75);color:#ff7777;padding:9px 18px;font-family:inherit;font-size:.65rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;cursor:pointer;margin-left:auto}
.se-delete-btn:hover{background:rgba(180,0,0,.16);border-color:#ff7777}
.se-add-note{font-size:.6rem;letter-spacing:.1em;opacity:.4;padding:16px 24px}
.admin-grid-hint{padding-top:0;padding-bottom:14px}
.se-empty-state{max-width:720px;margin:0 auto 24px;padding:20px 24px 28px;text-transform:none;letter-spacing:normal;line-height:1.6}
.se-empty-state h2{font-size:.9rem;text-transform:uppercase;letter-spacing:.12em;margin-bottom:.75rem}
.se-empty-state p{opacity:.65;margin-bottom:1rem}
.se-empty-help{opacity:.65;margin-top:.75rem}
.se-album-links{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
.admin-sm-toggle{background:none;border:none;color:#fff;cursor:pointer;font-family:inherit;font-size:.6rem;font-weight:700;letter-spacing:.13em;text-transform:uppercase;padding:0;opacity:.85}
.admin-sm-toggle:hover{opacity:1}
/* analytics */
.analytics-page{width:min(1180px,calc(100vw - 32px));margin:0 auto;padding:34px 0 64px;text-transform:none;letter-spacing:normal}
.analytics-head{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:10px}
.analytics-head h1{font-size:1.25rem;letter-spacing:.1em;text-transform:uppercase}
.analytics-tabs{display:flex;gap:8px;flex-wrap:wrap}
.analytics-tabs a{border:1px solid rgba(127,127,127,.45);padding:8px 12px;font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.analytics-tabs a.is-active{background:#666;color:#fff;border-color:#666}
.analytics-note,.analytics-empty p{font-size:.82rem;line-height:1.55;opacity:.58;margin-bottom:22px}
.analytics-help{font-size:.78rem;line-height:1.45;opacity:.55;margin:-4px 0 12px;max-width:760px}
.analytics-last-visit{font-size:.76rem;line-height:1.45;opacity:.62;margin:18px 0 -10px}
.analytics-note code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.95em}
.analytics-empty{border:1px solid rgba(127,127,127,.25);padding:28px;text-align:center;margin-top:28px}
.analytics-empty h2,.analytics-page h2{font-size:.9rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:12px}
.analytics-page h3{font-size:.78rem;letter-spacing:.08em;text-transform:uppercase;margin:2px 0 10px;opacity:.72}
.analytics-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:24px 0}
.analytics-card{border:1px solid rgba(127,127,127,.22);background:rgba(127,127,127,.08);padding:16px 14px;min-height:92px;display:flex;flex-direction:column;justify-content:space-between}
.analytics-card span{font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;opacity:.64;display:flex;align-items:center;gap:7px}
.analytics-card-head{display:flex;align-items:center;justify-content:space-between;gap:10px}
.analytics-card strong{font-size:1.35rem;letter-spacing:0;font-weight:700}
.analytics-delta{font-size:.72rem;line-height:1.35;letter-spacing:normal;text-transform:none;opacity:.62;margin-top:8px}
.analytics-delta.is-up{color:#178a41;opacity:1}
.analytics-delta.is-down{color:#b23b3b;opacity:1}
.analytics-page section{margin-top:30px}
.analytics-title{display:flex;align-items:center;gap:8px}
.analytics-icon{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;opacity:.72;flex:0 0 auto}
.analytics-icon svg{display:block;width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.analytics-sparkline{width:86px;height:24px;display:block;flex:0 0 86px;overflow:visible}
.analytics-sparkline polyline{fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;opacity:.72}
.analytics-metric-label{display:flex;align-items:center;justify-content:space-between;gap:12px;min-width:190px}
.analytics-metric-label span{white-space:nowrap}
.analytics-grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.analytics-page table{width:100%;border-collapse:collapse;font-size:.82rem;background:rgba(127,127,127,.045)}
.analytics-page th,.analytics-page td{border-bottom:1px solid rgba(127,127,127,.18);padding:10px 11px;text-align:left;vertical-align:middle}
.analytics-page th{font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;opacity:.58;font-weight:700}
.analytics-page td:last-child,.analytics-page th:last-child{text-align:right}
.analytics-page a{text-decoration:underline;text-decoration-color:rgba(127,127,127,.45);text-underline-offset:3px}
.analytics-cell-strong{font-weight:700}
.analytics-sub{display:inline-block;margin-top:3px;font-size:.72rem;opacity:.65;line-height:1.35}
.analytics-photo{display:flex;align-items:center;gap:10px;text-decoration:none!important}
.analytics-photo img{width:44px;height:44px;object-fit:cover;background:#222;flex:0 0 auto}
.analytics-photo span{overflow-wrap:anywhere}
@media(max-width:800px){.analytics-head{align-items:flex-start;flex-direction:column}.analytics-cards{grid-template-columns:repeat(2,1fr)}.analytics-grid2{grid-template-columns:1fr}.analytics-page{width:calc(100vw - 20px)}.analytics-page table{font-size:.76rem}.analytics-page th,.analytics-page td{padding:8px 7px}.analytics-photo img{width:36px;height:36px}}
@media(max-width:480px){.analytics-cards{grid-template-columns:1fr}.analytics-page{overflow-x:hidden}.analytics-page section{overflow-x:auto}.analytics-page table{min-width:520px}}
/* caption display */
#lb-caption{position:fixed;bottom:38px;left:0;right:0;text-align:center;padding:0 80px;font-size:.82rem;opacity:.9;line-height:1.5;pointer-events:none;color:#fff;text-shadow:0 1px 8px rgba(0,0,0,.8),0 0 20px rgba(0,0,0,.6)}
#lb.lb-admin #lb-counter{bottom:60px}
#lb.lb-admin #lb-caption{bottom:90px}
.series-cap{display:block;text-align:left;color:#595959;padding:4px 0 0;line-height:1.35;pointer-events:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* admin caption editor in lightbox */
#lb-cap-edit{position:fixed;bottom:0;left:0;right:0;display:flex;gap:6px;align-items:center;padding:6px 16px;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:2}
#lb-cap-inputs{flex:1;display:flex;flex-direction:column;gap:4px;min-width:0}
#lb-cap-ai,#lb-cap-save{background:none;border:1px solid rgba(255,255,255,.45);color:#fff;font-family:inherit;font-size:.6rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;padding:4px 10px;white-space:nowrap;flex-shrink:0;line-height:1.6}
#lb-cap-ai:hover,#lb-cap-save:hover{border-color:rgba(255,255,255,.85)}
#lb-cap-ai:disabled,#lb-cap-save:disabled{opacity:.3;cursor:default}
.cap-in{width:100%;box-sizing:border-box;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.3);color:#fff;font-family:inherit;font-size:.7rem;padding:4px 8px;outline:none;line-height:1.4}
.cap-in::placeholder{color:rgba(255,255,255,.38)}
.cap-in:focus{border-color:rgba(255,255,255,.75);background:rgba(255,255,255,.18)}
.cap-no-key{font-size:.58rem;opacity:.55;color:#fff;width:100%;text-align:center;line-height:1.35}
.cap-no-key code{background:rgba(255,255,255,.12);padding:1px 4px;font-family:ui-monospace,monospace}
/* batch caption editor page */
@keyframes bc-spin{to{transform:rotate(360deg)}}
.bc-toolbar{display:flex;align-items:center;gap:12px;padding:14px 20px;border-bottom:1px solid rgba(255,255,255,.1)}
.bc-count{font-size:.8rem;opacity:.55;letter-spacing:.06em}
.bc-grid{width:100%;border-collapse:collapse}
.bc-row{display:grid;grid-template-columns:28px 80px 1fr auto;gap:10px;align-items:center;padding:2px 20px;border-bottom:3px solid #fff;background:rgba(128,128,128,.07)}
.bc-multi .bc-thumb{height:72px}
.bc-cb{width:16px;height:16px;cursor:pointer;accent-color:#d96c00;flex-shrink:0}
.bc-spinner{width:16px;height:16px;border:2px solid rgba(128,128,128,.35);border-top-color:#d96c00;border-radius:50%;animation:bc-spin .7s linear infinite;flex-shrink:0}
.bc-thumb{width:80px;height:60px;object-fit:cover;display:block;background:rgba(255,255,255,.06)}
.bc-inputs{display:flex;flex-direction:column;gap:5px;min-width:0}
.bc-in{width:100%;box-sizing:border-box;background:rgba(255,255,255,.08);border:1px solid #888;color:inherit;font-family:inherit;font-size:.9rem;padding:5px 8px;outline:none;line-height:1.4}
.bc-in:focus{border-color:#bbb;background:rgba(255,255,255,.14)}
.bc-in::placeholder{opacity:.38}
.bc-save{background:none;border:1px solid rgba(255,255,255,.35);color:inherit;font-family:inherit;font-size:.72rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;padding:5px 12px;white-space:nowrap;line-height:1.6}
.bc-save:hover:not(:disabled){border-color:rgba(255,255,255,.8)}
.bc-save:disabled{opacity:.3;cursor:default}
.bc-save.bc-ok{border-color:#4caf50;color:#4caf50}
.bc-save.bc-err{border-color:#e57373;color:#e57373}
.bc-footer{padding:16px 20px}
.bc-gen-btn{background:#d96c00;border:none;color:#fff;font-family:inherit;font-size:.8rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;padding:10px 20px;line-height:1.4}
.bc-gen-btn:hover{background:#b85a00}
.bc-gen-btn:disabled{opacity:.5;cursor:default}
.bc-row-busy .bc-in{opacity:.5}
.bc-row-done .bc-cb{accent-color:#4caf50}
</style>
<?php
$_s  = load_settings();
$_d  = default_settings();
$_g  = (int)($_s['gap'] ?? $_d['gap']);
$_cp = max(0, min(80, (int)($_s['content_padding'] ?? $_d['content_padding'])));
$_nf = preg_replace('/[^0-9.a-z%]/', '', $_s['nav_font_size'] ?? $_d['nav_font_size']) ?: $_d['nav_font_size'];
$_tf = preg_replace('/[^0-9.a-z%]/', '', $_s['tile_label_font_size'] ?? $_d['tile_label_font_size']) ?: $_d['tile_label_font_size'];
$_raw_bg = $_s['bg_color'] ?? $_d['bg_color'];
$_bg = in_array($_raw_bg, ['#000', '#888', '#fff'], true) ? $_raw_bg : $_d['bg_color'];
$_fg = ($_bg === '#fff') ? '#111' : '#fff';
$_sm_rg = $_g * 2;
$_g3    = max((int)($_g * 0.75), 12);
$_dfs = preg_replace('/[^0-9.a-z%]/', '', $_s['desc_font_size'] ?? $_d['desc_font_size']) ?: $_d['desc_font_size'];
$_srg = preg_replace('/[^0-9.a-z%]/', '', $_s['series_row_gap'] ?? $_d['series_row_gap']) ?: $_d['series_row_gap'];
$_swd = max(0, (int)($_s['series_width_desktop'] ?? $_d['series_width_desktop']));
$_swd_all = max(0, (int)round($_swd * 0.8));
$_swd_many = max(0, (int)round($_swd * 1.2));
$_spm = max(0, (int)($_s['series_padding_mobile'] ?? $_d['series_padding_mobile']));
$_series_desktop_tile = max(220, min(320, (int)round($_swd / 3)));
$_series_mobile_tile = 150;
$_series_desktop_few_width = ($_series_desktop_tile * 2) + $_g3;
$_series_desktop_many_width = ($_series_desktop_tile * 3) + ($_g3 * 2);
$_series_mobile_row_width = ($_series_mobile_tile * 2) + $_g3;
$_wm = '';
if ($_bg === '#fff') {
    $_wm = '.nav-edit,.nav-toggle{color:#000}'
         . '#sm{background:rgba(180,180,180,.88)}'
         . '#sm-panel{background:#f8f8f8;border-color:#ddd}'
         . '#sm-head{border-color:#ddd}'
         . '#sm-head button{color:#111}'
         . '.sm-input{background:#fff;color:#111;border-color:#ccc}'
         . '.sm-input:focus{border-color:#666}'
         . '.sm-section-head{border-color:#e5e5e5;color:#333}'
         . '.sm-section-desc{color:#333}'
         . '#sm-save{background:#000;color:#fff}'
         . '#sm-save:hover{background:#222}'
         . '.sm-btn{color:#111;border-color:#bbb}'
         . '.sm-btn:hover{background:#e8e8e8;border-color:#888}'
         . '#sm-missing-list{background:rgba(0,0,0,.035);border-color:rgba(0,0,0,.08)}'
         . '#an-box,#ns-box,#up-box{background:#f8f8f8}'
         . '#an-input,#an-input-en,#an-desc,#an-desc-en,#ns-title,#ns-title-en,#up-album,#up-new-name,#up-new-slug,#up-file{background:#fff;color:#111;border-color:#ccc}'
         . '.up-progress{background:#ddd}.up-progress span{background:#111}'
         . '.an-btns button{border-color:#999;color:#111}'
         . '.an-btns .an-save{background:#000;color:#fff;border-color:#000}'
         . '.an-btns .an-delete{color:#a00000;border-color:#a00000}'
         . '.an-btns .an-delete:hover{background:rgba(160,0,0,.1);border-color:#700}'
         . '.se-inputs input[type=text],.se-inputs textarea{background:#fff;color:#111;border-color:#ccc}'
         . '.se-inputs input[type=text]:focus,.se-inputs textarea:focus{border-color:#666}'
         . '.se-save-btn{background:#000;color:#fff}'
         . '.se-save-btn:hover{background:#222}'
         . '.se-copy-btn{color:#111;border-color:#999}'
         . '.se-copy-btn:hover{border-color:#333}'
         . '.se-delete-btn{color:#a00000;border-color:#a00000}'
         . '.se-delete-btn:hover{background:rgba(160,0,0,.1);border-color:#700}'
         . '.tile-label{color:#fff}'
         . ''
         . '#lb-cap-edit .cap-in{color:#fff}';
}
$_atfg = ($_fg === '#111') ? '#fff' : '#000';
echo "<style>.grid{gap:{$_g}px;padding-left:{$_cp}px;padding-right:{$_cp}px}.nav{font-size:{$_nf}}.tile-label{font-size:{$_tf}}.album-desc,.series-desc,.series-cap{font-size:{$_dfs}}html,body{background:{$_bg};color:{$_fg};--analytics-tab-fg:{$_atfg}}@media(max-width:520px){#page-nav{background:{$_bg}}}#gallery.series-mode{row-gap:{$_sm_rg}px}.series-grid,.series-desc,.series-nav,.series-h1-row,#series-main,.series-strip{max-width:{$_swd}px;margin-left:auto;margin-right:auto}.series-grid,.series-desc,.series-nav,.series-h1-row{padding-left:{$_cp}px;padding-right:{$_cp}px}#series-main.series-count-many,.series-strip.series-count-many{max-width:{$_swd_many}px}.series-strip--all{max-width:{$_swd_all}px}.series-strip--all.series-count-many{max-width:{$_swd_many}px}.series-grid{row-gap:{$_srg}}#series-main,.series-strip{gap:{$_g3}px;padding-bottom:{$_g3}px;--series-desktop-tile-size:{$_series_desktop_tile}px;--series-mobile-tile-size:{$_series_mobile_tile}px;--series-desktop-few-width:{$_series_desktop_few_width}px;--series-desktop-many-width:{$_series_desktop_many_width}px;--series-mobile-row-width:{$_series_mobile_row_width}px}@media(min-width:521px){#lb:not(.zoomed) img{padding-left:{$_cp}px;padding-right:{$_cp}px}}@media(max-width:520px){.series-grid,.series-desc,.series-nav,.series-h1-row{max-width:none;padding-left:{$_spm}px;padding-right:{$_spm}px}}{$_wm}</style>\n";
?>
<script data-cfasync="false">
var LB_PRIMARY_HTML_LANG=<?= json_encode(primary_html_lang_attr()) ?>;
var LB_DEBUG=true;
var LB_ANALYTICS_ENABLED=<?= (analytics_enabled() && !is_admin()) ? 'true' : 'false' ?>;
var LB_COPIED_LABEL=<?= json_encode(copied_label_text(), JSON_UNESCAPED_SLASHES) ?>;
function lbDebug(){if(window.LB_DEBUG&&window.console&&console.debug)console.debug.apply(console,arguments);}
function lbWarn(){if(window.console&&console.warn)console.warn.apply(console,arguments);}
function lbFetchFailureDetails(url,label){
  if(!url)return;
  try{url=new URL(url,location.href).href;}catch(e){}
  lbDebug('[Lightbox] probing failed resource',label,url);
  fetch(url,{cache:'no-store',credentials:'same-origin'}).then(function(r){
    var ct=r.headers.get('content-type')||'';
    return r.text().then(function(t){
      lbWarn('[Lightbox] failed resource details',{label:label,url:url,status:r.status,statusText:r.statusText,contentType:ct,body:t.slice(0,800)});
    });
  }).catch(function(e){lbWarn('[Lightbox] failed resource probe failed',label,url,e);});
}
window.addEventListener('error',function(e){
  if(e.target&&e.target!==window){
    var src=e.target.currentSrc||e.target.src||e.target.href||'';
    lbWarn('[Lightbox] resource failed',e.target.tagName,src);
    if(e.target.tagName==='IMG')lbFetchFailureDetails(src,'image');
    return;
  }
  lbWarn('[Lightbox] script error',e.message,e.filename,e.lineno,e.colno);
},true);
window.addEventListener('unhandledrejection',function(e){lbWarn('[Lightbox] unhandled promise rejection',e.reason);});
function lbRequestFS(){try{var d=document.documentElement;if(d.requestFullscreen)d.requestFullscreen({navigationUI:'hide'});else if(d.webkitRequestFullscreen)d.webkitRequestFullscreen();}catch(e){}}
function lbExitFS(){try{if(document.fullscreenElement&&document.exitFullscreen)document.exitFullscreen();else if(document.webkitFullscreenElement&&document.webkitExitFullscreen)document.webkitExitFullscreen();}catch(e){}}
function lbClampPan(x,y){
  var img=document.getElementById('lb-img'),nw=img.naturalWidth||img.width,nh=img.naturalHeight||img.height,vw=innerWidth,vh=innerHeight;
  if(nw<=vw)x=(vw-nw)/2;else x=Math.min(0,Math.max(vw-nw,x));
  if(nh<=vh)y=(vh-nh)/2;else y=Math.min(0,Math.max(vh-nh,y));
  return{x:x,y:y};
}
function lbSetPan(x,y){
  var p=lbClampPan(x,y),img=document.getElementById('lb-img');
  img.dataset.panX=p.x;img.dataset.panY=p.y;img.style.transform='translate('+p.x+'px,'+p.y+'px)';
}
function lbResetZoom(){
  var el=document.getElementById('lb'),img=document.getElementById('lb-img');
  if(!el||!img)return;
  el.classList.remove('zoomed');img.classList.remove('is-panning');img.style.width='';img.style.height='';img.style.transform='';delete img.dataset.panX;delete img.dataset.panY;delete img.dataset.zoomRx;delete img.dataset.zoomRy;delete img.dataset.zoomCx;delete img.dataset.zoomCy;
}
function lbFitRect(){
  var img=document.getElementById('lb-img'),nw=img.naturalWidth||1,nh=img.naturalHeight||1,s=Math.min(innerWidth/nw,innerHeight/nh),w=nw*s,h=nh*s;
  return{x:(innerWidth-w)/2,y:(innerHeight-h)/2,w:w,h:h,nw:nw,nh:nh};
}
function lbZoomAt(x,y){
  var el=document.getElementById('lb'),img=document.getElementById('lb-img');
  if(el.classList.contains('zoomed')){lbResetZoom();return;}
  if(!(img.naturalWidth&&img.naturalHeight))return;
  var r=lbFitRect(),rx=Math.min(1,Math.max(0,(x-r.x)/r.w)),ry=Math.min(1,Math.max(0,(y-r.y)/r.h));
  el.classList.add('zoomed');img.style.width=img.naturalWidth+'px';img.style.height=img.naturalHeight+'px';
  img.dataset.zoomRx=rx;img.dataset.zoomRy=ry;img.dataset.zoomCx=x;img.dataset.zoomCy=y;
  lbSetPan(x-rx*img.naturalWidth,y-ry*img.naturalHeight);
}
function lbPreloadLarge(i){
  if(!(window.IMGS&&IMGS[i]))return;
  var target=IMGS[i];
  window.lbLargePreloads=window.lbLargePreloads||{};
  if(window.lbLargePreloads[target])return;
  var pre=new Image();
  window.lbLargePreloads[target]=pre;
  pre.onerror=function(){delete window.lbLargePreloads[target];};
  pre.src=target;
}
function showLarge(i){
  var img=document.getElementById('lb-img'),target=IMGS[i];
  window.lbLargePreloads=window.lbLargePreloads||{};
  var hi=window.lbLargePreloads[target]||new Image();
  window.lbLargePreloads[target]=hi;
  var targetAbs=target;try{targetAbs=new URL(target,location.href).href;}catch(e){}
  var hiStart=(performance&&performance.now)?performance.now():Date.now();
  hi.onload=function(){
    if(window.lbAnalyticsImage)lbAnalyticsImage(target,true,'full',hiStart);
    if(cur!==i)return;
    var el=document.getElementById('lb');
    img.onload=null;
    var old=document.querySelector('#lb .lb-hi-fade');if(old)old.remove();
    if(el.classList.contains('zoomed')){
      img.src=target;img.style.opacity='1';
      img.style.width=hi.naturalWidth+'px';img.style.height=hi.naturalHeight+'px';
      lbSetPan(parseFloat(img.dataset.zoomCx||innerWidth/2)-parseFloat(img.dataset.zoomRx||'.5')*hi.naturalWidth,parseFloat(img.dataset.zoomCy||innerHeight/2)-parseFloat(img.dataset.zoomRy||'.5')*hi.naturalHeight);
      return;
    }
    if(img.getAttribute('src')===target){img.style.opacity='1';return;}
    var fade=document.createElement('img');
    fade.className='lb-hi-fade';
    fade.alt='';
    fade.draggable=false;
    fade.src=target;
    el.appendChild(fade);
    requestAnimationFrame(function(){fade.style.opacity='1';});
    setTimeout(function(){if(cur!==i){fade.remove();return;}img.src=target;img.style.opacity='1';fade.remove();},260);
  };
  hi.onerror=function(){if(window.lbAnalyticsImage)lbAnalyticsImage(target,false,'full',hiStart);if(cur===i)lbWarn('[Lightbox] large image failed',target);};
  if(hi.src!==targetAbs)hi.src=target;
  if(hi.complete&&hi.naturalWidth){hi.onload();}
}
function lbSetMeta(i){
  if(!(window.SHARE_URLS&&SHARE_URLS[i]))return;
  var share=SHARE_URLS[i],img=(window.META_IMAGE_URLS&&META_IMAGE_URLS[i])||'';
  document.querySelector('link[rel="canonical"]')?.setAttribute('href',share);
  var ogUrl=document.querySelector('meta[property="og:url"]');if(ogUrl)ogUrl.setAttribute('content',share);
  if(img){
    ['og:image','og:image:secure_url'].forEach(function(p){var m=document.querySelector('meta[property="'+p+'"]');if(m)m.setAttribute('content',img);});
    var tw=document.querySelector('meta[name="twitter:image"]');if(tw)tw.setAttribute('content',img);
  }
}
function lbShareTrack(meta){
  if(window.lbAnalyticsShare)window.lbAnalyticsShare(meta||{});
}
function lbShareUrl(url,title,meta){
  url=url||location.href;title=title||document.title;meta=meta||{};
  lbShareTrack(Object.assign({share_url:url,share_title:title},meta));
  if(navigator.share){
    navigator.share({title:title,url:url}).catch(function(){});
    return 'shared';
  }
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(url).catch(function(){});
    return 'copied';
  }
  return 'shared';
}
function lbShareFromButton(btn){
  if(!btn)return;
  var mode=lbShareUrl(btn.dataset.shareUrl||location.href,btn.dataset.shareTitle||document.title,{page_type:btn.dataset.sharePage||'',album:btn.dataset.shareAlbum||'',photo:btn.dataset.sharePhoto||'',series:btn.dataset.shareSeries||''});
  if(mode==='copied'){var old=btn.textContent;btn.textContent=LB_COPIED_LABEL||'Copied';setTimeout(function(){btn.textContent=old;},1100);}
}
function lbShareCurrent(){
  var url=(window.SHARE_URLS&&SHARE_URLS[cur])||location.href,title=document.title,album=(window.ALBUMS&&ALBUMS[cur])||(window.ALBUM||''),photo=(window.FILES&&FILES[cur])||'';
  lbShareUrl(url,title,{page_type:'photo',album:album,photo:photo,series:(window.LB_SERIES_ID||'')});
}
function lbInstallLightbox(){
  var el=document.getElementById('lb'),img=document.getElementById('lb-img');
  if(!el||!img||el.dataset.installed)return;
  el.dataset.installed='1';
  var lbScrollY=0,lastTap=0,closeTimer=0,clickHandledZoom=false,down=null,drag=false,sx=0,sy=0,suppressClick=false,pinching=false,pinchUntil=0;
  function lbQueueAdjacent(i){
    var seen={};
    [i+1,i+2,i-1,i-2].forEach(function(n){
      if(!IMGS.length)return;
      var idx=(n+IMGS.length)%IMGS.length;
      if(idx===i||seen[idx])return;
      seen[idx]=true;
      queueLarge(idx,false);
    });
  }
  window.lb=function(i){
    var wasOpen=el.classList.contains('open');
    lbResetZoom();
    cur=i;
    if(window.lbAnalyticsPhotoView)lbAnalyticsPhotoView(i);
    if(!wasOpen){lbScrollY=window.scrollY;document.body.style.top='-'+lbScrollY+'px';document.body.classList.add('lb-lock');if(!window.matchMedia('(hover:hover) and (pointer:fine)').matches)lbRequestFS();var _n=document.getElementById('page-nav');if(_n)_n.classList.add('lb-hidden');}
    var target=IMGS[i],thumb=(window.THUMBS&&THUMBS[i])||'';
    img.alt=(window.ALTS&&ALTS[i])||'';
    img.onload=null;
    if(thumb&&img.getAttribute('src')!==thumb&&img.getAttribute('src')!==target){img.src=thumb;img.style.opacity='1';}
    else if(!thumb){img.style.opacity='0';}
    document.getElementById('lb-counter').textContent=(i+1)+' / '+IMGS.length;
    var _lbc=document.getElementById('lb-caption');if(_lbc){if(window.LB_CAPTIONS_ON&&window.CAPTIONS&&CAPTIONS[i]){_lbc.innerHTML=CAPTIONS[i];_lbc.style.display='';}else{_lbc.innerHTML='';_lbc.style.display='none';}}
    if(typeof capLoadForImage==='function')capLoadForImage(i);
    el.classList.add('open');
    if(window.SHARE_URLS&&SHARE_URLS[i]) history.replaceState(null,'',SHARE_URLS[i]);
    else location.hash='i='+i;
    lbSetMeta(i);
    queueLarge(i,true);
    lbQueueAdjacent(i);
  };
  window.lbClose=function(){
    if(window.lbAnalyticsFlushDwell)lbAnalyticsFlushDwell();
    lbResetZoom();
    lbExitFS();
    el.classList.remove('open');
    history.replaceState(null,'',window.ALBUM_PAGE_URL||location.pathname+location.search);
    var _n=document.getElementById('page-nav');if(_n)_n.classList.remove('lb-hidden');
    setTimeout(function(){document.body.classList.remove('lb-lock');document.body.style.top='';window.scrollTo(0,lbScrollY);},200);
  };
  window.lbMove=function(d){if(el.classList.contains('zoomed')&&!window.matchMedia('(hover:hover) and (pointer:fine)').matches)return;lb((cur+d+IMGS.length)%IMGS.length);};
  window.preload=function(i){queueLarge(i,false);};
  el.addEventListener('click',function(e){if(e.target===el)lbClose();});
  img.addEventListener('pointerdown',function(e){
    if(!el.classList.contains('zoomed'))return;
    down={id:e.pointerId,x:e.clientX,y:e.clientY,px:parseFloat(img.dataset.panX||'0'),py:parseFloat(img.dataset.panY||'0')};drag=false;img.classList.add('is-panning');img.setPointerCapture(e.pointerId);e.preventDefault();
  });
  img.addEventListener('pointermove',function(e){
    if(!down||e.pointerId!==down.id)return;
    var dx=e.clientX-down.x,dy=e.clientY-down.y;if(Math.abs(dx)>3||Math.abs(dy)>3)drag=true;
    lbSetPan(down.px+dx,down.py+dy);e.preventDefault();
  });
  function endPan(e){if(down&&e.pointerId===down.id){down=null;img.classList.remove('is-panning');}}
  img.addEventListener('pointerup',endPan);img.addEventListener('pointercancel',endPan);
  img.addEventListener('click',function(e){
    e.stopPropagation();
    if(Date.now()<pinchUntil){suppressClick=false;return;}
    if(suppressClick){suppressClick=false;return;}
    if(drag){drag=false;return;}
    var now=Date.now();
    if(now-lastTap<300){clearTimeout(closeTimer);lastTap=0;clickHandledZoom=true;lbZoomAt(e.clientX,e.clientY);return;}
    clearTimeout(closeTimer);lastTap=now;closeTimer=setTimeout(lbClose,350);
  });
  img.addEventListener('dblclick',function(e){
    e.stopPropagation();
    clearTimeout(closeTimer);lastTap=0;
    if(clickHandledZoom){clickHandledZoom=false;return;}
    lbZoomAt(e.clientX,e.clientY);
  });
  el.addEventListener('touchstart',function(e){
    if(e.touches.length>1){pinching=true;pinchUntil=Date.now()+450;suppressClick=true;lastTap=0;clearTimeout(closeTimer);return;}
    if(e.touches.length){sx=e.touches[0].clientX;sy=e.touches[0].clientY;}
  },{passive:true});
  el.addEventListener('touchmove',function(e){
    if(e.touches.length>1){pinching=true;pinchUntil=Date.now()+450;suppressClick=true;lastTap=0;clearTimeout(closeTimer);}
  },{passive:true});
  el.addEventListener('touchend',function(e){
    if(pinching||Date.now()<pinchUntil){
      if(!e.touches.length){pinching=false;pinchUntil=Date.now()+450;}
      suppressClick=true;lastTap=0;clearTimeout(closeTimer);return;
    }
    if(el.classList.contains('zoomed')||!e.changedTouches.length)return;
    var dx=e.changedTouches[0].clientX-sx,dy=e.changedTouches[0].clientY-sy;
    if(Math.abs(dx)>Math.abs(dy)&&Math.abs(dx)>40){suppressClick=true;lbMove(dx<0?1:-1);}
  });
  window.addEventListener('resize',function(){if(el.classList.contains('zoomed'))lbSetPan(parseFloat(img.dataset.panX||'0'),parseFloat(img.dataset.panY||'0'));});
  document.addEventListener('keydown',function(e){
    var o=el.classList.contains('open');
    if(e.key==='Escape'){if(o)lbClose();else location.href=window.ALBUM_BACK_URL||location.pathname;return;}
    if(!o)return;
    if(e.key==='ArrowLeft')lbMove(-1);
    else if(e.key==='ArrowRight')lbMove(1);
  });
  var m=location.hash.match(/i=(\d+)/);
  if(m){var n=parseInt(m[1]);if(n>=0&&n<IMGS.length)lb(n);}
  else if(typeof SHARE_INDEX==='number'&&SHARE_INDEX>=0&&SHARE_INDEX<IMGS.length){lb(SHARE_INDEX);}
}
document.addEventListener('DOMContentLoaded',function(){
  lbDebug('[Lightbox] DOM ready',{url:location.href,tiles:document.querySelectorAll('.tile').length,images:document.images.length});
  var back=document.querySelector('.nav-back');
  if(back){
    document.body.classList.add('has-float-back');
    var fb=document.createElement('a');
    fb.className='float-back';
    fb.href=back.href;
    fb.setAttribute('aria-label',back.getAttribute('aria-label')||'Back');
    fb.innerHTML='<?= icon_arrow_left() ?>';
    document.body.appendChild(fb);
  }
  Array.prototype.forEach.call(document.images,function(img){
    var src=img.currentSrc||img.src||img.getAttribute('data-src')||'';
    lbDebug('[Lightbox] image registered',src);
    img.addEventListener('error',function(){lbWarn('[Lightbox] image error event',img.currentSrc||img.src);lbFetchFailureDetails(img.currentSrc||img.src,'image');});
    img.addEventListener('load',function(){lbDebug('[Lightbox] image loaded',img.currentSrc||img.src,img.naturalWidth+'x'+img.naturalHeight);});
    if(img.complete&&!img.naturalWidth){lbWarn('[Lightbox] image already failed',src);lbFetchFailureDetails(src,'image');}
  });
});
(function(){
  var checking=false;
  var pageWasAdmin=<?= is_admin() ? 'true' : 'false' ?>;
  function checkAdminSession(){
    if(checking)return;
    checking=true;
    fetch(<?= json_encode(public_url('?admin_status=1'), JSON_UNESCAPED_SLASHES) ?>+'&_='+Date.now(),{cache:'no-store',credentials:'same-origin'})
      .then(function(r){return r.json();})
      .then(function(j){if(!!j.admin!==pageWasAdmin)location.reload();})
      .catch(function(){})
      .finally(function(){checking=false;});
  }
  window.addEventListener('pageshow',function(e){if(e.persisted)checkAdminSession();});
  document.addEventListener('visibilitychange',function(){if(!document.hidden)checkAdminSession();});
  window.addEventListener('focus',checkAdminSession);
})();
function lbInstallAnalytics(ctx){
  if(!LB_ANALYTICS_ENABLED||!ctx||window.lbAnalyticsInstalled)return;
  window.lbAnalyticsInstalled=true;
  var endpoint=<?= json_encode(public_url('?analytics_event=1'), JSON_UNESCAPED_SLASHES) ?>;
  var now=function(){return (performance&&performance.now)?performance.now():Date.now();};
  function randId(){var a=new Uint8Array(18),c=window.crypto||window.msCrypto;if(c&&c.getRandomValues)c.getRandomValues(a);else for(var i=0;i<a.length;i++)a[i]=Math.floor(Math.random()*256);return Array.from(a,function(x){return (x%36).toString(36);}).join('');}
  function getStore(k){try{return localStorage.getItem(k)||'';}catch(e){return '';}}
  function setStore(k,v){try{localStorage.setItem(k,v);}catch(e){}}
  var vid=getStore('lb_analytics_vid');if(!/^[A-Za-z0-9_-]{12,80}$/.test(vid)){vid=randId();setStore('lb_analytics_vid',vid);}
  var sess={};try{sess=JSON.parse(getStore('lb_analytics_session')||'{}')||{};}catch(e){sess={};}
  var t=Date.now();
  if(!sess.id||!sess.last||t-sess.last>30*60*1000){sess={id:randId(),last:t};}
  else sess.last=t;
  setStore('lb_analytics_session',JSON.stringify(sess));
  var sid=sess.id,queue=[],lastPhoto=null,lastPhotoStarted=0,lastViewKey='',lastViewAt=0;
  function base(type){
    var i=(typeof cur==='number')?cur:0;
    return {type:type,vid:vid,sid:sid,album:ctx.currentAlbum?ctx.currentAlbum(i):(ctx.album||''),album_title:ctx.albumTitle||'',series:ctx.series||'',series_title:ctx.seriesTitle||''};
  }
  function send(events,beacon){
    if(!events.length)return;
    var body=JSON.stringify(events.length===1?events[0]:events);
    if(beacon&&navigator.sendBeacon){try{if(navigator.sendBeacon(endpoint,new Blob([body],{type:'application/json'})))return;}catch(e){}}
    fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:body,cache:'no-store',credentials:'same-origin'}).catch(function(){});
  }
  function push(ev,beacon){queue.push(ev);if(beacon||queue.length>=6)flush(beacon);}
  function flush(beacon){var out=queue.splice(0);send(out,beacon);}
  window.lbAnalyticsFlush=function(beacon){flush(!!beacon);};
  window.lbAnalyticsFlushDwell=function(){
    if(lastPhoto===null)return;
    var dur=Math.round(now()-lastPhotoStarted);
    var idx=lastPhoto;
    lastPhoto=null;
    if(dur>=1000){
      var ev=base('photo_dwell');
      ev.album=ctx.currentAlbum?ctx.currentAlbum(idx):(ctx.album||'');ev.photo=(ctx.files&&ctx.files[idx])||'';ev.photo_title=ev.photo;ev.index=idx;ev.total=(ctx.files&&ctx.files.length)||0;ev.duration_ms=Math.min(dur,<?= ANALYTICS_MAX_DWELL_MS ?>);
      push(ev,true);
    }
  };
  window.lbAnalyticsPhotoView=function(i){
    window.lbAnalyticsFlushDwell();
    var f=(ctx.files&&ctx.files[i])||'';if(!f)return;
    var key=sid+':'+ctx.album+':'+f,ts=Date.now();
    if(key===lastViewKey&&ts-lastViewAt<8000)return;
    lastViewKey=key;lastViewAt=ts;lastPhoto=i;lastPhotoStarted=now();
    var ev=base('photo_view');ev.album=ctx.currentAlbum?ctx.currentAlbum(i):(ctx.album||'');ev.photo=f;ev.photo_title=f;ev.index=i;ev.total=ctx.files.length;push(ev,false);
  };
  window.lbAnalyticsImage=function(src,success,type,start){
    var ev=base('image_load'),dt=Math.round(now()-(start||now()));
    ev.photo=ctx.currentPhoto?ctx.currentPhoto():'';
    ev.src=src||'';ev.image_type=type||'unknown';ev.duration_ms=Math.max(0,dt);ev.success=!!success;push(ev,!success);
  };
  window.lbAnalyticsSeriesSourceClick=function(album){
    if(!ctx.series||!album)return;
    var ev=base('series_source_click');ev.album=album;push(ev,true);
  };
  window.lbAnalyticsShare=function(meta){
    meta=meta||{};
    var ev=base('share_click');
    ev.album=meta.album||ev.album||'';ev.photo=meta.photo||'';ev.series=meta.series||ev.series||'';ev.share_url=meta.share_url||'';ev.share_title=meta.share_title||'';ev.page_type=meta.page_type||ctx.viewType||'';
    push(ev,true);
  };
  if(ctx.viewType==='series'||ctx.viewType==='album'){var av=base(ctx.viewType==='series'?'series_view':'album_view');av.total=(ctx.files&&ctx.files.length)||0;push(av,false);}
  document.querySelectorAll('.tile[data-album] img').forEach(function(img){
    var start=now(),tile=img.closest('.tile'),album=tile?tile.dataset.album||ctx.album:'',photo=tile?tile.dataset.file||'':'';
    function done(ok){
      var ev={type:'image_load',vid:vid,sid:sid,album:album,photo:photo,src:img.currentSrc||img.src||img.getAttribute('data-src')||'',image_type:'thumbnail',duration_ms:Math.round(now()-start),success:!!ok};
      push(ev,!ok);
    }
    if(img.complete)done(!!img.naturalWidth);
    else{img.addEventListener('load',function(){done(true);},{once:true});img.addEventListener('error',function(){done(false);},{once:true});}
  });
  document.addEventListener('visibilitychange',function(){if(document.hidden){window.lbAnalyticsFlushDwell();flush(true);}});
  window.addEventListener('pagehide',function(){window.lbAnalyticsFlushDwell();flush(true);});
  setInterval(function(){flush(false);},15000);
}
function toggleVis(type,id,btn){var h=btn.dataset.hidden==='1',nh=h?0:1;var url=type==='album'?'?set_album_hidden=1':'?set_series_hidden=1';var b=type==='album'?new URLSearchParams({a:id,hidden:nh}):new URLSearchParams({id:id,hidden:nh});fetch(url,{method:'POST',headers:{'X-CSRF-Token':LB_CSRF},body:b}).then(function(r){if(!r.ok)return;btn.dataset.hidden=String(nh);btn.innerHTML=nh?'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16"><ellipse cx="8" cy="8" rx="6.5" ry="4" stroke="currentColor" stroke-width="1.4" fill="none" opacity=".4"/><circle cx="8" cy="8" r="2" fill="currentColor" opacity=".4"/><line x1="2" y1="13" x2="14" y2="3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>':'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16"><ellipse cx="8" cy="8" rx="6.5" ry="4" stroke="currentColor" stroke-width="1.4" fill="none"/><circle cx="8" cy="8" r="2" fill="currentColor"/></svg>';btn.closest('.tile').classList.toggle('tile-hidden',nh===1);});}
function setLbLang(l){document.cookie='lb_lang='+l+';max-age='+365*24*3600+';path=/;samesite=lax;secure';document.body.classList.remove('lang-de','lang-en');document.body.classList.add('lang-'+l);document.documentElement.lang=l==='de'?LB_PRIMARY_HTML_LANG:'en';document.querySelectorAll('[data-lang]').forEach(function(a){a.classList.toggle('ls-on',a.dataset.lang===l);});}
function dndSetup(grid,saveUrl,csrf,key){
  var dragging=null;
  grid.addEventListener('dragstart',function(e){
    var t=e.target.closest('.tile');if(!t)return;
    dragging=t;
    e.dataTransfer.effectAllowed='move';
    requestAnimationFrame(function(){if(dragging)dragging.classList.add('dnd-drag');});
  });
  grid.addEventListener('dragend',function(){
    if(dragging)dragging.classList.remove('dnd-drag');
    dragging=null;
  });
  grid.addEventListener('dragover',function(e){
    e.preventDefault();
    if(!dragging)return;
    var t=e.target.closest('.tile');
    if(!t||t===dragging)return;
    var r=t.getBoundingClientRect();
    var after=e.clientX>r.left+r.width/2;
    if(after&&t.nextElementSibling!==dragging){t.after(dragging);}
    else if(!after&&t.previousElementSibling!==dragging){t.before(dragging);}
  });
  grid.addEventListener('drop',function(e){
    e.preventDefault();
    if(!dragging)return;
    var order=Array.from(grid.querySelectorAll('.tile')).map(function(t){return t.dataset[key];}).filter(Boolean);
    fetch(saveUrl,{method:'POST',headers:{'X-CSRF-Token':csrf},body:new URLSearchParams({order:order.join(',')})});
  });
}
</script>
</head>
<?php $_bcls = 'lang-' . current_lang() . (is_admin() ? ' is-admin' : ''); ?><body class="<?= $_bcls ?>">
    <?php
}

function lang_switch_html(): string {
    if (!multilingual_enabled()) return '';
    $de = current_lang() === 'de' ? ' ls-on' : '';
    $en = current_lang() === 'en' ? ' ls-on' : '';
    $pl = htmlspecialchars(primary_lang_label());
    return '<span class="lang-switch">'
         . '<a href="' . htmlspecialchars(lang_url('de')) . '" class="' . trim($de) . '" data-lang="de" onclick="setLbLang(\'de\')">' . $pl . '</a>'
         . '<a href="' . htmlspecialchars(lang_url('en')) . '" class="' . trim($en) . '" data-lang="en" onclick="setLbLang(\'en\')">EN</a>'
         . '</span>';
}

function share_label_text(): string {
    return lf(load_settings(), 'share_label') ?: (current_lang() === 'en' ? 'Share' : 'Teilen');
}

function copied_label_text(): string {
    return lf(load_settings(), 'copied_label') ?: (current_lang() === 'en' ? 'Copied' : 'Kopiert');
}

function share_link_html(string $url, string $title, string $page_type, string $album = '', string $photo = '', string $series = ''): string {
    return '<button class="share-link" type="button" data-share-url="' . htmlspecialchars($url, ENT_QUOTES) . '" data-share-title="' . htmlspecialchars($title, ENT_QUOTES) . '" data-share-page="' . htmlspecialchars($page_type, ENT_QUOTES) . '" data-share-album="' . htmlspecialchars($album, ENT_QUOTES) . '" data-share-photo="' . htmlspecialchars($photo, ENT_QUOTES) . '" data-share-series="' . htmlspecialchars($series, ENT_QUOTES) . '" onclick="lbShareFromButton(this)">' . htmlspecialchars(share_label_text()) . '</button>';
}

function nav_tools_html(string $url, string $title, string $page_type, string $album = '', string $photo = '', string $series = ''): string {
    return '<span class="nav-tools">' . lang_switch_html() . share_link_html($url, $title, $page_type, $album, $photo, $series) . '</span>';
}

function bi(string $de, string $en): string {
    if (!multilingual_enabled()) return htmlspecialchars($en !== '' ? $en : $de);
    if ($en === '' || $en === $de) return htmlspecialchars($de);
    return '<span class="t-de">' . htmlspecialchars($de) . '</span>'
         . '<span class="t-en">' . htmlspecialchars($en) . '</span>';
}

function bi_html(string $de_html, string $en_html): string {
    if (!multilingual_enabled()) return $en_html !== '' ? $en_html : $de_html;
    if ($en_html === '' || $en_html === $de_html) return $de_html;
    return '<div class="t-de">' . $de_html . '</div>'
         . '<div class="t-en">' . $en_html . '</div>';
}

function html_foot(): void {
    echo '</body></html>';
}

function ensure_gallery_readme(): void {
    $file = __DIR__ . '/README.txt';
    if (is_file($file)) return;
    $content = <<<TXT
Lightbox photo gallery

Getting started
How the gallery is organized:
- Albums are the foundation of the gallery. Each album is a folder inside
  images/, for example images/my-first-album/.
- Photos you put into those album folders are the master images. Keep those
  files as your originals.
- Series are curated selections. A series can use photos from one album or
  from several different albums without copying the master images.
- For speed, the gallery creates JPEG thumbnails and larger JPEG display
  images only when they are needed. These generated files live in the thumbs/
  and large/ folders inside each album folder.
- The thumbs/ and large/ folders are only caches. You can safely remove them;
  the gallery will recreate the needed files automatically.
- The gallery uses local Montserrat font files from fonts/. The included
  files are enough for normal use. If they are missing, download Montserrat
  from Google Fonts:
  https://fonts.google.com/specimen/Montserrat
  or from the upstream project:
  https://github.com/JulietaUla/Montserrat
  Then place WOFF2 webfont files at:
  fonts/montserrat-latin.woff2
  fonts/montserrat-latin-ext.woff2

1. Create an album folder, for example:
   images/my-first-album/
2. Put JPEG, PNG, or WebP photos into that folder.
3. Make sure images/ and all album folders are writable by the web server.
   The gallery needs write access to save thumbnails, large display images,
   album settings, and image order files.
4. Reload the gallery in your browser.

Admin mode
- IMPORTANT: To access admin mode, open:
  https://myserver.com/lightbox/admin
- On first admin access, choose a long unique password.
- The password is saved only as a one-way hash.
- For better isolation, set LIGHTBOX_ADMIN_PASSWORD_FILE to a writable path
  outside the public web folder before first admin setup.

Password reset
To reset the admin password, create this file in the gallery folder:
  reset-pass.txt

Then open /admin. The gallery removes reset-pass.txt, deletes the stored
password hash, and shows the create-password screen again.

TXT;
    @file_put_contents($file, $content, LOCK_EX);
    @chmod($file, 0664);
}

function getting_started_guide(): void {
    $images_created = false;
    if (!is_dir(IMG_DIR)) {
        $images_created = @mkdir(IMG_DIR, 0775);
    }
    $admin_url = htmlspecialchars(absolute_url(admin_url()));
    $version = htmlspecialchars(APP_VERSION);
    echo '<main class="empty-guide">';
    echo '<h1>Welcome — no albums yet</h1>';
    echo '<p>Lightbox ' . $version . '</p>';
    echo '<p>Follow these steps to get your gallery up and running.</p>';
    echo '<h2>Step 1 — Log in as admin</h2>';
    echo '<p><strong>Make a note of this link — it will not be shown again once your gallery has albums.</strong></p>';
    echo '<p><a href="' . $admin_url . '" target="_blank" rel="noopener">' . $admin_url . '</a> (opens in a new window) — use this to set up your admin password and access the gallery controls. You can rename albums, write descriptions, arrange series, and change settings from there.</p>';
    echo '<h2>Step 2 — Add your first album</h2>';
    if ($images_created) {
        echo '<p>An empty <code>images/</code> folder has been created for you. Create a subfolder inside it for your first album — for example <code>images/my-first-album/</code> — and place your JPEG, PNG, or WebP photos inside it. Reload this page and your gallery will appear.</p>';
    } else {
        echo '<p>Create a subfolder inside <code>images/</code> for your first album — for example <code>images/my-first-album/</code> — and place your JPEG, PNG, or WebP photos inside it. Reload this page and your gallery will appear.</p>';
    }
    echo '<h2>Requirements</h2>';
    echo '<ul>';
    echo '<li><strong>PHP 7.4 or newer</strong> — most shared hosts and modern servers already have this.</li>';
    echo '<li><strong>GD extension</strong> — used to resize photos into thumbnails and display images. Usually enabled by default.</li>';
    echo '<li><strong>EXIF extension</strong> — used to read photo orientation and capture date so images display the right way up. Usually enabled by default.</li>';
    echo '<li><strong>Writable <code>images/</code> folder</strong> — the web server must be able to write inside <code>images/</code> so it can save thumbnails, display images, and album settings.</li>';
    echo '<li><em>(Optional)</em> <strong><code>LIGHTBOX_GOOGLE_API_KEY</code></strong> in <code>.env</code> + the cURL PHP extension — enables the AI Caption button that generates captions from your photos automatically.</li>';
    echo '</ul>';
    echo '<h2>How the gallery works</h2>';
    echo '<p>Each folder inside <code>images/</code> is an album. Albums are the foundation of the gallery — everything else is built on top of them.</p>';
    echo '<p>Optionally, you can create <em>series</em>: curated collections that draw photos from one or more albums. Series are managed in admin and don\'t require duplicating any files.</p>';
    echo '<p>The gallery automatically generates JPEG thumbnails and display images the first time a visitor opens an album. These cached files are stored in <code>thumbs/</code> and <code>large/</code> subfolders inside each album. They are safe to delete at any time — the gallery will rebuild them as needed.</p>';
    echo '<p>Make sure the <code>images/</code> folder and its subfolders are writable by the web server, so thumbnails, display images, and album settings can be saved.</p>';
    echo '<p>A <code>README.txt</code> file with these setup notes has been saved in the gallery folder for reference.</p>';
    echo '</main>';
}

function analytics_range_files(string $prefix, int $days): array {
    $files = [];
    for ($i = $days - 1; $i >= 0; $i--) {
        $files[] = analytics_dir() . '/' . $prefix . '-' . date('Y-m-d', strtotime("-{$i} days")) . '.jsonl';
    }
    return $files;
}

function analytics_read_jsonl(string $prefix, int $days): array {
    $rows = [];
    foreach (analytics_range_files($prefix, $days) as $file) {
        if (!is_file($file)) continue;
        $fh = @fopen($file, 'rb');
        if (!$fh) continue;
        while (($line = fgets($fh)) !== false) {
            $row = json_decode(trim($line), true);
            if (is_array($row)) $rows[] = $row;
        }
        fclose($fh);
    }
    return $rows;
}

function analytics_day_keys(int $days): array {
    $keys = [];
    for ($i = $days - 1; $i >= 0; $i--) {
        $keys[] = date('Y-m-d', strtotime("-{$i} days"));
    }
    return $keys;
}

function analytics_event_day(array $row, array $day_lookup): string {
    $ts = (int)($row['ts'] ?? 0);
    if ($ts <= 0) return '';
    $day = date('Y-m-d', $ts);
    return isset($day_lookup[$day]) ? $day : '';
}

function analytics_catalog(): array {
    $albums = [];
    $photos = [];
    $series_out = [];
    foreach (albums() as $al) {
        $slug = (string)$al['slug'];
        $imgs = images_in($slug);
        $albums[$slug] = [
            'title' => lf(['name' => $al['name'] ?? $slug, 'name_en' => $al['name_en'] ?? ''], 'name') ?: $slug,
            'count' => count($imgs),
            'url' => album_url($slug),
        ];
        foreach ($imgs as $idx => $img) {
            $photos[$slug . "\n" . $img] = [
                'album' => $slug,
                'photo' => $img,
                'title' => $img,
                'album_title' => $albums[$slug]['title'],
                'index' => $idx,
                'total' => count($imgs),
                'thumb' => thumb_url_ar($slug, $img),
                'url' => canonical_image_url($slug, $img),
            ];
        }
    }
    foreach (load_series() as $sid => $series) {
        if (!in_array($sid, SERIES_IDS, true) || !series_has_admin_content($series)) continue;
        $valid = series_valid_images($series, true);
        $series_out[$sid] = [
            'title' => series_title_value($series, 'Untitled Series'),
            'count' => count($valid),
            'url' => series_url($sid),
            'images' => array_map(fn($img) => $img['album'] . "\n" . $img['file'], $valid),
        ];
    }
    return ['albums' => $albums, 'photos' => $photos, 'series' => $series_out];
}

function analytics_aggregate(int $days): array {
    $events = analytics_read_jsonl('events', $days);
    $loads = analytics_read_jsonl('image-loads', $days);
    $cat = analytics_catalog();
    $day_keys = analytics_day_keys($days);
    $day_lookup = array_fill_keys($day_keys, true);
    $daily_counts = [];
    $daily_visitors = [];
    $daily_sessions = [];
    $daily_dwell = [];
    $daily_album_sessions = [];
    $daily_series_sessions = [];
    $daily_loads = [];
    foreach ($day_keys as $day) {
        $daily_counts[$day] = ['album_views' => 0, 'series_views' => 0, 'series_source_clicks' => 0, 'share_clicks' => 0, 'photo_views' => 0];
        $daily_visitors[$day] = [];
        $daily_sessions[$day] = [];
        $daily_dwell[$day] = ['sum' => 0, 'count' => 0];
        $daily_album_sessions[$day] = [];
        $daily_series_sessions[$day] = [];
        $daily_loads[$day] = ['sum' => 0, 'success' => 0, 'failed' => 0];
    }
    $visitors = [];
    $sessions = [];
    $album_stats = [];
    $series_stats = [];
    $photo_stats = [];
    $share_stats = [];
    $album_sessions = [];
    $series_sessions = [];
    $dwell_sum = 0;
    $dwell_count = 0;
    $album_views = 0;
    $series_views = 0;
    $series_source_clicks = 0;
    $share_clicks = 0;
    $photo_views = 0;
    foreach ($events as $ev) {
        $type = $ev['type'] ?? '';
        $vid = (string)($ev['vid'] ?? '');
        $sid = (string)($ev['sid'] ?? '');
        $album = (string)($ev['album'] ?? '');
        $photo = (string)($ev['photo'] ?? '');
        $series = (string)($ev['series'] ?? '');
        $day = analytics_event_day($ev, $day_lookup);
        if ($vid !== '') $visitors[$vid] = true;
        if ($sid !== '') $sessions[$sid] = $sessions[$sid] ?? ['photos' => []];
        if ($day !== '') {
            if ($vid !== '') $daily_visitors[$day][$vid] = true;
            if ($sid !== '') $daily_sessions[$day][$sid] = $daily_sessions[$day][$sid] ?? ['photos' => []];
        }
        if ($type === 'album_view' && $album !== '') {
            $album_views++;
            if ($day !== '') $daily_counts[$day]['album_views']++;
            $album_stats[$album] = $album_stats[$album] ?? ['album' => $album, 'views' => 0, 'visitors' => [], 'completed' => 0, 'sessions' => 0];
            $album_stats[$album]['views']++;
            if ($vid !== '') $album_stats[$album]['visitors'][$vid] = true;
        } elseif ($type === 'series_view' && $series !== '') {
            $series_views++;
            if ($day !== '') $daily_counts[$day]['series_views']++;
            $series_stats[$series] = $series_stats[$series] ?? ['series' => $series, 'views' => 0, 'photo_views' => 0, 'source_clicks' => 0, 'source_albums' => [], 'visitors' => [], 'completed' => 0, 'sessions' => 0];
            $series_stats[$series]['views']++;
            if ($vid !== '') $series_stats[$series]['visitors'][$vid] = true;
        } elseif ($type === 'series_source_click' && $series !== '' && $album !== '') {
            $series_source_clicks++;
            if ($day !== '') $daily_counts[$day]['series_source_clicks']++;
            $series_stats[$series] = $series_stats[$series] ?? ['series' => $series, 'views' => 0, 'photo_views' => 0, 'source_clicks' => 0, 'source_albums' => [], 'visitors' => [], 'completed' => 0, 'sessions' => 0];
            $series_stats[$series]['source_clicks']++;
            $series_stats[$series]['source_albums'][$album] = ($series_stats[$series]['source_albums'][$album] ?? 0) + 1;
            if ($vid !== '') $series_stats[$series]['visitors'][$vid] = true;
        } elseif ($type === 'share_click') {
            $share_url = (string)($ev['share_url'] ?? '');
            if ($share_url !== '') {
                $share_clicks++;
                if ($day !== '') $daily_counts[$day]['share_clicks']++;
                $share_stats[$share_url] = $share_stats[$share_url] ?? ['url' => $share_url, 'title' => (string)($ev['share_title'] ?? $share_url), 'page_type' => (string)($ev['page_type'] ?? ''), 'album' => $album, 'photo' => $photo, 'series' => $series, 'count' => 0, 'visitors' => []];
                $share_stats[$share_url]['count']++;
                if ($vid !== '') $share_stats[$share_url]['visitors'][$vid] = true;
            }
        } elseif ($type === 'photo_view' && $album !== '' && $photo !== '') {
            $photo_views++;
            if ($day !== '') $daily_counts[$day]['photo_views']++;
            $pkey = $album . "\n" . $photo;
            $photo_stats[$pkey] = $photo_stats[$pkey] ?? ['album' => $album, 'photo' => $photo, 'views' => 0, 'dwell_sum' => 0, 'dwell_count' => 0];
            $photo_stats[$pkey]['views']++;
            if ($sid !== '') $sessions[$sid]['photos'][$pkey] = true;
            if ($day !== '' && $sid !== '') $daily_sessions[$day][$sid]['photos'][$pkey] = true;
            if ($sid !== '') {
                $akey = $album . "\n" . $sid;
                $idx = (int)($cat['photos'][$pkey]['index'] ?? ($ev['idx'] ?? 0));
                $total = (int)($cat['albums'][$album]['count'] ?? ($ev['total'] ?? 0));
                $album_sessions[$akey] = $album_sessions[$akey] ?? ['album' => $album, 'sid' => $sid, 'max_idx' => -1, 'last_idx' => -1, 'last_photo' => '', 'total' => $total];
                if ($idx >= $album_sessions[$akey]['max_idx']) {
                    $album_sessions[$akey]['max_idx'] = $idx;
                    $album_sessions[$akey]['last_idx'] = $idx;
                    $album_sessions[$akey]['last_photo'] = $photo;
                }
                if ($total > 0) $album_sessions[$akey]['total'] = $total;
                if ($day !== '') {
                    $daily_album_sessions[$day][$akey] = $daily_album_sessions[$day][$akey] ?? ['max_idx' => -1, 'total' => $total];
                    if ($idx >= $daily_album_sessions[$day][$akey]['max_idx']) $daily_album_sessions[$day][$akey]['max_idx'] = $idx;
                    if ($total > 0) $daily_album_sessions[$day][$akey]['total'] = $total;
                }
            }
            if ($sid !== '' && $series !== '') {
                $series_stats[$series] = $series_stats[$series] ?? ['series' => $series, 'views' => 0, 'photo_views' => 0, 'source_clicks' => 0, 'source_albums' => [], 'visitors' => [], 'completed' => 0, 'sessions' => 0];
                $series_stats[$series]['photo_views']++;
                $skey = $series . "\n" . $sid;
                $sidx = isset($ev['idx']) ? (int)$ev['idx'] : 0;
                $stotal = isset($ev['total']) ? (int)$ev['total'] : (int)($cat['series'][$series]['count'] ?? 0);
                $series_sessions[$skey] = $series_sessions[$skey] ?? ['series' => $series, 'sid' => $sid, 'max_idx' => -1, 'last_idx' => -1, 'last_photo' => '', 'last_album' => '', 'total' => $stotal];
                if ($sidx >= $series_sessions[$skey]['max_idx']) {
                    $series_sessions[$skey]['max_idx'] = $sidx;
                    $series_sessions[$skey]['last_idx'] = $sidx;
                    $series_sessions[$skey]['last_photo'] = $photo;
                    $series_sessions[$skey]['last_album'] = $album;
                }
                if ($stotal > 0) $series_sessions[$skey]['total'] = $stotal;
                if ($day !== '') {
                    $daily_series_sessions[$day][$skey] = $daily_series_sessions[$day][$skey] ?? ['max_idx' => -1, 'total' => $stotal];
                    if ($sidx >= $daily_series_sessions[$day][$skey]['max_idx']) $daily_series_sessions[$day][$skey]['max_idx'] = $sidx;
                    if ($stotal > 0) $daily_series_sessions[$day][$skey]['total'] = $stotal;
                }
            }
        } elseif ($type === 'photo_dwell' && $album !== '' && $photo !== '') {
            $dur = max(0, min(ANALYTICS_MAX_DWELL_MS, (int)($ev['duration_ms'] ?? 0)));
            if ($dur >= 1000) {
                $dwell_sum += $dur;
                $dwell_count++;
                if ($day !== '') {
                    $daily_dwell[$day]['sum'] += $dur;
                    $daily_dwell[$day]['count']++;
                }
                $pkey = $album . "\n" . $photo;
                $photo_stats[$pkey] = $photo_stats[$pkey] ?? ['album' => $album, 'photo' => $photo, 'views' => 0, 'dwell_sum' => 0, 'dwell_count' => 0];
                $photo_stats[$pkey]['dwell_sum'] += $dur;
                $photo_stats[$pkey]['dwell_count']++;
            }
        }
    }
    foreach ($album_sessions as $as) {
        $album = $as['album'];
        $album_stats[$album] = $album_stats[$album] ?? ['album' => $album, 'views' => 0, 'visitors' => [], 'completed' => 0, 'sessions' => 0];
        $album_stats[$album]['sessions']++;
        $total = max(1, (int)$as['total']);
        $completed = ($as['max_idx'] + 1) >= $total || (($as['max_idx'] + 1) / $total) >= 0.9;
        if ($completed) $album_stats[$album]['completed']++;
    }
    foreach ($series_sessions as $ss) {
        $series = $ss['series'];
        $series_stats[$series] = $series_stats[$series] ?? ['series' => $series, 'views' => 0, 'photo_views' => 0, 'source_clicks' => 0, 'source_albums' => [], 'visitors' => [], 'completed' => 0, 'sessions' => 0];
        $series_stats[$series]['sessions']++;
        $total = max(1, (int)$ss['total']);
        $completed = ($ss['max_idx'] + 1) >= $total || (($ss['max_idx'] + 1) / $total) >= 0.9;
        if ($completed) $series_stats[$series]['completed']++;
    }
    $dropoffs = [];
    foreach ($album_sessions as $as) {
        $total = max(1, (int)$as['total']);
        $completed = ($as['max_idx'] + 1) >= $total || (($as['max_idx'] + 1) / $total) >= 0.9;
        if ($completed || $as['last_photo'] === '') continue;
        $key = $as['album'] . "\n" . $as['last_photo'];
        $dropoffs[$key] = $dropoffs[$key] ?? ['album' => $as['album'], 'photo' => $as['last_photo'], 'idx' => $as['last_idx'], 'count' => 0];
        $dropoffs[$key]['count']++;
    }
    foreach ($album_stats as &$st) {
        $st['unique'] = count($st['visitors']);
        $st['completion_rate'] = $st['sessions'] > 0 ? $st['completed'] / $st['sessions'] : 0;
    }
    unset($st);
    foreach ($series_stats as &$st) {
        $st['unique'] = count($st['visitors']);
        $st['completion_rate'] = $st['sessions'] > 0 ? $st['completed'] / $st['sessions'] : 0;
        $st['photos_per_session'] = $st['sessions'] > 0 ? $st['photo_views'] / $st['sessions'] : 0;
        $st['source_click_rate'] = $st['views'] > 0 ? $st['source_clicks'] / $st['views'] : 0;
        arsort($st['source_albums']);
    }
    unset($st);
    foreach ($photo_stats as &$st) {
        $st['avg_dwell'] = $st['dwell_count'] > 0 ? $st['dwell_sum'] / $st['dwell_count'] : 0;
    }
    unset($st);
    $load_success = array_values(array_filter($loads, fn($r) => !empty($r['success'])));
    $load_failed = array_values(array_filter($loads, fn($r) => empty($r['success'])));
    foreach ($loads as $r) {
        $day = analytics_event_day($r, $day_lookup);
        if ($day === '') continue;
        if (!empty($r['success'])) {
            $daily_loads[$day]['sum'] += max(0, (int)($r['duration_ms'] ?? 0));
            $daily_loads[$day]['success']++;
        } else {
            $daily_loads[$day]['failed']++;
        }
    }
    $load_avg = 0;
    if ($load_success) $load_avg = array_sum(array_map(fn($r) => max(0, (int)($r['duration_ms'] ?? 0)), $load_success)) / count($load_success);
    usort($album_stats, fn($a, $b) => $b['views'] <=> $a['views']);
    usort($series_stats, fn($a, $b) => $b['views'] <=> $a['views']);
    usort($photo_stats, fn($a, $b) => $b['views'] <=> $a['views']);
    foreach ($share_stats as &$st) $st['unique'] = count($st['visitors']);
    unset($st);
    usort($share_stats, fn($a, $b) => $b['count'] <=> $a['count']);
    usort($dropoffs, fn($a, $b) => $b['count'] <=> $a['count']);
    usort($load_success, fn($a, $b) => ((int)($b['duration_ms'] ?? 0)) <=> ((int)($a['duration_ms'] ?? 0)));
    $failure_counts = [];
    foreach ($load_failed as $r) {
        $key = ((string)($r['album'] ?? '')) . "\n" . ((string)($r['photo'] ?? '')) . "\n" . ((string)($r['src'] ?? ''));
        $failure_counts[$key] = $failure_counts[$key] ?? ['album' => (string)($r['album'] ?? ''), 'photo' => (string)($r['photo'] ?? ''), 'src' => (string)($r['src'] ?? ''), 'count' => 0];
        $failure_counts[$key]['count']++;
    }
    usort($failure_counts, fn($a, $b) => $b['count'] <=> $a['count']);
    $completion_rates = array_column($album_stats, 'completion_rate');
    $series_completion_rates = array_column($series_stats, 'completion_rate');
    $timeline = [
        'unique_visitors' => [],
        'album_views' => [],
        'series_views' => [],
        'series_source_clicks' => [],
        'share_clicks' => [],
        'photo_views' => [],
        'photos_per_session' => [],
        'avg_dwell' => [],
        'completion_rate' => [],
        'series_completion_rate' => [],
        'avg_load' => [],
        'failed_loads' => [],
    ];
    foreach ($day_keys as $day) {
        $timeline['unique_visitors'][] = count($daily_visitors[$day]);
        foreach (['album_views', 'series_views', 'series_source_clicks', 'share_clicks', 'photo_views'] as $key) {
            $timeline[$key][] = $daily_counts[$day][$key];
        }
        $session_count = count($daily_sessions[$day]);
        $timeline['photos_per_session'][] = $session_count ? array_sum(array_map(fn($s) => count($s['photos']), $daily_sessions[$day])) / $session_count : 0;
        $timeline['avg_dwell'][] = $daily_dwell[$day]['count'] ? $daily_dwell[$day]['sum'] / $daily_dwell[$day]['count'] : 0;
        $album_completed = 0;
        foreach ($daily_album_sessions[$day] as $as) {
            $total = max(1, (int)$as['total']);
            if (($as['max_idx'] + 1) >= $total || (($as['max_idx'] + 1) / $total) >= 0.9) $album_completed++;
        }
        $timeline['completion_rate'][] = $daily_album_sessions[$day] ? $album_completed / count($daily_album_sessions[$day]) : 0;
        $series_completed = 0;
        foreach ($daily_series_sessions[$day] as $ss) {
            $total = max(1, (int)$ss['total']);
            if (($ss['max_idx'] + 1) >= $total || (($ss['max_idx'] + 1) / $total) >= 0.9) $series_completed++;
        }
        $timeline['series_completion_rate'][] = $daily_series_sessions[$day] ? $series_completed / count($daily_series_sessions[$day]) : 0;
        $timeline['avg_load'][] = $daily_loads[$day]['success'] ? $daily_loads[$day]['sum'] / $daily_loads[$day]['success'] : 0;
        $timeline['failed_loads'][] = $daily_loads[$day]['failed'];
    }
    return [
        'days' => $days,
        'timeline_days' => $day_keys,
        'timeline' => $timeline,
        'events_count' => count($events),
        'loads_count' => count($loads),
        'unique_visitors' => count($visitors),
        'album_views' => $album_views,
        'series_views' => $series_views,
        'series_source_clicks' => $series_source_clicks,
        'share_clicks' => $share_clicks,
        'photo_views' => $photo_views,
        'photos_per_session' => $sessions ? array_sum(array_map(fn($s) => count($s['photos']), $sessions)) / count($sessions) : 0,
        'avg_dwell' => $dwell_count ? $dwell_sum / $dwell_count : 0,
        'completion_rate' => $completion_rates ? array_sum($completion_rates) / count($completion_rates) : 0,
        'series_completion_rate' => $series_completion_rates ? array_sum($series_completion_rates) / count($series_completion_rates) : 0,
        'avg_load' => $load_avg,
        'failed_loads' => count($load_failed),
        'top_albums' => array_slice($album_stats, 0, 12),
        'top_series' => array_slice($series_stats, 0, 12),
        'top_photos' => array_slice($photo_stats, 0, 12),
        'top_shares' => array_slice($share_stats, 0, 12),
        'dropoffs' => array_slice($dropoffs, 0, 12),
        'slowest_loads' => array_slice($load_success, 0, 10),
        'failed_by_image' => array_slice($failure_counts, 0, 10),
        'catalog' => $cat,
    ];
}

function analytics_format_count($n): string {
    return number_format((float)$n, is_float($n) && floor($n) !== $n ? 1 : 0);
}

function analytics_format_duration_ms($ms): string {
    $ms = (float)$ms;
    if ($ms <= 0) return '0s';
    $s = $ms / 1000;
    if ($s < 60) return rtrim(rtrim(number_format($s, 1), '0'), '.') . 's';
    return (int)floor($s / 60) . 'm ' . str_pad((string)(int)floor(fmod($s, 60)), 2, '0', STR_PAD_LEFT) . 's';
}

function analytics_format_percent($v): string {
    return number_format(max(0, min(1, (float)$v)) * 100, 0) . '%';
}

function analytics_sparkline_html(array $values, string $label = ''): string {
    if (!$values) return '';
    $vals = array_map(fn($v) => (float)$v, $values);
    $w = 86;
    $h = 24;
    $pad = 2;
    $min = min($vals);
    $max = max($vals);
    $range = $max - $min;
    $count = count($vals);
    $points = [];
    foreach ($vals as $i => $v) {
        $x = $count > 1 ? $pad + (($w - $pad * 2) * ($i / ($count - 1))) : $w / 2;
        $y = $range > 0 ? $pad + (($h - $pad * 2) * (1 - (($v - $min) / $range))) : $h / 2;
        $points[] = round($x, 2) . ',' . round($y, 2);
    }
    $title = $label !== '' ? '<title>' . htmlspecialchars($label) . '</title>' : '';
    return '<svg class="analytics-sparkline" viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="' . htmlspecialchars($label ?: 'Timeline') . '">' . $title . '<polyline points="' . implode(' ', $points) . '"/></svg>';
}

function analytics_metric_label(string $label, array $timeline): string {
    return '<span class="analytics-metric-label"><span>' . htmlspecialchars($label) . '</span>' . analytics_sparkline_html($timeline, $label . ' timeline') . '</span>';
}

function analytics_admin_visits_file(): string {
    return analytics_dir() . '/admin-visits.json';
}

function analytics_admin_visits(): array {
    $file = analytics_admin_visits_file();
    if (!is_file($file)) return [];
    $data = @json_decode((string)file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function analytics_snapshot(array $data): array {
    return [
        'unique_visitors' => (float)$data['unique_visitors'],
        'album_views' => (float)$data['album_views'],
        'series_views' => (float)$data['series_views'],
        'series_source_clicks' => (float)$data['series_source_clicks'],
        'share_clicks' => (float)$data['share_clicks'],
        'photo_views' => (float)$data['photo_views'],
        'photos_per_session' => (float)$data['photos_per_session'],
        'avg_dwell' => (float)$data['avg_dwell'],
        'completion_rate' => (float)$data['completion_rate'],
        'avg_load' => (float)$data['avg_load'],
        'failed_loads' => (float)$data['failed_loads'],
    ];
}

function analytics_remember_admin_visit(int $days, array $data): void {
    if (!analytics_ensure_dir()) return;
    $visits = analytics_admin_visits();
    $visits[(string)$days] = [
        'ts' => time(),
        'metrics' => analytics_snapshot($data),
    ];
    atomic_write(analytics_admin_visits_file(), json_encode($visits, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function analytics_last_visit_text(?array $visit): string {
    if (!$visit || empty($visit['ts'])) return 'No previous analytics dashboard visit for this range yet.';
    return 'Last analytics dashboard visit for this range: ' . date('M j, Y H:i', (int)$visit['ts']) . '.';
}

function analytics_visit_old_enough(?array $visit): bool {
    return $visit && !empty($visit['ts']) && time() - (int)$visit['ts'] >= 86400;
}

function analytics_delta_html(string $key, array $data, ?array $visit, string $kind = 'count'): string {
    if (!$visit || !isset($visit['metrics'][$key])) return '<div class="analytics-delta">No previous value</div>';
    if (!analytics_visit_old_enough($visit)) return '<div class="analytics-delta">Delta available after 24h</div>';
    $current = (float)($data[$key] ?? 0);
    $previous = (float)$visit['metrics'][$key];
    $delta = $current - $previous;
    if (abs($delta) < 0.0001) return '<div class="analytics-delta">No change since last visit</div>';
    $class = $delta > 0 ? ' is-up' : ' is-down';
    $sign = $delta > 0 ? '+' : '-';
    $abs = abs($delta);
    if ($kind === 'duration') {
        $value = $sign . analytics_format_duration_ms($abs);
    } elseif ($kind === 'percent') {
        $value = $sign . number_format($abs * 100, 0) . ' pp';
    } else {
        $value = $sign . analytics_format_count($abs);
    }
    return '<div class="analytics-delta' . $class . '">' . htmlspecialchars($value) . ' since last visit</div>';
}

function analytics_photo_meta(array $data, string $album, string $photo): array {
    $key = $album . "\n" . $photo;
    $url = $album !== '' && analytics_album_exists($album) ? album_url($album) : all_photos_url();
    return $data['catalog']['photos'][$key] ?? ['album' => $album, 'photo' => $photo, 'title' => $photo, 'album_title' => $album, 'index' => 0, 'total' => 0, 'thumb' => '', 'url' => $url];
}

function analytics_photo_link_html(array $meta, string $label = '', string $sub = ''): string {
    $title = $label !== '' ? $label : (string)($meta['title'] ?? '');
    $url = (string)($meta['url'] ?? all_photos_url());
    $thumb = (string)($meta['thumb'] ?? '');
    $html = '<a class="analytics-photo" href="' . htmlspecialchars($url) . '">';
    if ($thumb !== '') $html .= '<img src="' . htmlspecialchars($thumb) . '" alt="" loading="lazy">';
    $html .= '<span>' . htmlspecialchars($title);
    if ($sub !== '') $html .= '<br><span class="analytics-sub">' . htmlspecialchars($sub) . '</span>';
    $html .= '</span></a>';
    return $html;
}

function analytics_share_photo_meta(array $data, array $row): ?array {
    $album = (string)($row['album'] ?? '');
    $photo = (string)($row['photo'] ?? '');
    if ($album !== '' && $photo !== '') return analytics_photo_meta($data, $album, $photo);

    $url = (string)($row['url'] ?? '');
    $path = rawurldecode((string)(parse_url($url, PHP_URL_PATH) ?? ''));
    $query = (string)(parse_url($url, PHP_URL_QUERY) ?? '');
    if ($query !== '') {
        parse_str($query, $params);
        $album = safe_seg((string)($params['a'] ?? '')) ?? '';
        $photo = safe_seg((string)($params['share_image'] ?? '')) ?? '';
        if ($album !== '' && $photo !== '') return analytics_photo_meta($data, $album, $photo);
    }
    $parts = route_path_parts($path);
    if ($parts && in_array($parts[0], public_langs(), true)) array_shift($parts);
    if (count($parts) === 4 && $parts[0] === 'album' && $parts[2] === 'photo') {
        $album = resolve_album_seo_slug($parts[1], null) ?? '';
        $photo = $album !== '' ? (resolve_photo_seo_slug($album, $parts[3]) ?? '') : '';
        if ($album !== '' && $photo !== '') return analytics_photo_meta($data, $album, $photo);
    }
    return null;
}

function analytics_icon(string $name): string {
    $icons = [
        'visitors' => '<path d="M5.5 7.5a2.5 2.5 0 1 1 5 0 2.5 2.5 0 0 1-5 0Z"/><path d="M3 14.2c.7-2.2 2.4-3.4 5-3.4s4.3 1.2 5 3.4"/>',
        'traffic' => '<path d="M2.5 13.5h11"/><path d="M4 11V7"/><path d="M8 11V3"/><path d="M12 11V5.5"/>',
        'engagement' => '<path d="M8 13.5s-5-2.9-5-6.7A2.8 2.8 0 0 1 8 5a2.8 2.8 0 0 1 5 1.8c0 3.8-5 6.7-5 6.7Z"/>',
        'album' => '<path d="M3 4.5h10v8H3z"/><path d="M5 7.5l2 2 1.5-1.5L11 10.5"/>',
        'series' => '<path d="M3 5h7"/><path d="M6 8h7"/><path d="M3 11h7"/>',
        'photo' => '<path d="M3 4h10v9H3z"/><path d="M6 7h.01"/><path d="M4.5 11l2.3-2.3 1.6 1.6 1.2-1.2L12 11.5"/>',
        'dropoff' => '<path d="M3 4h7"/><path d="M3 8h10"/><path d="M3 12h5"/><path d="M10.5 10.5 13 13"/><path d="m13 10.5-2.5 2.5"/>',
        'performance' => '<path d="M3 11a5 5 0 1 1 10 0"/><path d="M8 11l2.5-3.5"/><path d="M4.5 13h7"/>',
        'clock' => '<path d="M8 3a5 5 0 1 1 0 10A5 5 0 0 1 8 3Z"/><path d="M8 5.5V8l1.8 1.2"/>',
        'link' => '<path d="M6.5 5.5 8 4a3 3 0 0 1 4.2 4.2l-1.5 1.5"/><path d="M9.5 10.5 8 12a3 3 0 0 1-4.2-4.2l1.5-1.5"/><path d="M6.5 9.5 9.5 6.5"/>',
    ];
    $path = $icons[$name] ?? $icons['traffic'];
    return '<span class="analytics-icon" aria-hidden="true"><svg viewBox="0 0 16 16">' . $path . '</svg></span>';
}

function analytics_heading(string $icon, string $text): string {
    return '<h2 class="analytics-title">' . analytics_icon($icon) . htmlspecialchars($text) . '</h2>';
}

function page_admin_analytics(int $days): void {
    analytics_ensure_dir();
    $data = analytics_aggregate($days);
    $last_visits = analytics_admin_visits();
    $last_visit = $last_visits[(string)$days] ?? null;
    html_head('Analytics — ' . site_title_text(), 'Local gallery analytics.', '', absolute_url(analytics_admin_url()));
    echo '<nav class="nav" id="page-nav"><a class="nav-back" href="' . htmlspecialchars(public_url()) . '"><span class="nav-title">' . site_title_html() . '</span></a></nav>';
    admin_bar_html();
    settings_modal(albums());
    echo '<main class="analytics-page">';
    echo '<div class="analytics-head"><h1>Analytics</h1><div class="analytics-tabs"><a class="' . ($days === 7 ? 'is-active' : '') . '" href="' . htmlspecialchars(analytics_admin_url(7)) . '">Last 7 Days</a><a class="' . ($days === 30 ? 'is-active' : '') . '" href="' . htmlspecialchars(analytics_admin_url(30)) . '">Last 30 Days</a></div></div>';
    echo '<p class="analytics-note">Local anonymous analytics from <code>' . htmlspecialchars(ANALYTICS_DIR) . '/</code>. Delete the JSONL files there to reset analytics, or disable collection in General Settings.</p>';
    if ($data['events_count'] === 0 && $data['loads_count'] === 0) {
        echo '<div class="analytics-empty"><h2>No analytics yet</h2><p>Open a public album, view a few photos, then return here. Missing daily files are normal and count as empty days.</p></div></main>';
        analytics_remember_admin_visit($days, $data);
        html_foot();
        return;
    }
    echo '<p class="analytics-last-visit">' . htmlspecialchars(analytics_last_visit_text(is_array($last_visit) ? $last_visit : null)) . '</p>';
    $tl = is_array($data['timeline'] ?? null) ? $data['timeline'] : [];
    $cards = [
        ['visitors', 'unique_visitors', 'Unique visitors', analytics_format_count($data['unique_visitors']), 'count'],
        ['album', 'album_views', 'Album views', analytics_format_count($data['album_views']), 'count'],
        ['series', 'series_views', 'Series views', analytics_format_count($data['series_views']), 'count'],
        ['link', 'series_source_clicks', 'Source clicks', analytics_format_count($data['series_source_clicks']), 'count'],
        ['link', 'share_clicks', 'Share clicks', analytics_format_count($data['share_clicks']), 'count'],
        ['photo', 'photo_views', 'Photo views', analytics_format_count($data['photo_views']), 'count'],
        ['engagement', 'photos_per_session', 'Photos/session', analytics_format_count($data['photos_per_session']), 'count'],
        ['clock', 'avg_dwell', 'Avg time/photo', analytics_format_duration_ms($data['avg_dwell']), 'duration'],
        ['dropoff', 'completion_rate', 'Completion rate', analytics_format_percent($data['completion_rate']), 'percent'],
        ['performance', 'avg_load', 'Avg image load', analytics_format_duration_ms($data['avg_load']), 'duration'],
        ['performance', 'failed_loads', 'Failed image loads', analytics_format_count($data['failed_loads']), 'count'],
    ];
    echo '<section class="analytics-cards">';
    foreach ($cards as $card) {
        echo '<div class="analytics-card"><div class="analytics-card-head"><span>' . analytics_icon($card[0]) . htmlspecialchars($card[2]) . '</span>' . analytics_sparkline_html($tl[$card[1]] ?? [], $card[2] . ' timeline') . '</div><strong>' . htmlspecialchars($card[3]) . '</strong>' . analytics_delta_html($card[1], $data, is_array($last_visit) ? $last_visit : null, $card[4]) . '</div>';
    }
    echo '</section>';
    echo '<section class="analytics-grid2"><div>' . analytics_heading('traffic', 'Traffic') . '<p class="analytics-help">How many anonymous visitors opened albums, series, source links, and photos in this date range.</p><table><tbody>'
       . '<tr><th>' . analytics_metric_label('Unique visitors', $tl['unique_visitors'] ?? []) . '</th><td>' . analytics_format_count($data['unique_visitors']) . '</td></tr>'
       . '<tr><th>' . analytics_metric_label('Album views', $tl['album_views'] ?? []) . '</th><td>' . analytics_format_count($data['album_views']) . '</td></tr>'
       . '<tr><th>' . analytics_metric_label('Series views', $tl['series_views'] ?? []) . '</th><td>' . analytics_format_count($data['series_views']) . '</td></tr>'
       . '<tr><th>' . analytics_metric_label('Series source clicks', $tl['series_source_clicks'] ?? []) . '</th><td>' . analytics_format_count($data['series_source_clicks']) . '</td></tr>'
       . '<tr><th>' . analytics_metric_label('Share clicks', $tl['share_clicks'] ?? []) . '</th><td>' . analytics_format_count($data['share_clicks']) . '</td></tr>'
       . '<tr><th>' . analytics_metric_label('Photo views', $tl['photo_views'] ?? []) . '</th><td>' . analytics_format_count($data['photo_views']) . '</td></tr>'
       . '</tbody></table></div>';
    echo '<div>' . analytics_heading('engagement', 'Engagement') . '<p class="analytics-help">How deeply visitors browse: distinct photos per session, time spent on photos, and completion rates. A visit counts as complete when the viewer reaches the final photo, or at least 90% of the photos, in that album or series.</p><table><tbody>'
       . '<tr><th>' . analytics_metric_label('Photos/session', $tl['photos_per_session'] ?? []) . '</th><td>' . analytics_format_count($data['photos_per_session']) . '</td></tr>'
       . '<tr><th>' . analytics_metric_label('Average time/photo', $tl['avg_dwell'] ?? []) . '</th><td>' . analytics_format_duration_ms($data['avg_dwell']) . '</td></tr>'
       . '<tr><th>' . analytics_metric_label('Album completion', $tl['completion_rate'] ?? []) . '</th><td>' . analytics_format_percent($data['completion_rate']) . '</td></tr>'
       . '<tr><th>' . analytics_metric_label('Series completion', $tl['series_completion_rate'] ?? []) . '</th><td>' . analytics_format_percent($data['series_completion_rate']) . '</td></tr>'
       . '</tbody></table></div></section>';
    echo '<section>' . analytics_heading('album', 'Top Albums') . '<p class="analytics-help">Albums ranked by album page views. Completion is calculated per visitor session by looking at the furthest photo position reached in that album: if the session reaches the last photo, or at least 90% of the album, it counts as completed.</p><table><thead><tr><th>Album</th><th>Views</th><th>Visitors</th><th>Completion</th></tr></thead><tbody>';
    foreach ($data['top_albums'] as $row) {
        $album = $row['album'];
        $meta = $data['catalog']['albums'][$album] ?? ['title' => $album, 'url' => album_url($album)];
        echo '<tr><td><a href="' . htmlspecialchars($meta['url']) . '">' . htmlspecialchars($meta['title']) . '</a></td><td>' . analytics_format_count($row['views']) . '</td><td>' . analytics_format_count($row['unique']) . '</td><td>' . analytics_format_percent($row['completion_rate']) . '</td></tr>';
    }
    echo '</tbody></table></section>';
    echo '<section>' . analytics_heading('series', 'Top Series') . '<p class="analytics-help">Series ranked by series page views. Completion uses the same rule as albums, but follows the custom order of photos in the series. Source clicks show how often visitors used the source-album links below a series; the smaller lines list the clicked album names and their individual click counts.</p><table><thead><tr><th>Series</th><th>Views</th><th>Visitors</th><th>Photo Views</th><th>Completion</th><th>Source Clicks</th></tr></thead><tbody>';
    foreach ($data['top_series'] as $row) {
        $series = $row['series'];
        $meta = $data['catalog']['series'][$series] ?? ['title' => $series, 'url' => series_url($series)];
        $sources = [];
        foreach (array_slice($row['source_albums'] ?? [], 0, 2, true) as $album => $count) {
            $am = $data['catalog']['albums'][$album] ?? ['title' => $album, 'url' => album_url($album)];
            $sources[] = '<a href="' . htmlspecialchars($am['url']) . '">' . htmlspecialchars($am['title']) . '</a>: ' . analytics_format_count($count);
        }
        $source_text = '<strong class="analytics-cell-strong">Total: ' . analytics_format_count($row['source_clicks']) . '</strong>' . ($sources ? '<br><span class="analytics-sub">By album: ' . implode(', ', $sources) . '</span>' : '');
        echo '<tr><td><a href="' . htmlspecialchars($meta['url']) . '">' . htmlspecialchars($meta['title']) . '</a></td><td>' . analytics_format_count($row['views']) . '</td><td>' . analytics_format_count($row['unique']) . '</td><td>' . analytics_format_count($row['photo_views']) . '</td><td>' . analytics_format_percent($row['completion_rate']) . '</td><td>' . $source_text . '</td></tr>';
    }
    echo '</tbody></table></section>';
    echo '<section>' . analytics_heading('photo', 'Top Photos') . '<p class="analytics-help">Photos ranked by lightbox views, with average dwell time from valid views longer than one second.</p><table><thead><tr><th>Photo</th><th>Album</th><th>Views</th><th>Avg Time</th></tr></thead><tbody>';
    foreach ($data['top_photos'] as $row) {
        $m = analytics_photo_meta($data, $row['album'], $row['photo']);
        echo '<tr><td>' . analytics_photo_link_html($m) . '</td><td>' . htmlspecialchars($m['album_title']) . '</td><td>' . analytics_format_count($row['views']) . '</td><td>' . analytics_format_duration_ms($row['avg_dwell']) . '</td></tr>';
    }
    echo '</tbody></table></section>';
    echo '<section>' . analytics_heading('link', 'Top Share Links') . '<p class="analytics-help">Links visitors shared or copied from the gallery, album, series, and photo views.</p><table><thead><tr><th>Link</th><th>Type</th><th>Shares</th><th>Visitors</th></tr></thead><tbody>';
    foreach ($data['top_shares'] as $row) {
        $label = trim((string)($row['title'] ?? '')) ?: (string)$row['url'];
        $share_meta = analytics_share_photo_meta($data, $row);
        $link_html = $share_meta ? analytics_photo_link_html($share_meta, $label, (string)$row['url']) : '<a href="' . htmlspecialchars((string)$row['url']) . '">' . htmlspecialchars($label) . '</a><br><span class="analytics-sub">' . htmlspecialchars((string)$row['url']) . '</span>';
        echo '<tr><td>' . $link_html . '</td><td>' . htmlspecialchars((string)($row['page_type'] ?? '')) . '</td><td>' . analytics_format_count($row['count']) . '</td><td>' . analytics_format_count($row['unique'] ?? 0) . '</td></tr>';
    }
    echo '</tbody></table></section>';
    echo '<section>' . analytics_heading('dropoff', 'Drop-off Points') . '<p class="analytics-help">For sessions that did not reach the final photo or the 90% completion threshold, this shows the last photo viewed before the visitor stopped browsing that album.</p><table><thead><tr><th>Album</th><th>Drop-off Photo</th><th>Index</th><th>Count</th></tr></thead><tbody>';
    foreach ($data['dropoffs'] as $row) {
        $m = analytics_photo_meta($data, $row['album'], $row['photo']);
        echo '<tr><td>' . htmlspecialchars($m['album_title']) . '</td><td>' . analytics_photo_link_html($m) . '</td><td>' . ((int)$row['idx'] + 1) . ' / ' . (int)$m['total'] . '</td><td>' . analytics_format_count($row['count']) . '</td></tr>';
    }
    echo '</tbody></table></section>';
    echo '<section>' . analytics_heading('performance', 'Image Performance') . '<p class="analytics-help">Browser-side image timing and failures for thumbnails and full lightbox images.</p><div class="analytics-grid2"><div><h3>Slowest Successful Loads</h3><table><thead><tr><th>Image</th><th>Type</th><th>Load Time</th></tr></thead><tbody>';
    foreach ($data['slowest_loads'] as $row) {
        $m = analytics_photo_meta($data, (string)($row['album'] ?? ''), (string)($row['photo'] ?? ''));
        echo '<tr><td>' . analytics_photo_link_html($m, $m['title'] ?: ($row['src'] ?? 'image')) . '</td><td>' . htmlspecialchars((string)($row['image_type'] ?? 'unknown')) . '</td><td>' . analytics_format_duration_ms($row['duration_ms'] ?? 0) . '</td></tr>';
    }
    echo '</tbody></table></div><div><h3>Failed Loads</h3><table><thead><tr><th>Image</th><th>Failures</th></tr></thead><tbody>';
    foreach ($data['failed_by_image'] as $row) {
        $m = analytics_photo_meta($data, $row['album'], $row['photo']);
        $label = $m['title'] ?: ($row['src'] ?: 'image');
        echo '<tr><td>' . analytics_photo_link_html($m, $label) . '</td><td>' . analytics_format_count($row['count']) . '</td></tr>';
    }
    echo '</tbody></table></div></div></section>';
    echo '</main>';
    analytics_remember_admin_visit($days, $data);
    html_foot();
}

// ─── pages ───────────────────────────────────────────────────────────────────

function page_overview(): void {
    ensure_gallery_readme();
    $albs  = albums();
    $base  = base_url();
    $title = site_title_text();
    $desc  = $title . '. ' . count($albs) . ' albums.';

    $jsonld = json_encode([
        '@context'    => 'https://schema.org',
        '@type'       => 'ImageGallery',
        'name'        => $title,
        'description' => $desc,
        'url'         => $base . '/',
    ], JSON_UNESCAPED_SLASHES);

    $_ov_s = load_settings();
    $st = site_title_html();
    $series_label_de = trim((string)($_ov_s['series_label'] ?? 'SERIES')) ?: 'SERIES';
    $series_label_en = trim((string)($_ov_s['series_label_en'] ?? $series_label_de)) ?: $series_label_de;
    $series_heading = bi($series_label_de, $series_label_en);
    $admin    = is_admin();
    $show_all = isset($_GET['all']);
    $sdata_ov = load_series();
    $s_order  = load_settings()['series_order'] ?? SERIES_IDS;
    if (!is_array($s_order)) $s_order = SERIES_IDS;
    $series_tiles = [];
    foreach ($s_order as $sid) {
        if (!in_array($sid, SERIES_IDS, true)) continue;
        $sv = $sdata_ov[$sid];
        if (!$sv['images']) continue;
        if (!$admin && ($sv['hidden'] ?? false)) continue;
        [$title_de, $title_en] = series_title_parts($sv, $admin ? 'Untitled Series' : '');
        if (!$admin && $title_de === '') continue;
        $valid_imgs = series_valid_images($sv, $admin);
        if (!$valid_imgs) continue;
        $first = series_hero_image($sv, $valid_imgs);
        if (!$first) continue;
        $series_tiles[] = ['id' => $sid, 'title_de' => $title_de, 'title_en' => $title_en, 'album' => $first['album'], 'file' => $first['file'], 'thumb' => thumb_url_ar($first['album'], $first['file']), 'hidden' => (bool)($sv['hidden'] ?? false), 'thumb_missing' => !thumb_current($first['album'], $first['file'])];
    }
    $hero = '';
    if ($series_tiles) {
        $hero = $series_tiles[0]['thumb'];
    } elseif ($albs) {
        $hero = thumb_url_ar($albs[0]['slug'], $albs[0]['hero']);
    }
    $overview_canonical = clean_urls_enabled() && multilingual_enabled() ? absolute_url(public_url(lang_path_prefix())) : $base . '/';
    html_head($title, $desc, $hero, $overview_canonical);
    echo '<script type="application/ld+json">' . $jsonld . '</script>';
    $overview_share_url = $show_all ? absolute_url(all_photos_url()) : absolute_url(public_url(lang_path_prefix()));
    echo '<nav class="nav" id="overview-nav"><span>' . $st . '</span>' . nav_tools_html($overview_share_url, $title, $show_all ? 'all' : 'home') . '</nav>';
    if ($admin) {
        admin_bar_html();
        settings_modal($albs);
    }
    if (!$albs && !$series_tiles) {
        echo '<script data-cfasync="false">document.body.classList.add("page-home")</script>';
        getting_started_guide();
        html_foot();
        return;
    }
    if (!$series_tiles) $show_all = true;
    if (!$show_all) {
        // Series-only view: 2-column centered grid
        $series_count_class = count($series_tiles) >= 5 ? ' series-count-many' : ' series-count-few';
        echo '<script data-cfasync="false">document.body.classList.add("page-home")</script>';
        echo '<div id="series-home-wrap">';
        if ($admin && count($series_tiles) > 1) {
            echo '<div class="se-add-note admin-grid-hint">Drag and drop series to change their order.</div>';
        }
        echo '<main class="grid' . $series_count_class . '" id="series-main">';
        foreach ($series_tiles as $st_item) {
            $drag = $admin ? ' draggable="true" data-id="' . $st_item['id'] . '"' : '';
            $hcls = ($admin && $st_item['hidden']) ? ' tile-hidden' : '';
            $pcls = ($st_item['thumb_missing'] ?? false) ? ' thumb-pending' : '';
            $data = ' data-album="' . htmlspecialchars($st_item['album']) . '" data-file="' . htmlspecialchars($st_item['file']) . '"';
            $img_attr = ($st_item['thumb_missing'] ?? false) ? 'data-src="' . htmlspecialchars($st_item['thumb']) . '"' : 'src="' . htmlspecialchars($st_item['thumb']) . '"';
            echo '<a class="tile' . $hcls . $pcls . '" href="' . htmlspecialchars(series_url($st_item['id'])) . '"' . $drag . $data . '>';
            echo '<img ' . $img_attr . ' alt="' . htmlspecialchars($st_item['title_de']) . '" draggable="false" loading="lazy">';
            echo '<span class="tile-label">' . bi($st_item['title_de'], $st_item['title_en']) . '</span>';
            if ($admin) {
                $hd = $st_item['hidden'] ? '1' : '0';
                $ic = $st_item['hidden'] ? icon_eye_closed() : icon_eye_open();
                echo '<span class="vis-btn" role="button" data-hidden="' . $hd . '" onclick="toggleVis(\'series\',\'' . $st_item['id'] . '\',this);event.preventDefault()" title="Toggle visibility">' . $ic . '</span>';
            }
            echo '</a>';
        }
        echo '</main>';
        echo '<div class="all-photos-link-wrap" style="text-align:center;padding:1.5rem 0 3rem"><a href="' . htmlspecialchars(all_photos_url()) . '" style="font-size:.75rem;letter-spacing:.15em;opacity:.8;text-decoration:none;color:inherit;display:inline-flex;align-items:center;gap:6px">' . setting_label_html('all_photos_label', 'Alle Fotos', 'All Photos') . icon_arrow_right() . '</a></div>';
        echo '</div>';
        if ($admin) {
            $csrf = json_encode($_SESSION['csrf'] ?? '');
            echo '<script data-cfasync="false">dndSetup(document.getElementById("series-main"),"?save_series_order=1",' . $csrf . ',"id");</script>';
        }
    } else {
        // ?all: series strip + album grid
        if ($series_tiles) {
            $series_count_class = count($series_tiles) >= 5 ? ' series-count-many' : ' series-count-few';
            echo '<h2 class="overview-section-title">' . $series_heading . '</h2>';
            echo '<div class="grid series-strip series-strip--all' . $series_count_class . '">';
            foreach ($series_tiles as $st_item) {
                $hcls = ($admin && $st_item['hidden']) ? ' tile-hidden' : '';
                $pcls = '';
                $data = ' data-album="' . htmlspecialchars($st_item['album']) . '" data-file="' . htmlspecialchars($st_item['file']) . '"';
                $img_attr = 'src="' . htmlspecialchars($st_item['thumb']) . '"';
                echo '<a class="tile' . $hcls . $pcls . '" href="' . htmlspecialchars(series_url($st_item['id'])) . '"' . $data . '>';
                echo '<img ' . $img_attr . ' alt="' . htmlspecialchars($st_item['title_de']) . '" loading="eager" fetchpriority="high">';
                echo '<span class="tile-label">' . bi($st_item['title_de'], $st_item['title_en']) . '</span>';
                if ($admin) {
                    $hd = $st_item['hidden'] ? '1' : '0';
                    $ic = $st_item['hidden'] ? icon_eye_closed() : icon_eye_open();
                    echo '<span class="vis-btn" role="button" data-hidden="' . $hd . '" onclick="toggleVis(\'series\',\'' . $st_item['id'] . '\',this);event.preventDefault()" title="Toggle visibility">' . $ic . '</span>';
                }
                echo '</a>';
            }
            echo '</div>';
        }
        echo '<h2 class="overview-section-title">' . setting_label_html('albums_label', 'ALBUMS', 'ALBUMS') . ($series_tiles ? ' <a href="' . htmlspecialchars(public_url()) . '">(hide)</a>' : '') . '</h2>';
        echo '<main class="grid" id="overview-grid">';
        $visible_idx = 0;
        foreach ($albs as $al) {
            if (!$admin && ($al['hidden'] ?? false)) continue;
            $turl  = htmlspecialchars(thumb_url_ar($al['slug'], $al['hero']));
            $aurl  = htmlspecialchars(add_url_param(album_url($al['slug']), 'from', 'all'));
            $drag  = $admin ? ' draggable="true" data-slug="' . htmlspecialchars($al['slug']) . '"' : '';
            $hcls  = ($admin && ($al['hidden'] ?? false)) ? ' tile-hidden' : '';
            $is_pending = !thumb_current($al['slug'], $al['hero']);
            $pcls  = $is_pending ? ' thumb-pending' : '';
            $load  = $visible_idx < 6 ? ' fetchpriority="high"' : ' loading="lazy"';
            $visible_idx++;
            echo '<a class="tile' . $hcls . $pcls . '" href="' . $aurl . '"' . $drag . ' data-album="' . htmlspecialchars($al['slug']) . '" data-file="' . htmlspecialchars($al['hero']) . '">';
            $al_name_de = $al['name'] ?? $al['slug'];
            $al_name_en = $al['name_en'] ?? '';
            $img_attr = $is_pending ? 'data-src="' . $turl . '"' : 'src="' . $turl . '"';
            echo '<img ' . $img_attr . ' alt="' . htmlspecialchars($al_name_de) . '" draggable="false"' . $load . '>';
            echo '<span class="tile-label">' . bi($al_name_de, $al_name_en) . '</span>';
            if ($admin) {
                $hd = ($al['hidden'] ?? false) ? '1' : '0';
                $ic = ($al['hidden'] ?? false) ? icon_eye_closed() : icon_eye_open();
                echo '<span class="vis-btn" role="button" data-hidden="' . $hd . '" onclick="toggleVis(\'album\',\'' . htmlspecialchars($al['slug'], ENT_QUOTES) . '\',this);event.preventDefault()" title="Toggle visibility">' . $ic . '</span>';
            }
            echo '</a>';
        }
        echo '</main>';
        if ($admin) {
            $csrf = json_encode($_SESSION['csrf'] ?? '');
            echo '<script data-cfasync="false">';
            echo 'dndSetup(document.getElementById("overview-grid"),"?save_album_order=1",' . $csrf . ',"slug");';
            echo '</script>';
        }
    }
    echo '<div id="prep">Preparing&hellip;</div>';
    echo '<script data-cfasync="false">(function(){var p=document.getElementById("prep"),imgs=document.querySelectorAll(".tile img:not([loading=\'lazy\'])"),n=imgs.length;if(!n){p.classList.add("done");return;}var t=setTimeout(function(){p.classList.add("done");},2500);function check(){if(--n<=0){clearTimeout(t);p.classList.add("done");}}imgs.forEach(function(img){if(img.complete)check();else{img.addEventListener("load",check,{once:true});img.addEventListener("error",check,{once:true});}});})();(function(){document.querySelectorAll(".tile.thumb-pending img").forEach(function(img){function done(){img.closest(".tile").classList.remove("thumb-pending");}if(img.complete&&img.naturalWidth)done();else{img.addEventListener("load",done,{once:true});img.addEventListener("error",done,{once:true});}});})();(function(){function byView(a,b){var ar=a.getBoundingClientRect(),br=b.getBoundingClientRect(),av=ar.bottom>0&&ar.top<innerHeight,bv=br.bottom>0&&br.top<innerHeight;if(av!==bv)return av?-1:1;return ar.top-br.top||ar.left-br.left;}var q=Array.prototype.slice.call(document.querySelectorAll(".tile.thumb-pending[data-album][data-file]")).filter(function(tile){var img=tile.querySelector("img");return !!(img&&img.getAttribute("data-src"));}).sort(byView);function next(){var tile=q.shift();if(!tile)return;var img=tile.querySelector("img"),src=img&&img.getAttribute("data-src");if(!img||!src){next();return;}function done(){img.removeEventListener("load",done);img.removeEventListener("error",fail);setTimeout(next,80);}function fail(){img.removeEventListener("load",done);img.removeEventListener("error",fail);lbWarn("[Lightbox] overview thumbnail failed",tile.dataset.album,tile.dataset.file);setTimeout(next,250);}img.addEventListener("load",done,{once:true});img.addEventListener("error",fail,{once:true});img.setAttribute("loading","eager");img.setAttribute("fetchpriority","high");img.setAttribute("src",src);img.removeAttribute("data-src");}var seriesImgs=Array.prototype.slice.call(document.querySelectorAll(".series-strip img"));var left=seriesImgs.filter(function(img){return !(img.complete&&img.naturalWidth);}).length,started=false;function startQueue(){if(started)return;started=true;next();}if(left){var start=function(){if(--left<=0)startQueue();};seriesImgs.forEach(function(img){if(img.complete&&img.naturalWidth)return;img.addEventListener("load",start,{once:true});img.addEventListener("error",start,{once:true});});setTimeout(startQueue,1500);}else{startQueue();}})();</script>';
    echo '<script data-cfasync="false">lbInstallAnalytics({viewType:' . json_encode($show_all ? 'all' : 'home') . '});</script>';
    html_foot();
}

// ─── admin settings modal ────────────────────────────────────────────────────

function settings_modal(array $albs): void {
    $s    = load_settings();
    $csrf = htmlspecialchars($_SESSION['csrf'] ?? '');
    $d    = default_settings();
    $gap  = (int)($s['gap'] ?? $d['gap']);
    $cp   = (int)($s['content_padding'] ?? $d['content_padding']);
    $nf   = htmlspecialchars($s['nav_font_size'] ?? $d['nav_font_size']);
    $tf   = htmlspecialchars($s['tile_label_font_size'] ?? $d['tile_label_font_size']);
    $srg  = htmlspecialchars($s['series_row_gap'] ?? $d['series_row_gap']);
    $swd  = (int)($s['series_width_desktop'] ?? $d['series_width_desktop']);
    $spm  = (int)($s['series_padding_mobile'] ?? $d['series_padding_mobile']);
    $tq   = thumb_quality();
    $dle  = display_long_edge();
    $dq   = display_quality();
    $analytics_enabled = !empty($s['analytics_enabled']);
    $clean_urls = !empty($s['clean_urls']);
    $multi = multilingual_enabled();
    $st_raw = (string)($s['site_title'] ?? $d['site_title']);
    $st_en_raw = (string)($s['site_title_en'] ?? $d['site_title_en']);
    if (!$multi && $st_en_raw === '') $st_en_raw = $st_raw;
    $series_label_raw = (string)($s['series_label'] ?? $d['series_label']);
    $series_label_en_raw = (string)($s['series_label_en'] ?? $d['series_label_en']);
    if (!$multi && $series_label_en_raw === '') $series_label_en_raw = $series_label_raw;
    $all_photos_label_raw = (string)($s['all_photos_label'] ?? $d['all_photos_label']);
    $all_photos_label_en_raw = (string)($s['all_photos_label_en'] ?? $d['all_photos_label_en']);
    $share_label_raw = (string)($s['share_label'] ?? $d['share_label']);
    $share_label_en_raw = (string)($s['share_label_en'] ?? $d['share_label_en']);
    $copied_label_raw = (string)($s['copied_label'] ?? $d['copied_label']);
    $copied_label_en_raw = (string)($s['copied_label_en'] ?? $d['copied_label_en']);
    $album_label_raw = (string)($s['album_label'] ?? $d['album_label']);
    $album_label_en_raw = (string)($s['album_label_en'] ?? $d['album_label_en']);
    $albums_label_raw = (string)($s['albums_label'] ?? $d['albums_label']);
    $albums_label_en_raw = (string)($s['albums_label_en'] ?? $d['albums_label_en']);
    $source_label_raw = (string)($s['source_label'] ?? $d['source_label']);
    $source_label_en_raw = (string)($s['source_label_en'] ?? $d['source_label_en']);
    $sources_label_raw = (string)($s['sources_label'] ?? $d['sources_label']);
    $sources_label_en_raw = (string)($s['sources_label_en'] ?? $d['sources_label_en']);
    if (!$multi && $all_photos_label_en_raw === '') $all_photos_label_en_raw = $all_photos_label_raw;
    if (!$multi && $share_label_en_raw === '') $share_label_en_raw = $share_label_raw;
    if (!$multi && $copied_label_en_raw === '') $copied_label_en_raw = $copied_label_raw;
    if (!$multi && $album_label_en_raw === '') $album_label_en_raw = $album_label_raw;
    if (!$multi && $albums_label_en_raw === '') $albums_label_en_raw = $albums_label_raw;
    if (!$multi && $source_label_en_raw === '') $source_label_en_raw = $source_label_raw;
    if (!$multi && $sources_label_en_raw === '') $sources_label_en_raw = $sources_label_raw;
    $st    = htmlspecialchars($st_raw);
    $st_en = htmlspecialchars($st_en_raw);
    $series_label = htmlspecialchars($series_label_raw);
    $series_label_en = htmlspecialchars($series_label_en_raw);
    $all_photos_label = htmlspecialchars($all_photos_label_raw);
    $all_photos_label_en = htmlspecialchars($all_photos_label_en_raw);
    $share_label = htmlspecialchars($share_label_raw);
    $share_label_en = htmlspecialchars($share_label_en_raw);
    $copied_label = htmlspecialchars($copied_label_raw);
    $copied_label_en = htmlspecialchars($copied_label_en_raw);
    $album_label = htmlspecialchars($album_label_raw);
    $album_label_en = htmlspecialchars($album_label_en_raw);
    $albums_label = htmlspecialchars($albums_label_raw);
    $albums_label_en = htmlspecialchars($albums_label_en_raw);
    $source_label = htmlspecialchars($source_label_raw);
    $source_label_en = htmlspecialchars($source_label_en_raw);
    $sources_label = htmlspecialchars($sources_label_raw);
    $sources_label_en = htmlspecialchars($sources_label_en_raw);
    $pl_raw = primary_lang_label();
    $pl = htmlspecialchars($pl_raw);
    $lang_style = $multi ? '' : ' style="display:none"';
    $en_title_label = $multi ? 'Gallery Title (EN)' : 'Gallery Title';
    $en_series_label = $multi ? 'Series Heading (EN)' : 'Series Heading';
    $en_all_photos_label = $multi ? 'All Photos Link (EN)' : 'All Photos Link';
    $en_share_label = $multi ? 'Share Link (EN)' : 'Share Link';
    $en_copied_label = $multi ? 'Copied Feedback (EN)' : 'Copied Feedback';
    $en_album_label = $multi ? 'Album Prefix (EN)' : 'Album Prefix';
    $en_albums_label = $multi ? 'Albums Heading (EN)' : 'Albums Heading';
    $en_source_label = $multi ? 'Source Label (EN)' : 'Source Label';
    $en_sources_label = $multi ? 'Sources Label (EN)' : 'Sources Label';
    $raw_bg = $s['bg_color'] ?? $d['bg_color'];
    $bg   = in_array($raw_bg, ['#000', '#888', '#fff'], true) ? $raw_bg : $d['bg_color'];
    ?>
<div id="sm">
  <div id="sm-panel">
    <div id="sm-head"><span>General Settings</span><button onclick="settingsClose()">&#10005;</button></div>
    <div id="sm-body">
      <details id="sm-group-site" class="sm-group" data-default-open="1" open>
        <summary class="sm-section-head">Site</summary>
        <p class="sm-section-desc">Titles used in navigation, metadata, and optional language variants.</p>
        <div class="sm-row"><label class="sm-label">Version</label>
          <div class="sm-readonly"><?= htmlspecialchars(APP_VERSION) ?></div></div>
        <div class="sm-row"><label class="sm-label">Multilingual</label>
          <label class="sm-check"><input type="checkbox" id="sm-ml" value="1"<?= $multi ? ' checked' : '' ?> onchange="settingsLangToggle()"><span>Use two languages</span></label></div>
        <div class="sm-row sm-ml-row"<?= $lang_style ?>><label class="sm-label">Language Label</label>
          <input class="sm-input" id="sm-primary-lang-label" value="<?= $pl ?>" maxlength="16" oninput="settingsLangToggle()"></div>
        <div class="sm-row sm-primary-row"<?= $lang_style ?>><label class="sm-label" id="sm-title-primary-label">Gallery Title (<?= $pl ?>)</label>
          <input class="sm-input" id="sm-title" value="<?= $st ?>"></div>
        <div class="sm-row"><label class="sm-label" id="sm-title-en-label"><?= $en_title_label ?></label>
          <input class="sm-input" id="sm-title-en" value="<?= $st_en ?>"></div>
        <div class="sm-row sm-primary-row"<?= $lang_style ?>><label class="sm-label" id="sm-series-primary-label">Series Heading (<?= $pl ?>)</label>
          <input class="sm-input" id="sm-series-label" value="<?= $series_label ?>" maxlength="80"></div>
        <div class="sm-row"><label class="sm-label" id="sm-series-en-label"><?= $en_series_label ?></label>
          <input class="sm-input" id="sm-series-label-en" value="<?= $series_label_en ?>" maxlength="80"></div>
        <div class="sm-row sm-primary-row"<?= $lang_style ?>><label class="sm-label" id="sm-all-photos-primary-label">All Photos Link (<?= $pl ?>)</label>
          <input class="sm-input" id="sm-all-photos-label" value="<?= $all_photos_label ?>" maxlength="80"></div>
        <div class="sm-row"><label class="sm-label" id="sm-all-photos-en-label"><?= $en_all_photos_label ?></label>
          <input class="sm-input" id="sm-all-photos-label-en" value="<?= $all_photos_label_en ?>" maxlength="80"></div>
        <div class="sm-row sm-primary-row"<?= $lang_style ?>><label class="sm-label" id="sm-share-primary-label">Share Link (<?= $pl ?>)</label>
          <input class="sm-input" id="sm-share-label" value="<?= $share_label ?>" maxlength="80"></div>
        <div class="sm-row"><label class="sm-label" id="sm-share-en-label"><?= $en_share_label ?></label>
          <input class="sm-input" id="sm-share-label-en" value="<?= $share_label_en ?>" maxlength="80"></div>
        <div class="sm-row sm-primary-row"<?= $lang_style ?>><label class="sm-label" id="sm-copied-primary-label">Copied Feedback (<?= $pl ?>)</label>
          <input class="sm-input" id="sm-copied-label" value="<?= $copied_label ?>" maxlength="80"></div>
        <div class="sm-row"><label class="sm-label" id="sm-copied-en-label"><?= $en_copied_label ?></label>
          <input class="sm-input" id="sm-copied-label-en" value="<?= $copied_label_en ?>" maxlength="80"></div>
        <div class="sm-row sm-primary-row"<?= $lang_style ?>><label class="sm-label" id="sm-album-primary-label">Album Prefix (<?= $pl ?>)</label>
          <input class="sm-input" id="sm-album-label" value="<?= $album_label ?>" maxlength="80"></div>
        <div class="sm-row"><label class="sm-label" id="sm-album-en-label"><?= $en_album_label ?></label>
          <input class="sm-input" id="sm-album-label-en" value="<?= $album_label_en ?>" maxlength="80"></div>
        <div class="sm-row sm-primary-row"<?= $lang_style ?>><label class="sm-label" id="sm-albums-primary-label">Albums Heading (<?= $pl ?>)</label>
          <input class="sm-input" id="sm-albums-label" value="<?= $albums_label ?>" maxlength="80"></div>
        <div class="sm-row"><label class="sm-label" id="sm-albums-en-label"><?= $en_albums_label ?></label>
          <input class="sm-input" id="sm-albums-label-en" value="<?= $albums_label_en ?>" maxlength="80"></div>
        <div class="sm-row sm-primary-row"<?= $lang_style ?>><label class="sm-label" id="sm-source-primary-label">Source Label (<?= $pl ?>)</label>
          <input class="sm-input" id="sm-source-label" value="<?= $source_label ?>" maxlength="80"></div>
        <div class="sm-row"><label class="sm-label" id="sm-source-en-label"><?= $en_source_label ?></label>
          <input class="sm-input" id="sm-source-label-en" value="<?= $source_label_en ?>" maxlength="80"></div>
        <div class="sm-row sm-primary-row"<?= $lang_style ?>><label class="sm-label" id="sm-sources-primary-label">Sources Label (<?= $pl ?>)</label>
          <input class="sm-input" id="sm-sources-label" value="<?= $sources_label ?>" maxlength="80"></div>
        <div class="sm-row"><label class="sm-label" id="sm-sources-en-label"><?= $en_sources_label ?></label>
          <input class="sm-input" id="sm-sources-label-en" value="<?= $sources_label_en ?>" maxlength="80"></div>
      </details>
      <details id="sm-group-layout" class="sm-group" data-default-open="1" open>
        <summary class="sm-section-head">Layout</summary>
        <p class="sm-section-desc">Controls spacing and text sizes across the gallery. Changes take effect when you save and reload.</p>
        <div class="sm-row"><label class="sm-label">Thumbnail Gap (px)</label>
          <input class="sm-input" id="sm-gap" type="number" min="0" max="40" value="<?= $gap ?>"></div>
        <p class="sm-field-hint">Space between photos in the grid. 0 = no gap; 3–6 is a typical tight grid.</p>
        <div class="sm-row"><label class="sm-label">Content Padding L/R (px)</label>
          <input class="sm-input" id="sm-cp" type="number" min="0" max="80" value="<?= $cp ?>"></div>
        <p class="sm-field-hint">Left and right margin inside the page content area.</p>
        <div class="sm-row"><label class="sm-label">Nav Font Size</label>
          <input class="sm-input" id="sm-nf" value="<?= $nf ?>"></div>
        <p class="sm-field-hint">Size of navigation link text. Use CSS values like 1rem or 14px.</p>
        <div class="sm-row"><label class="sm-label">Album Label Font Size</label>
          <input class="sm-input" id="sm-tf" value="<?= $tf ?>"></div>
        <p class="sm-field-hint">Size of the caption text shown below each photo in the grid.</p>
        <div class="sm-row"><label class="sm-label">Description Font Size</label>
          <input class="sm-input" id="sm-dfs" value="<?= htmlspecialchars($s['desc_font_size'] ?? $d['desc_font_size']) ?>"></div>
        <p class="sm-field-hint">Size of album and series description text.</p>
        <div class="sm-row"><label class="sm-label">Series Image Gap</label>
          <input class="sm-input" id="sm-srg" value="<?= $srg ?>"></div>
        <p class="sm-field-hint">Gap between images in series and project overview pages. Use CSS values like 1rem.</p>
        <div class="sm-row"><label class="sm-label">Series Width Desktop (px)</label>
          <input class="sm-input" id="sm-swd" type="number" min="0" value="<?= $swd ?>"></div>
        <p class="sm-field-hint">Maximum content width for series and project pages on desktop screens.</p>
        <div class="sm-row"><label class="sm-label">Series Padding Mobile (px)</label>
          <input class="sm-input" id="sm-spm" type="number" min="0" value="<?= $spm ?>"></div>
        <p class="sm-field-hint">Left and right padding for series pages on phone-sized screens.</p>
      </details>
      <details id="sm-group-urls" class="sm-group" data-default-open="1" open>
        <summary class="sm-section-head">URLs & SEO</summary>
        <p class="sm-section-desc">Optional human-readable public links for series, albums, and shared photos.</p>
        <div class="sm-row"><label class="sm-label">Clean URLs</label>
          <label class="sm-check"><input type="checkbox" id="sm-clean-urls" value="1"<?= $clean_urls ? ' checked' : '' ?>><span>Use SEO clean URLs</span></label></div>
        <p class="sm-field-hint">Generates links such as <code>/series/name</code>, <code>/album/name</code>, and <code>/album/name/photo/photo-name</code>. On Apache-compatible servers, saving this setting writes or updates a marked Lightbox block in <code>.htaccess</code> when the gallery folder is writable. Query-string URLs keep working.</p>
      </details>
      <details id="sm-group-images" class="sm-group" data-default-open="1" open>
        <summary class="sm-section-head">Image Generation</summary>
        <p class="sm-section-desc">The gallery automatically creates two cached copies of each photo: a small thumbnail for the grid, and a larger display image for the lightbox. Your original photos are never modified. If you change the quality or size settings below, remove the existing cached images so they get regenerated with the new settings.</p>
        <div class="sm-row"><label class="sm-label">Thumb Quality</label>
          <input class="sm-input" id="sm-tq" type="number" min="40" max="100" value="<?= $tq ?>"></div>
        <p class="sm-field-hint">JPEG quality for grid thumbnails (1–100). 85 is a good default — lower saves bandwidth but makes thumbnails look worse.</p>
        <div class="sm-row"><label class="sm-label">Large Long Edge (px)</label>
          <input class="sm-input" id="sm-dle" type="number" min="800" max="8000" value="<?= $dle ?>"></div>
        <p class="sm-field-hint">Longest side of the lightbox display image in pixels. 2000 suits most screens; go higher for retina or large-monitor displays.</p>
        <div class="sm-row"><label class="sm-label">Large Quality</label>
          <input class="sm-input" id="sm-dq" type="number" min="40" max="100" value="<?= $dq ?>"></div>
        <p class="sm-field-hint">JPEG quality for lightbox images (1–100). Can be slightly lower than thumbnail quality since the images are already displayed at full resolution.</p>
        <p class="sm-section-desc" style="margin-top:18px">Thumbnails and display images are generated automatically when visitors browse your gallery, so you don't need to create them manually. Pre-generating them here just means the first visitor won't have to wait — a small improvement to their experience. If you run into display issues, you can delete the cached files and let them be rebuilt from scratch. Your original photos are never affected.</p>
        <div class="sm-img-btn-grid">
          <button class="sm-btn" onclick="smResetAllThumbs(this)"><?= icon_trash() ?>Remove All Thumbnails</button>
          <button class="sm-btn" onclick="smResetAllLarge(this)"><?= icon_trash() ?>Remove All Large Images</button>
          <button class="sm-btn" onclick="smGenAllThumbs(this)"><?= icon_rotate() ?>Generate Missing Thumbnails</button>
          <button class="sm-btn" onclick="smGenAllLarge(this)"><?= icon_rotate() ?>Generate Missing Large Images</button>
          <button class="sm-btn" onclick="smShowMissing('thumbs',this)"><?= icon_eye_open() ?>List Missing Thumbnails</button>
          <button class="sm-btn" onclick="smShowMissing('large',this)"><?= icon_eye_open() ?>List Missing Large Images</button>
        </div>
        <div id="sm-gen-progress" style="display:none;margin-top:12px">
          <div class="up-progress"><span id="sm-gen-bar"></span></div>
          <p class="sm-section-desc" id="sm-gen-status" style="margin-top:6px;margin-bottom:0"></p>
          <button class="sm-btn" id="sm-gen-stop" type="button" onclick="smStopGeneration()" style="margin-top:8px">Stop Generation</button>
        </div>
        <div id="sm-missing-list" style="display:none;margin-top:12px;max-height:200px;font-size:.72rem;line-height:1.7;font-family:monospace"></div>
      </details>
      <details id="sm-group-analytics" class="sm-group" data-default-open="1" open>
        <summary class="sm-section-head">Privacy & Analytics</summary>
        <p class="sm-section-desc">Local flat-file analytics. Stores anonymous visitor/session IDs, album/photo views, photo dwell time, and image load timing. No full IPs, user agents, cookies, or external services are logged.</p>
        <div class="sm-row"><label class="sm-label">Analytics</label>
          <label class="sm-check"><input type="checkbox" id="sm-analytics" value="1"<?= $analytics_enabled ? ' checked' : '' ?>><span>Collect anonymous local analytics</span></label></div>
        <p class="sm-field-hint">Data is stored in <code><?= htmlspecialchars(ANALYTICS_DIR) ?>/events-YYYY-MM-DD.jsonl</code> and <code><?= htmlspecialchars(ANALYTICS_DIR) ?>/image-loads-YYYY-MM-DD.jsonl</code>. To reset analytics, delete those JSONL files.</p>
      </details>
      <details id="sm-group-appearance" class="sm-group" data-default-open="1" open>
        <summary class="sm-section-head">Appearance</summary>
        <p class="sm-section-desc">Default gallery background used by public pages.</p>
        <div class="sm-row"><label class="sm-label">Background</label>
          <div class="bg-choice-row" role="radiogroup" aria-label="Background">
            <label class="bg-choice"><input type="radio" name="sm-bg" value="#000"<?= $bg === '#000' ? ' checked' : '' ?>><span class="bg-swatch bg-swatch-black" aria-hidden="true"></span><span>Black</span></label>
            <label class="bg-choice"><input type="radio" name="sm-bg" value="#888"<?= $bg === '#888' ? ' checked' : '' ?>><span class="bg-swatch bg-swatch-grey" aria-hidden="true"></span><span>Grey</span></label>
            <label class="bg-choice"><input type="radio" name="sm-bg" value="#fff"<?= $bg === '#fff' ? ' checked' : '' ?>><span class="bg-swatch bg-swatch-white" aria-hidden="true"></span><span>White</span></label>
          </div></div>
      </details>
      <button id="sm-save" onclick="settingsSave()">Save Settings</button>
    </div>
  </div>
</div>
<script data-cfasync="false">
var SM_CSRF=<?= json_encode($_SESSION['csrf'] ?? '') ?>;var LB_CSRF=SM_CSRF;var SM_ALBUMS=<?= json_encode(album_slugs_for_cache_reset()) ?>;
function settingsOpen(){document.getElementById('sm').classList.add('open');}
function settingsClose(){document.getElementById('sm').classList.remove('open');}
document.getElementById('sm').addEventListener('click',function(e){if(e.target===this)settingsClose();});
document.addEventListener('keydown',function(e){var smOpen=document.getElementById('sm').classList.contains('open');if(e.key==='Escape'&&smOpen){settingsClose();}if(e.key==='Enter'&&smOpen&&e.target.tagName!=='TEXTAREA'&&e.target.tagName!=='SELECT'&&e.target.tagName!=='SUMMARY'){settingsSave();}});
function settingsRestoreGroups(){
  document.querySelectorAll('#sm .sm-group[id]').forEach(function(group){
    var key='lb_settings_group_'+group.id;
    var saved=null;
    try{saved=localStorage.getItem(key);}catch(e){}
    if(saved==='open')group.open=true;
    else if(saved==='closed')group.open=false;
    else group.open=group.dataset.defaultOpen==='1';
    group.addEventListener('toggle',function(){
      try{localStorage.setItem(key,group.open?'open':'closed');}catch(e){}
    });
  });
}
settingsRestoreGroups();
function smPost(url,body){
  return fetch(url,{method:'POST',headers:{'X-CSRF-Token':SM_CSRF},body:body?new URLSearchParams(body):null});
}
function smCacheMessage(j){
  if(!j||j.ok)return '';
  var lines=[j.error||'Could not remove all generated files.'];
  if(j.deleted)lines.push('Removed generated images: '+j.deleted);
  if(j.deleted_meta)lines.push('Removed bookkeeping files: '+j.deleted_meta);
  if(j.failed_count)lines.push('Files that could not be removed: '+j.failed_count);
  if(j.unreadable_count)lines.push('Folders that could not be read: '+j.unreadable_count);
  if(j.hint)lines.push(j.hint);
  if(j.unreadable_directories&&j.unreadable_directories.length)lines.push('Unreadable folder: '+j.unreadable_directories[0]);
  if(j.failed_examples&&j.failed_examples.length){
    var ex=j.failed_examples[0];
    lines.push('Example file: '+ex.path);
    if(ex.metadata_file)lines.push('That example is a bookkeeping file, not a generated image.');
    lines.push('Folder writable: '+(ex.directory_writable?'yes':'no')+', file writable: '+(ex.file_writable?'yes':'no'));
  }
  return lines.join('\n');
}
function smRemovedMessage(j,label){
  var n=(j&&j.deleted)||0,meta=(j&&j.deleted_meta)||0;
  if(n)return 'Removed '+n+' ✓';
  if(meta)return 'No '+label+' found; cleaned '+meta+' index files ✓';
  return 'No '+label+' found ✓';
}
function smOk(btn,msg){
  var orig=btn.textContent;
  btn.textContent=msg||'Done ✓';btn.disabled=true;
  setTimeout(function(){btn.textContent=orig;btn.disabled=false;},2000);
}
function settingsLangToggle(){
  var ml=document.getElementById('sm-ml'),on=ml&&ml.checked;
  var lbl=document.getElementById('sm-primary-lang-label');
  var name=(lbl&&lbl.value.trim())||'DE';
  document.querySelectorAll('.sm-ml-row,.sm-primary-row').forEach(function(row){row.style.display=on?'':'none';});
  var primary=document.getElementById('sm-title-primary-label');
  if(primary)primary.textContent='Gallery Title ('+name+')';
  var en=document.getElementById('sm-title-en-label');
  if(en)en.textContent=on?'Gallery Title (EN)':'Gallery Title';
  var seriesPrimary=document.getElementById('sm-series-primary-label');
  if(seriesPrimary)seriesPrimary.textContent='Series Heading ('+name+')';
  var seriesEn=document.getElementById('sm-series-en-label');
  if(seriesEn)seriesEn.textContent=on?'Series Heading (EN)':'Series Heading';
  var allPhotosPrimary=document.getElementById('sm-all-photos-primary-label');
  if(allPhotosPrimary)allPhotosPrimary.textContent='All Photos Link ('+name+')';
  var allPhotosEn=document.getElementById('sm-all-photos-en-label');
  if(allPhotosEn)allPhotosEn.textContent=on?'All Photos Link (EN)':'All Photos Link';
  var sharePrimary=document.getElementById('sm-share-primary-label');
  if(sharePrimary)sharePrimary.textContent='Share Link ('+name+')';
  var shareEn=document.getElementById('sm-share-en-label');
  if(shareEn)shareEn.textContent=on?'Share Link (EN)':'Share Link';
  var copiedPrimary=document.getElementById('sm-copied-primary-label');
  if(copiedPrimary)copiedPrimary.textContent='Copied Feedback ('+name+')';
  var copiedEn=document.getElementById('sm-copied-en-label');
  if(copiedEn)copiedEn.textContent=on?'Copied Feedback (EN)':'Copied Feedback';
  var albumPrimary=document.getElementById('sm-album-primary-label');
  if(albumPrimary)albumPrimary.textContent='Album Prefix ('+name+')';
  var albumEn=document.getElementById('sm-album-en-label');
  if(albumEn)albumEn.textContent=on?'Album Prefix (EN)':'Album Prefix';
  var albumsPrimary=document.getElementById('sm-albums-primary-label');
  if(albumsPrimary)albumsPrimary.textContent='Albums Heading ('+name+')';
  var albumsEn=document.getElementById('sm-albums-en-label');
  if(albumsEn)albumsEn.textContent=on?'Albums Heading (EN)':'Albums Heading';
  var sourcePrimary=document.getElementById('sm-source-primary-label');
  if(sourcePrimary)sourcePrimary.textContent='Source Label ('+name+')';
  var sourceEn=document.getElementById('sm-source-en-label');
  if(sourceEn)sourceEn.textContent=on?'Source Label (EN)':'Source Label';
  var sourcesPrimary=document.getElementById('sm-sources-primary-label');
  if(sourcesPrimary)sourcesPrimary.textContent='Sources Label ('+name+')';
  var sourcesEn=document.getElementById('sm-sources-en-label');
  if(sourcesEn)sourcesEn.textContent=on?'Sources Label (EN)':'Sources Label';
}
function settingsSave(){
  var bg=document.querySelector('input[name="sm-bg"]:checked');
  var ml=document.getElementById('sm-ml');
  var siteTitle=document.getElementById('sm-title').value;
  var siteTitleEn=document.getElementById('sm-title-en').value;
  if(ml&&!ml.checked&&!siteTitle)siteTitle=siteTitleEn;
  var seriesLabel=document.getElementById('sm-series-label').value;
  var seriesLabelEn=document.getElementById('sm-series-label-en').value;
  if(ml&&!ml.checked&&!seriesLabel)seriesLabel=seriesLabelEn;
  var allPhotosLabel=document.getElementById('sm-all-photos-label').value;
  var allPhotosLabelEn=document.getElementById('sm-all-photos-label-en').value;
  var shareLabel=document.getElementById('sm-share-label').value;
  var shareLabelEn=document.getElementById('sm-share-label-en').value;
  var copiedLabel=document.getElementById('sm-copied-label').value;
  var copiedLabelEn=document.getElementById('sm-copied-label-en').value;
  var albumLabel=document.getElementById('sm-album-label').value;
  var albumLabelEn=document.getElementById('sm-album-label-en').value;
  var albumsLabel=document.getElementById('sm-albums-label').value;
  var albumsLabelEn=document.getElementById('sm-albums-label-en').value;
  var sourceLabel=document.getElementById('sm-source-label').value;
  var sourceLabelEn=document.getElementById('sm-source-label-en').value;
  var sourcesLabel=document.getElementById('sm-sources-label').value;
  var sourcesLabelEn=document.getElementById('sm-sources-label-en').value;
  if(ml&&!ml.checked&&!allPhotosLabel)allPhotosLabel=allPhotosLabelEn;
  if(ml&&!ml.checked&&!shareLabel)shareLabel=shareLabelEn;
  if(ml&&!ml.checked&&!copiedLabel)copiedLabel=copiedLabelEn;
  if(ml&&!ml.checked&&!albumLabel)albumLabel=albumLabelEn;
  if(ml&&!ml.checked&&!albumsLabel)albumsLabel=albumsLabelEn;
  if(ml&&!ml.checked&&!sourceLabel)sourceLabel=sourceLabelEn;
  if(ml&&!ml.checked&&!sourcesLabel)sourcesLabel=sourcesLabelEn;
  var b={
    site_title:siteTitle,
    site_title_en:siteTitleEn,
    series_label:seriesLabel,
    series_label_en:seriesLabelEn,
    all_photos_label:allPhotosLabel,
    all_photos_label_en:allPhotosLabelEn,
    share_label:shareLabel,
    share_label_en:shareLabelEn,
    copied_label:copiedLabel,
    copied_label_en:copiedLabelEn,
    album_label:albumLabel,
    album_label_en:albumLabelEn,
    albums_label:albumsLabel,
    albums_label_en:albumsLabelEn,
    source_label:sourceLabel,
    source_label_en:sourceLabelEn,
    sources_label:sourcesLabel,
    sources_label_en:sourcesLabelEn,
    multilingual:ml&&ml.checked?'1':'0',
    primary_lang_label:document.getElementById('sm-primary-lang-label').value,
    gap:document.getElementById('sm-gap').value,
    content_padding:document.getElementById('sm-cp').value,
    nav_font_size:document.getElementById('sm-nf').value,
    tile_label_font_size:document.getElementById('sm-tf').value,
    desc_font_size:document.getElementById('sm-dfs').value,
    series_row_gap:document.getElementById('sm-srg').value,
    series_width_desktop:document.getElementById('sm-swd').value,
    series_padding_mobile:document.getElementById('sm-spm').value,
    thumb_quality:document.getElementById('sm-tq').value,
    display_long_edge:document.getElementById('sm-dle').value,
    display_quality:document.getElementById('sm-dq').value,
    analytics_enabled:document.getElementById('sm-analytics').checked?'1':'0',
    clean_urls:document.getElementById('sm-clean-urls').checked?'1':'0',
    bg_color:bg?bg.value:'#fff'
  };
  var btn=document.getElementById('sm-save');
  smPost('?save_settings=1',b).then(function(r){return r.json().catch(function(){return {ok:r.ok};});}).then(function(j){
    if(j.ok){
      smOk(btn,j.warning?'Saved with warning':'Saved ✓');
      if(j.warning)alert(j.warning);
      setTimeout(function(){location.reload();},800);
    }else{
      alert((j&&j.error)||'Could not save settings.');
    }
  });
}
function smResetAllThumbs(btn){
  if(!confirm('Remove all generated thumbnails? Master images will not be removed and thumbnails will regenerate on demand.'))return;
  smPost('?reset_all_thumbs=1').then(function(r){return r.json().catch(function(){return {ok:r.ok};});}).then(function(j){if(j.ok){smOk(btn,smRemovedMessage(j,'thumbnails'));smShowMissing('thumbs');}else alert(smCacheMessage(j));});
}
function smResetAllLarge(btn){
  if(!confirm('Remove all generated large display images? Master images will not be removed and display images will regenerate on demand.'))return;
  smPost('?reset_all_large=1').then(function(r){return r.json().catch(function(){return {ok:r.ok};});}).then(function(j){if(j.ok){smOk(btn,smRemovedMessage(j,'large images'));smShowMissing('large');}else alert(smCacheMessage(j));});
}
var smGenJob=null;
function smStopGeneration(){
  if(!smGenJob)return;
  smGenJob.stopped=true;
  if(smGenJob.controller)smGenJob.controller.abort();
  if(smGenJob.scanTimer)clearInterval(smGenJob.scanTimer);
  if(smGenJob.type)smShowMissing(smGenJob.type);
  if(smGenJob.status)smGenJob.status.textContent='Stopped';
  if(smGenJob.btn)smGenJob.btn.disabled=false;
  var stop=document.getElementById('sm-gen-stop');
  if(stop)stop.disabled=true;
}
function smGenAll(type,btn){
  if(smGenJob&&!smGenJob.stopped)smStopGeneration();
  var albums=SM_ALBUMS,total=albums.length;
  if(!total)return;
  var prog=document.getElementById('sm-gen-progress');
  var bar=document.getElementById('sm-gen-bar');
  var status=document.getElementById('sm-gen-status');
  var stop=document.getElementById('sm-gen-stop');
  prog.style.display='';bar.style.width='0%';status.textContent='Starting…';btn.disabled=true;
  if(stop)stop.disabled=false;
  smGenJob={stopped:false,controller:null,btn:btn,status:status,type:type,scanTimer:null};
  smShowMissing(type);
  smGenJob.scanTimer=setInterval(function(){if(smGenJob&&!smGenJob.stopped&&smGenJob.type===type)smShowMissing(type);},3000);
  var done=0;
  function finish(msg,hide){
    status.textContent=msg;
    btn.disabled=false;
    if(stop)stop.disabled=true;
    if(smGenJob&&smGenJob.scanTimer)clearInterval(smGenJob.scanTimer);
    smShowMissing(type);
    if(smGenJob&&smGenJob.btn===btn)smGenJob=null;
    if(hide)setTimeout(function(){prog.style.display='none';},2500);
  }
  function nextAlbum(){
    if(!smGenJob||smGenJob.stopped){finish('Stopped',false);return;}
    if(done>=total){bar.style.width='100%';finish('Done ✓',true);return;}
    fetchBatch(albums[done],0,0,{});
  }
  function fetchBatch(album,cursor,stalled,seen){
    if(!smGenJob||smGenJob.stopped){finish('Stopped',false);return;}
    smGenJob.controller=new AbortController();
    var url=(type==='thumbs'?'?gen_thumbs=1':'?gen_large=1')+'&a='+encodeURIComponent(album)+'&cursor='+cursor+'&_='+(Date.now());
    fetch(url,{cache:'no-store',credentials:'same-origin',signal:smGenJob.controller.signal}).then(function(r){return r.json().then(function(d){if(!r.ok||d.ok===false)throw d;return d;});}).then(function(d){
      if(!smGenJob||smGenJob.stopped){finish('Stopped',false);return;}
      if(d.generated&&d.generated.length)status.textContent=album+' / '+d.generated[d.generated.length-1];
      else status.textContent=album;
      var key=[cursor,d.next_cursor||0,d.remaining,(d.generated||[]).join('|')].join(':');
      seen[key]=(seen[key]||0)+1;
      if(seen[key]>2){status.textContent=album+' / stopped: repeated batch response';done++;bar.style.width=Math.round(done/total*100)+'%';nextAlbum();return;}
      if(d.remaining>0&&(d.generated&&d.generated.length||stalled<1)){fetchBatch(album,d.next_cursor||0,(d.generated&&d.generated.length)?0:stalled+1,seen);}
      else{done++;bar.style.width=Math.round(done/total*100)+'%';nextAlbum();}
    }).catch(function(e){
      if(smGenJob&&smGenJob.stopped){finish('Stopped',false);return;}
      status.textContent=album+' / '+((e&&e.name==='AbortError')?'Stopped':((e&&e.error)||'generation failed'));
      done++;bar.style.width=Math.round(done/total*100)+'%';nextAlbum();
    });
  }
  nextAlbum();
}
function smGenAllThumbs(btn){smGenAll('thumbs',btn);}
function smGenAllLarge(btn){smGenAll('large',btn);}
var smMissingScanActive={};
function smShowMissing(type,btn){
  if(smMissingScanActive[type])return;
  smMissingScanActive[type]=true;
  var url=(type==='thumbs'?'?missing_thumbs=1':'?missing_large=1')+'&_='+(Date.now());
  var list=document.getElementById('sm-missing-list');
  var orig=btn?btn.textContent:'';
  if(btn){btn.disabled=true;btn.textContent='Scanning…';}
  fetch(url,{method:'POST',headers:{'X-CSRF-Token':SM_CSRF},cache:'no-store',credentials:'same-origin'}).then(function(r){return r.json().then(function(d){if(!r.ok||d.ok===false)throw d;return d;});}).then(function(d){
    if(btn){btn.disabled=false;btn.textContent=orig;}
    var results=d.results||{},albums=Object.keys(results);
    list.innerHTML='';
    if(!albums.length){
      var ok=document.createElement('div');ok.textContent=(type==='thumbs'?'All thumbnails present ✓':'All large images present ✓');ok.style.textAlign='center';list.appendChild(ok);
    } else {
      var total=document.createElement('div');total.textContent=(d.total_missing||0)+' missing across '+albums.length+' albums';total.style.fontWeight='bold';total.style.marginBottom='8px';list.appendChild(total);
      albums.forEach(function(album){
        var wrap=document.createElement('div');wrap.style.marginBottom='6px';
        var hd=document.createElement('div');
        hd.textContent=album+' ('+results[album].length+' missing)';
        hd.style.fontWeight='bold';wrap.appendChild(hd);
        results[album].forEach(function(f){
          var row=document.createElement('div');row.style.paddingLeft='10px';row.textContent=f;wrap.appendChild(row);
        });
        list.appendChild(wrap);
      });
    }
    list.style.display='';
  }).catch(function(e){if(btn){btn.disabled=false;btn.textContent=orig;}list.innerHTML='';var err=document.createElement('div');err.textContent=(e&&e.error)||'Could not scan generated files.';err.style.textAlign='center';list.appendChild(err);list.style.display='';})
    .finally(function(){smMissingScanActive[type]=false;});
}
</script>
    <?php
}

// ─── admin login page ─────────────────────────────────────────────────────────

function page_admin_password_setup(string $msg = ''): void {
    header('Cache-Control: no-store');
    $file = htmlspecialchars(admin_password_file());
    ?>
<!DOCTYPE html>
<html lang="<?= html_lang_attr() ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Create Admin Password</title>
<style>
@font-face{font-family:'Montserrat';font-style:normal;font-weight:400 700;font-display:swap;src:url('<?= htmlspecialchars(public_url('fonts/montserrat-latin.woff2')) ?>') format('woff2')}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:#000;color:#fff;font-family:'Montserrat',sans-serif;min-height:100%;display:flex;align-items:center;justify-content:center}
form{display:flex;flex-direction:column;gap:14px;width:min(520px,calc(100vw - 32px));padding:28px}
h1{font-size:1.25rem;letter-spacing:.12em;text-transform:uppercase}
p{font-size:1rem;line-height:1.55;opacity:.72;text-transform:none;letter-spacing:.02em}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9rem;background:#111;border:1px solid #333;padding:1px 4px;word-break:break-all}
input[type=password]{background:#111;border:1px solid #333;color:#fff;padding:13px 14px;font-size:1.08rem;outline:none;width:100%}
input[type=password]:focus{border-color:#666}
button{background:#fff;color:#000;border:none;padding:13px;font-size:.95rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;cursor:pointer}
button:hover{background:#ddd}
.setup-help{border-top:1px solid #222;margin-top:4px;padding-top:12px}
.setup-help summary{cursor:pointer;font-size:.9rem;font-weight:700;letter-spacing:.08em;text-transform:none;list-style:none;opacity:.86}
.setup-help summary::-webkit-details-marker{display:none}
.setup-help summary::before{content:'▶';display:inline-block;font-size:.72rem;margin-right:8px;transition:transform .18s}
.setup-help[open] summary::before{transform:rotate(90deg)}
.setup-help p{font-size:.86rem;margin-top:10px;opacity:.62}
.err{font-size:.9rem;letter-spacing:.08em;color:#f66;text-transform:uppercase}
</style>
</head>
<body>
<form method="post" action="<?= htmlspecialchars(admin_url()) ?>">
<h1>Create Admin Password</h1>
<p>This first-run password protects the gallery admin tools. Use a long, unique password.</p>
<?php if ($msg): ?><span class="err"><?= htmlspecialchars($msg) ?></span><?php endif ?>
<input type="password" name="pass" autofocus autocomplete="new-password" placeholder="New password">
<input type="password" name="pass2" autocomplete="new-password" placeholder="Repeat password">
<button type="submit">Save Password</button>
<details class="setup-help">
<summary>New here? What this password does</summary>
<p>The password lets you open the gallery admin tools later. It is not stored as readable text; Lightbox saves only a one-way hash in <code><?= $file ?></code>.</p>
<p>Advanced setup: you can set <code>LIGHTBOX_ADMIN_PASSWORD_FILE</code> to a path outside the public web folder, for example <code>/var/www/private/lightbox-admin-password.php</code>. Make that folder writable for first setup, then keep the file at mode <code>600</code>.</p>
</details>
</form>
</body>
</html>
    <?php
}

function page_login(bool $failed = false, string $msg = ''): void {
    header('Cache-Control: no-store');
    ?>
<!DOCTYPE html>
<html lang="<?= html_lang_attr() ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin</title>
<style>
@font-face{font-family:'Montserrat';font-style:normal;font-weight:400 700;font-display:swap;src:url('<?= htmlspecialchars(public_url('fonts/montserrat-latin.woff2')) ?>') format('woff2')}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:#000;color:#fff;font-family:'Montserrat',sans-serif;height:100%;display:flex;align-items:center;justify-content:center}
form{display:flex;flex-direction:column;gap:14px;width:min(320px,calc(100vw - 32px))}
input[type=password]{background:#111;border:1px solid #333;color:#fff;padding:13px 14px;font-size:1.08rem;outline:none;width:100%}
input[type=password]:focus{border-color:#666}
button{background:#fff;color:#000;border:none;padding:13px;font-size:.95rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;cursor:pointer}
button:hover{background:#ddd}
.err{font-size:.9rem;letter-spacing:.08em;color:#f66;text-transform:uppercase}
</style>
</head>
<body>
<form method="post" action="<?= htmlspecialchars(admin_url()) ?>">
<?php if ($msg): ?><span class="err"><?= htmlspecialchars($msg) ?></span><?php elseif ($failed): ?><span class="err">Wrong password</span><?php endif ?>
<input type="password" name="pass" autofocus placeholder="Password">
<button type="submit">Enter</button>
</form>
</body>
</html>
    <?php
}

function page_album(string $album, array $cfg, array $imgs, ?string $share_image = null): void {
    $base  = base_url();
    $site_title = site_title_text();
    $default_name = default_album_name($album);
    $name  = lf($cfg + ['name' => $default_name, 'name_en' => ''], 'name') ?: $default_name;
    $hero  = resolve_hero($album, $cfg, $imgs);
    $meta_image = ($share_image && in_array($share_image, $imgs, true)) ? $share_image : $hero;
    $is_image_share = $share_image !== null && $meta_image === $share_image;
    $title = $name . ' — ' . $site_title;
    $album_desc = lf($cfg + ['description' => '', 'description_en' => ''], 'description');
    $desc = $is_image_share
        ? 'Photo from ' . $name . '. ' . ($album_desc !== '' ? $album_desc : count($imgs) . ' photos in this album.')
        : ($album_desc !== '' ? $album_desc : 'Album: ' . $name . '. ' . count($imgs) . ' photos.');
    $og_image_abs = og_image_url($album, $meta_image);
    $canonical_url = $is_image_share ? canonical_image_url($album, $meta_image) : canonical_album_url($album);

    $jsonld = json_encode([
        '@context'         => 'https://schema.org',
        '@type'            => 'CollectionPage',
        'name'             => $title,
        'description'      => $desc,
        'url'              => $canonical_url,
        'primaryImageOfPage' => ['@type' => 'ImageObject', 'url' => $og_image_abs],
    ], JSON_UNESCAPED_SLASHES);

    html_head($title, $desc, $og_image_abs, $canonical_url);
    echo '<script type="application/ld+json">' . $jsonld . '</script>';
    $admin_early = is_admin();
    $icon_expand   = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 16 16"><path fill="currentColor" fill-rule="evenodd" d="M7.754 2.004a.75.75 0 0 0 0 1.5h4.75v4.742a.75.75 0 0 0 1.5 0V2.754a.75.75 0 0 0-.75-.75zm.492 11.992a.75.75 0 0 0 0-1.5h-4.75V7.754a.75.75 0 0 0-1.5 0v5.492a.75.75 0 0 0 .75.75z" clip-rule="evenodd"/></svg>';
    $icon_collapse = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 16 16"><path fill="currentColor" fill-rule="evenodd" d="M15.25 6.993a.75.75 0 0 0 0-1.5H10.5V.75a.75.75 0 1 0-1.5 0v5.493c0 .414.336.75.75.75zM.75 9.007a.75.75 0 1 0 0 1.5H5.5v4.743a.75.75 0 0 0 1.5 0V9.757a.75.75 0 0 0-.75-.75z" clip-rule="evenodd"/></svg>';
    echo '<nav class="nav" id="page-nav">';
    $_pa_st = site_title_html();
    echo '<a class="nav-back" href="' . htmlspecialchars(all_photos_url()) . '"><span class="nav-title">' . $_pa_st . '</span></a>';
    echo nav_tools_html($canonical_url, $title, $is_image_share ? 'photo' : 'album', $album, $is_image_share ? $meta_image : '');
    echo '</nav>';
    if ($admin_early) {
        admin_bar_html();
        settings_modal(albums());
        $multi = multilingual_enabled();
        $pl = htmlspecialchars(primary_lang_label());
        $primary_style = $multi ? '' : ' style="display:none"';
        $album_en_label = $multi ? 'Album Name (EN)' : 'Album Name';
        $desc_en_label = $multi ? 'Description (EN)' : 'Description';
        $name_raw = (string)($cfg['name'] ?? $default_name);
        $name_en_raw = (string)($cfg['name_en'] ?? '');
        $desc_raw = (string)($cfg['description'] ?? '');
        $desc_en_raw = (string)($cfg['description_en'] ?? '');
        if (!$multi && $name_en_raw === '') $name_en_raw = $name_raw;
        if (!$multi && $desc_en_raw === '') $desc_en_raw = $desc_raw;
        $esc_name    = htmlspecialchars($name_raw, ENT_QUOTES);
        $esc_name_en = htmlspecialchars($name_en_raw, ENT_QUOTES);
        $esc_desc    = htmlspecialchars($desc_raw, ENT_QUOTES);
        $esc_desc_en = htmlspecialchars($desc_en_raw, ENT_QUOTES);
        echo '<div id="an-modal"><div id="an-box"><p class="an-label"' . $primary_style . '>Album Name (' . $pl . ')</p>';
        echo '<input id="an-input" type="text" value="' . $esc_name . '"' . $primary_style . '>';
        echo '<p class="an-label" style="margin-top:10px">' . $album_en_label . '</p>';
        echo '<input id="an-input-en" type="text" value="' . $esc_name_en . '" placeholder="English title">';
        echo '<p class="an-label" style="margin-top:10px' . ($multi ? '' : ';display:none') . '">Description (' . $pl . ')</p>';
        echo '<textarea id="an-desc" rows="2" placeholder="Short description"' . $primary_style . '>' . $esc_desc . '</textarea>';
        echo '<p class="an-label" style="margin-top:10px">' . $desc_en_label . '</p>';
        echo '<textarea id="an-desc-en" rows="2" placeholder="English description">' . $esc_desc_en . '</textarea>';
        $an_captions_checked = ($cfg['captions'] ?? '') === '1' ? ' checked' : '';
        echo '<label class="sm-check" style="margin-top:14px;display:inline-flex"><input type="checkbox" id="an-captions" value="1"' . $an_captions_checked . '> Display captions in lightbox</label>';
        echo '<div class="an-btns"><button class="an-delete" onclick="anDelete()">Delete Album</button><button onclick="anClose()">Cancel</button><button class="an-save" onclick="anSave()">Save</button></div>';
        echo '</div></div>';
    }
    $_adesc_de = $cfg['description'] ?? '';
    $_adesc_en = $cfg['description_en'] ?? '';
    $_has_desc = $_adesc_de || $_adesc_en;
    echo '<div class="album-h1-row' . ($_has_desc ? '' : ' album-h1-row--nodesc') . '">';
    $_album_label_de = trim((string)(load_settings()['album_label'] ?? 'Album')) ?: 'Album';
    $_album_label_en = trim((string)(load_settings()['album_label_en'] ?? $_album_label_de)) ?: $_album_label_de;
    echo '<h1 class="album-h1">' . bi($_album_label_de . ': ' . ($cfg['name'] ?? $default_name), $_album_label_en . ': ' . (($cfg['name_en'] ?? '') ?: ($cfg['name'] ?? $default_name))) . '</h1>';
    if ($admin_early) {
        echo '<button class="nav-edit" onclick="anOpen()" title="Album settings">Album Settings</button>';
        echo '<a class="nav-edit" href="?caption_editor=' . rawurlencode($album) . '" title="Batch caption editor">Create Captions</a>';
        echo '<button class="nav-edit" id="series-selection-toggle" onclick="seriesModeToggle()" title="Series Selection Mode">SERIES SELECT MODE OFF</button>';
    }
    echo '</div>';
    if ($_has_desc) {
        echo '<div class="album-desc">' . bi($_adesc_de, $_adesc_en) . '</div>';
    }

    $admin    = is_admin();
    $hero_img = resolve_hero($album, $cfg, $imgs);
    $missing_thumbs = [];
    foreach ($imgs as $img) {
        if (!thumb_current($album, $img)) {
            $missing_thumbs[$img] = true;
        }
    }
    $has_missing = !empty($missing_thumbs);
    $series_data = $admin ? load_series() : [];
    $series_choices = [];
    if ($admin) {
        foreach (SERIES_IDS as $sid) {
            if (series_has_admin_content($series_data[$sid] ?? [])) $series_choices[$sid] = $series_data[$sid];
        }
        if (!$series_choices) {
            echo '<div class="series-empty-hint">Create a series from the admin bar, then use Series Selection Mode to add images from this album.</div>';
        }
        echo '<div class="se-add-note admin-grid-hint">Drag and drop images to change their order. The star icon determines the album hero image.</div>';
    }
    echo '<div class="album-aspect-row"><button class="nav-toggle" id="aspect-toggle" onclick="aspectToggle()" title="Toggle aspect ratio"><span id="aspect-icon-sq">' . $icon_collapse . '</span><span id="aspect-icon-ar" style="display:none">' . $icon_expand . '</span></button></div>';
    echo '<main class="grid" id="gallery">';
    foreach ($imgs as $idx => $img) {
        $turl      = htmlspecialchars(thumb_url_ar($album, $img));
        $is_hero   = ($img === $hero_img);
        $drag      = $admin ? ' draggable="true"' : '';
        $is_pending = isset($missing_thumbs[$img]);
        $pcls      = $is_pending ? ' thumb-pending' : '';
        $load_attr = 'loading="lazy"';
        $img_attr = $is_pending ? 'data-src="' . $turl . '"' : 'src="' . $turl . '"';
        echo '<button class="tile' . $pcls . '" data-idx="' . $idx . '" data-file="' . htmlspecialchars($img) . '" onclick="lb(' . $idx . ')" aria-label="' . htmlspecialchars($img) . '"' . $drag . '>';
        $_cap = caption_pair($album, $img);
        $_alt = htmlspecialchars(lf(['caption' => $_cap['de'], 'caption_en' => $_cap['en']], 'caption'), ENT_QUOTES);
        echo '<img ' . $img_attr . ' alt="' . $_alt . '" draggable="false" ' . $load_attr . '>';
        if ($admin) {
            $star = $is_hero ? '&#9733;' : '&#9734;';
            echo '<span class="admin-star' . ($is_hero ? ' is-hero' : '') . '" data-file="' . htmlspecialchars($img) . '" onclick="setHero(this,event)">' . $star . '</span>';
            echo '<div class="series-checks" onclick="event.stopPropagation()">';
            foreach ($series_choices as $sid => $sitem) {
                $in = in_array($album . '/' . $img, $sitem['images'] ?? [], true);
                $_sc_label = series_title_value($sitem, 'Untitled Series');
                $_sc_tip = htmlspecialchars($_sc_label, ENT_QUOTES);
                $_sc_data = htmlspecialchars($_sc_label, ENT_QUOTES);
                echo '<label class="sc-label" title="' . $_sc_tip . '"><input type="checkbox" class="sc-cb" data-series="' . $sid . '" data-series-name="' . $_sc_data . '" data-album="' . htmlspecialchars($album) . '" data-file="' . htmlspecialchars($img) . '"' . ($in ? ' checked' : '') . '> <span>' . htmlspecialchars($_sc_label) . '</span></label>';
            }
            echo '</div>';
        }
        echo '</button>';
    }
    echo '</main>';
    if ($admin) echo '<div id="series-toast" role="status" aria-live="polite"></div>';

    // Image URLs for lightbox (JSON arrays)
    $img_urls = array_map(fn(string $f) => image_url($album, $f), $imgs);
    $thumb_urls = array_map(fn(string $f) => thumb_url_ar($album, $f), $imgs);
    $share_urls = array_map(fn(string $f) => canonical_image_url($album, $f), $imgs);
    $meta_image_urls = array_map(fn(string $f) => og_image_url($album, $f), $imgs);
    $share_index = $share_image !== null ? array_search($share_image, $imgs, true) : false;
    echo '<div id="lb" role="dialog" aria-modal="true"' . ($admin ? ' class="lb-admin"' : '') . '>';
    echo '<span id="lb-close" onclick="lbClose()" title="Close (Esc)" role="button" aria-label="Close lightbox">' . icon_arrow_left() . '</span>';
    echo '<span id="lb-prev" onclick="lbMove(-1)" title="Previous">&#8249;</span>';
    echo '<img id="lb-img" src="" alt="" draggable="false">';
    echo '<div id="lb-caption" style="display:none"></div>';
    if ($admin) { caption_editor_html(); }
    echo '<span id="lb-next" onclick="lbMove(1)" title="Next">&#8250;</span>';
    echo '<button id="lb-share" class="share-link" type="button" onclick="lbShareCurrent()">' . htmlspecialchars(share_label_text()) . '</button>';
    echo '<span id="lb-counter"></span>';
    echo '</div>';

    echo '<script data-cfasync="false">';
    echo 'var ALBUM=' . json_encode($album, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var FILES=' . json_encode($imgs, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var IMGS=' . json_encode($img_urls, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var THUMBS=' . json_encode($thumb_urls, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var SHARE_URLS=' . json_encode($share_urls, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var META_IMAGE_URLS=' . json_encode($meta_image_urls, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var SHARE_INDEX=' . ($share_index === false ? '-1' : (string)(int)$share_index) . ';';
    echo 'var CAPTIONS=' . json_encode(array_map(fn(string $f) => caption_html($album, $f), $imgs), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ';';
    echo 'var ALTS=' . json_encode(array_map(function(string $f) use ($album) { $p = caption_pair($album, $f); return lf(['caption' => $p['de'], 'caption_en' => $p['en']], 'caption'); }, $imgs), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ';';
    echo 'var CAPTIONS_DATA=' . json_encode(array_map(fn(string $f) => caption_pair($album, $f), $imgs), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ';';
    echo 'var LB_CAPTIONS_ON=' . (($cfg['captions'] ?? '') === '1' ? 'true' : 'false') . ';';
    echo 'var ALBUM_PAGE_URL=' . json_encode(album_url($album), JSON_UNESCAPED_SLASHES) . ';';
    echo 'var ALBUM_BACK_URL=' . json_encode(isset($_GET['from']) && $_GET['from'] === 'all' ? all_photos_url() : public_url(), JSON_UNESCAPED_SLASHES) . ';';
    echo 'var LARGE_GEN_URL=' . json_encode(public_url('?gen_large=1'), JSON_UNESCAPED_SLASHES) . ';';
    echo 'var cur=0;';
    echo 'lbInstallAnalytics({viewType:"album",album:ALBUM,albumTitle:' . json_encode($name, JSON_UNESCAPED_SLASHES) . ',files:FILES,currentPhoto:function(){return FILES[cur]||"";}});';
    echo <<<'JS'
var largeQueue=[],largeActive=false,largeReady={};
function queueLarge(i,show){
  if(i<0||i>=IMGS.length)return;
  if(largeReady[i]){if(show)showLarge(i);return;}
  largeQueue=largeQueue.filter(function(j){return j.i!==i;});
  var job={i:i,show:!!show};
  if(show)largeQueue.unshift(job);else largeQueue.push(job);
  pumpLargeQueue();
}
function pumpLargeQueue(){
  if(largeActive)return;
  var job=largeQueue.shift();
  if(!job)return;
  largeActive=true;
  var url=LARGE_GEN_URL+'&a='+encodeURIComponent(ALBUM)+'&f='+encodeURIComponent(FILES[job.i]);
  lbDebug('[Lightbox] generating large image',url);
  fetch(url,{cache:'no-store',credentials:'same-origin'}).then(function(r){
    lbDebug('[Lightbox] large generation response',r.status,r.statusText);
    if(!r.ok)return r.text().then(function(t){throw new Error(t||('HTTP '+r.status));});
    return r.json();
  }).then(function(data){
    if(data.ok!==false){
      largeReady[job.i]=true;
      if(job.show&&cur===job.i)showLarge(job.i);
      else lbPreloadLarge(job.i);
    }
  }).catch(function(e){lbWarn('[Lightbox] large generation failed',FILES[job.i],e);})
    .finally(function(){largeActive=false;setTimeout(pumpLargeQueue,80);});
}
lbInstallLightbox();
JS;
    echo '</script>';

    if ($admin) {
        $csrf = $_SESSION['csrf'] ?? '';
        $alb_js = json_encode($album, JSON_UNESCAPED_SLASHES);
        echo '<script data-cfasync="false">';
        echo 'var CTX_ALBUM=' . $alb_js . ';';
        echo 'var CTX_CSRF=' . json_encode($csrf) . ';';
        echo 'var CTX_ALBUM_NAME=' . json_encode($name, JSON_UNESCAPED_SLASHES) . ';';
        echo 'var PUBLIC_ALL_URL=' . json_encode(all_photos_url(), JSON_UNESCAPED_SLASHES) . ';';
        echo 'var AN_MULTI=' . (multilingual_enabled() ? 'true' : 'false') . ';';
        echo 'var AN_CAPTIONS_ON=' . (($cfg['captions'] ?? '') === '1' ? 'true' : 'false') . ';';
        echo 'var CAPTIONS_API=' . (caption_api_key() !== null ? 'true' : 'false') . ';';
        echo 'dndSetup(document.getElementById("gallery"),"?save_image_order=1&a="+encodeURIComponent(CTX_ALBUM),' . json_encode($csrf) . ',"file");';
        echo <<<'JS'
function setHero(el,e){
  e.stopPropagation();
  fetch('?set_hero=1&a='+encodeURIComponent(CTX_ALBUM)+'&f='+encodeURIComponent(el.dataset.file),{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'csrf='+encodeURIComponent(CTX_CSRF)
  }).then(function(r){if(r.ok)location.reload();});
}
function anOpen(){document.getElementById('an-modal').classList.add('open');document.getElementById('an-captions').checked=AN_CAPTIONS_ON;var inp=document.getElementById(AN_MULTI?'an-input':'an-input-en');inp.focus();inp.select();var kh=function(e){if(e.key==='Enter')anSave();if(e.key==='Escape')anClose();};var ek=function(e){if(e.key==='Escape')anClose();};document.getElementById('an-input').onkeydown=kh;document.getElementById('an-input-en').onkeydown=kh;document.getElementById('an-desc').onkeydown=ek;document.getElementById('an-desc-en').onkeydown=ek;}
function anClose(){document.getElementById('an-modal').classList.remove('open');}
function anSave(){
  var name=document.getElementById('an-input').value.trim();
  var name_en=document.getElementById('an-input-en').value.trim();
  var desc=document.getElementById('an-desc').value.trim();
  var desc_en=document.getElementById('an-desc-en').value.trim();
  var captions=document.getElementById('an-captions').checked?'1':'0';
  if(AN_MULTI){if(!name)return;}else{if(!name_en)return;if(!name)name=name_en;if(!desc)desc=desc_en;}
  fetch('?save_album_name=1&a='+encodeURIComponent(CTX_ALBUM),{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'name='+encodeURIComponent(name)+'&name_en='+encodeURIComponent(name_en)+'&description='+encodeURIComponent(desc)+'&description_en='+encodeURIComponent(desc_en)+'&captions='+captions+'&csrf='+encodeURIComponent(CTX_CSRF)
  }).then(function(r){if(r.ok)location.reload();});
}
function anDelete(){
  var label=CTX_ALBUM_NAME||CTX_ALBUM;
  if(!confirm('WARNING: Delete album "'+label+'"? Uploaded images will be deleted before removing the album folder.'))return;
  if(!confirm('FINAL WARNING: Uploaded images in "'+label+'" will be permanently deleted before the album folder is removed. This cannot be undone.'))return;
  fetch('?delete_album=1&a='+encodeURIComponent(CTX_ALBUM),{
    method:'POST',
    headers:{'X-CSRF-Token':CTX_CSRF},
    body:new URLSearchParams({confirm:'DELETE_UPLOADED_IMAGES'})
  }).then(function(r){if(r.ok)location.href=PUBLIC_ALL_URL;else alert('Could not delete this album.');});
}
document.getElementById('an-modal').addEventListener('click',function(e){if(e.target===this)anClose();});
// series checkboxes
var seriesToastTimer=null;
function showSeriesToast(msg){
  var t=document.getElementById('series-toast');
  if(!t)return;
  t.textContent=msg;
  clearTimeout(seriesToastTimer);
  t.classList.remove('show');
  void t.offsetWidth;
  t.classList.add('show');
  seriesToastTimer=setTimeout(function(){t.classList.remove('show');},1000);
}
document.querySelectorAll('.sc-cb').forEach(function(cb){
  cb.addEventListener('change',function(e){
    e.stopPropagation();
    var checked=cb.checked;
    cb.disabled=true;
    fetch('?assign_series=1',{method:'POST',headers:{'X-CSRF-Token':CTX_CSRF},body:new URLSearchParams({id:cb.dataset.series,a:cb.dataset.album,f:cb.dataset.file,checked:checked?'1':'0'})})
      .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json().catch(function(){return {ok:true};});})
      .then(function(j){
        if(j.ok===false)throw new Error(j.error||'Series update failed');
        showSeriesToast('image '+(checked?'added to ':'removed from ')+(cb.dataset.seriesName||'series'));
      })
      .catch(function(err){
        cb.checked=!checked;
        lbWarn('[Lightbox] series assignment failed',err);
        showSeriesToast('could not update series');
      })
      .finally(function(){cb.disabled=false;});
  });
});
// series selection mode: apply saved state
(function(){var on=localStorage.getItem('lb_series_mode')==='1';var g=document.getElementById('gallery');if(g)g.classList.toggle('series-mode',on);if(typeof seriesModeLabel==='function')seriesModeLabel(on);})();
JS;
        caption_editor_js();
        echo '</script>';
    }

    echo '<script data-cfasync="false">';
    echo '(function(){document.querySelectorAll("#gallery .tile img").forEach(function(img){function finish(ok){var tile=img.closest(".tile");if(ok){var nw=img.naturalWidth,nh=img.naturalHeight;if(nw&&nh){img.dataset.scale=(Math.max(nw,nh)/Math.min(nw,nh)).toFixed(4);}if(!window._arMode)img.style.transform=img.dataset.scale?"scale("+img.dataset.scale+")":"";}else{lbWarn("[Lightbox] album image failed",img.currentSrc||img.src);}tile.classList.add("loaded");tile.classList.remove("thumb-pending");}if(img.complete&&img.naturalWidth)finish(true);else{img.addEventListener("load",function(){finish(true);});img.addEventListener("error",function(){finish(false);});}});})();';
    if ($has_missing) {
        echo 'var ALBUM_THUMB_GEN_URL="?gen_thumbs=1&a="+encodeURIComponent(' . json_encode($album, JSON_UNESCAPED_SLASHES) . ');';
        echo <<<'JS'
(function(){
  function byView(a,b){
    var ar=a.getBoundingClientRect(),br=b.getBoundingClientRect();
    var av=ar.bottom>0&&ar.top<innerHeight,bv=br.bottom>0&&br.top<innerHeight;
    if(av!==bv)return av?-1:1;
    return ar.top-br.top||ar.left-br.left;
  }
  var queue=Array.prototype.slice.call(document.querySelectorAll('#gallery .tile.thumb-pending[data-file]')).filter(function(tile){
    var img=tile.querySelector('img');
    return !!(img&&img.getAttribute('data-src'));
  }).sort(byView);
  var batchSize=5;
  function loadTile(tile,doneBatch){
    var img=tile.querySelector('img');
    var src=img&&img.getAttribute('data-src');
    var file=tile.dataset.file||'';
    if(!img||!src||!file){doneBatch();return;}
    lbDebug('[Lightbox] loading thumbnail',src);
    function done(ok){
      img.removeEventListener('load',onload);
      img.removeEventListener('error',onerror);
      if(!ok)lbWarn('[Lightbox] thumbnail load failed',file);
      doneBatch();
    }
    function onload(){done(true);}
    function onerror(){done(false);}
    img.addEventListener('load',onload,{once:true});
    img.addEventListener('error',onerror,{once:true});
    try{
      img.setAttribute('loading','eager');
      img.setAttribute('fetchpriority','high');
      img.setAttribute('src',src);
      img.removeAttribute('data-src');
    }catch(e){
      lbWarn('[Lightbox] thumbnail generation failed',file,e);
      doneBatch();
    }
  }
  function finishServerThumbs(cursor,stalled){
    fetch(ALBUM_THUMB_GEN_URL+'&limit=12&cursor='+(cursor||0),{cache:'no-store',credentials:'same-origin'}).then(function(r){
      return r.json();
    }).then(function(d){
      if(d.remaining>0&&(d.generated&&d.generated.length||stalled<1)){
        setTimeout(function(){finishServerThumbs(d.next_cursor||0,(d.generated&&d.generated.length)?0:stalled+1);},80);
        return;
      }
      document.querySelectorAll('#gallery .tile.thumb-pending img[data-src]').forEach(function(img){
        img.setAttribute('loading','eager');
        img.setAttribute('fetchpriority','high');
        img.setAttribute('src',img.getAttribute('data-src'));
        img.removeAttribute('data-src');
      });
    }).catch(function(e){lbWarn('[Lightbox] thumbnail generator failed',e);});
  }
  function nextBatch(){
    if(!queue.length){finishServerThumbs(0,0);return;}
    var batch=queue.splice(0,batchSize),left=batch.length,settled=false;
    function doneBatch(){
      if(settled)return;
      if(--left<=0){
        settled=true;
        setTimeout(nextBatch,80);
      }
    }
    batch.forEach(function(tile){loadTile(tile,doneBatch);});
    setTimeout(function(){
      if(!settled){
        settled=true;
        nextBatch();
      }
    },5000);
  }
  nextBatch();
  setTimeout(function(){finishServerThumbs(0,0);},1500);
})();
JS;
    }
    echo <<<'JS'
(function(){
  var KEY='lb_ar_mode';
  var ar=localStorage.getItem(KEY)==='1';
  window._arMode=ar;
  var si=document.getElementById('aspect-icon-sq');
  var ai=document.getElementById('aspect-icon-ar');
  function setIcons(a){si.style.display=a?'none':'';ai.style.display=a?'':'none';}
  setIcons(ar);
  // On init (no animation): fix any already-loaded images
  document.querySelectorAll('#gallery .tile img').forEach(function(img){
    img.style.transform=ar?'':img.dataset.scale?'scale('+img.dataset.scale+')':'';
  });
  window.aspectToggle=function(){
    ar=!ar;
    window._arMode=ar;
    localStorage.setItem(KEY,ar?'1':'0');
    setIcons(ar);
    document.querySelectorAll('#gallery .tile img').forEach(function(img){
      var s=img.dataset.scale||'1';
      img.style.transition='transform .35s ease-in-out';
      img.style.transform=ar?'scale(1)':'scale('+s+')';
    });
  };
})();
JS;
    echo '</script>';

    html_foot();
}

// ─── series helpers ───────────────────────────────────────────────────────────

function load_series(): array {
    static $c = null;
    if ($c !== null) return $c;
    $defaults = [];
    foreach (SERIES_IDS as $sid) $defaults[$sid] = empty_series_record();
    if (!is_file(SERIES_FILE)) return $c = $defaults;
    $d = @json_decode((string)file_get_contents(SERIES_FILE), true);
    if (!is_array($d)) return $c = $defaults;
    foreach ($defaults as $sid => $def) {
        if (!isset($d[$sid]) || !is_array($d[$sid])) { $d[$sid] = $def; continue; }
        $d[$sid] = array_merge($def, $d[$sid]);
        if (!is_array($d[$sid]['images'])) $d[$sid]['images'] = [];
    }
    return $c = $d;
}

function empty_series_record(): array {
    return ['title' => '', 'title_en' => '', 'description' => '', 'description_en' => '', 'images' => [], 'bg_color' => '', 'desc_font_size' => '', 'hidden' => false, 'hero' => '', 'captions' => false];
}

function save_series_data(array $d): void {
    atomic_write(SERIES_FILE, json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function series_has_admin_content(array $series): bool {
    foreach (['title', 'title_en', 'description', 'description_en', 'hero'] as $key) {
        if (trim((string)($series[$key] ?? '')) !== '') return true;
    }
    return !empty($series['images']) && is_array($series['images']);
}

function first_empty_series_id(array $sdata): ?string {
    foreach (SERIES_IDS as $sid) {
        if (!series_has_admin_content($sdata[$sid] ?? [])) return $sid;
    }
    return null;
}

function series_title_value(array $series, string $fallback = ''): string {
    $local = trim(lf($series, 'title'));
    if ($local !== '') return $local;
    foreach (['title', 'title_en'] as $key) {
        $v = trim((string)($series[$key] ?? ''));
        if ($v !== '') return $v;
    }
    return $fallback;
}

function series_title_parts(array $series, string $fallback = ''): array {
    $title = trim((string)($series['title'] ?? ''));
    $title_en = trim((string)($series['title_en'] ?? ''));
    if ($title === '' && $title_en !== '') $title = $title_en;
    if ($title_en === '' && $title !== '') $title_en = $title;
    if ($title === '' && $fallback !== '') $title = $fallback;
    if ($title_en === '' && $fallback !== '') $title_en = $fallback;
    return [$title, $title_en];
}

function series_valid_images(array $series, bool $include_hidden_albums): array {
    $valid = [];
    $hidden_albs = [];
    $images = $series['images'] ?? [];
    if (!is_array($images)) return $valid;
    foreach ($images as $entry) {
        $eparts = explode('/', (string)$entry, 2);
        if (count($eparts) !== 2) continue;
        [$alb, $file] = $eparts;
        if (!safe_seg($alb) || !safe_seg($file)) continue;
        if (!is_file(source_image_path($alb, $file))) continue;
        if (!$include_hidden_albums) {
            if (!isset($hidden_albs[$alb])) {
                $hidden_albs[$alb] = (parse_config(IMG_DIR . '/' . $alb)['hidden'] ?? '') === '1';
            }
            if ($hidden_albs[$alb]) continue;
        }
        $valid[] = ['album' => $alb, 'file' => $file, 'key' => $alb . '/' . $file];
    }
    return $valid;
}

function series_hero_image(array $series, array $valid_imgs): ?array {
    $hero = trim((string)($series['hero'] ?? ''));
    if ($hero !== '') {
        foreach ($valid_imgs as $img) {
            if (($img['key'] ?? '') === $hero) return $img;
        }
    }
    return $valid_imgs[0] ?? null;
}

function series_album_links_html(): string {
    $albs = albums();
    if (!$albs) {
        return '<p class="se-empty-help">Add an album first. Once images exist, this area will offer album links.</p>';
    }
    $out = '<div class="se-album-links">';
    foreach ($albs as $al) {
        $out .= '<a class="se-copy-btn" href="' . htmlspecialchars(album_url($al['slug'])) . '" onclick="localStorage.setItem(\'lb_series_mode\',\'1\')">'
              . bi($al['name'] ?? $al['slug'], $al['name_en'] ?? '') . '</a>';
    }
    $out .= '</div>';
    return $out;
}

function parse_markdown(string $md): string {
    $md    = str_replace(["\r\n", "\r"], "\n", $md);
    $lines = explode("\n", $md);
    $out   = '';
    $para  = [];
    $flush = function () use (&$para, &$out) {
        if (!$para) return;
        $text = htmlspecialchars(implode(' ', $para));
        $text = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $text);
        $text = preg_replace('/\*(.+?)\*/', '<em>$1</em>', $text);
        $text = preg_replace('/\[([^\]]+)\]\(([^)]+)\)/', '<a href="$2">$1</a>', $text);
        $out .= '<p>' . $text . '</p>' . "\n";
        $para = [];
    };
    foreach ($lines as $line) {
        if (preg_match('/^(#{1,3})\s+(.+)/', $line, $m)) {
            $flush();
            $lv   = strlen($m[1]);
            $out .= '<h' . $lv . '>' . htmlspecialchars($m[2]) . '</h' . $lv . '>' . "\n";
        } elseif (trim($line) === '') {
            $flush();
        } else {
            $para[] = trim($line);
        }
    }
    $flush();
    return $out;
}

function new_series_modal_html(): void {
    $multi = multilingual_enabled();
    $pl = htmlspecialchars(primary_lang_label());
    $primary_style = $multi ? '' : ' style="display:none"';
    $title_en_label = $multi ? 'Series Title (EN)' : 'Series Title';
    $csrf = $_SESSION['csrf'] ?? '';
    $chk = fn(string $val) => $val === '' ? ' checked' : '';
    echo '<div id="ns-modal"><div id="ns-box">';
    echo '<p class="an-label"' . $primary_style . '>Series Title (' . $pl . ')</p>';
    echo '<input id="ns-title" type="text" maxlength="200" placeholder="Series title"' . $primary_style . '>';
    echo '<p class="an-label" style="margin-top:10px">' . $title_en_label . '</p>';
    echo '<input id="ns-title-en" type="text" maxlength="200" placeholder="Series title">';
    echo '<p class="an-label" style="margin-top:14px">Background</p>';
    echo '<div class="bg-choice-row" role="radiogroup" aria-label="Series background">';
    echo '<label class="bg-choice"><input type="radio" name="ns-bg" value=""' . $chk('') . '><span class="bg-swatch bg-swatch-default" aria-hidden="true"></span><span>Default</span></label>';
    echo '<label class="bg-choice"><input type="radio" name="ns-bg" value="#000"><span class="bg-swatch bg-swatch-black" aria-hidden="true"></span><span>Black</span></label>';
    echo '<label class="bg-choice"><input type="radio" name="ns-bg" value="#888"><span class="bg-swatch bg-swatch-grey" aria-hidden="true"></span><span>Grey</span></label>';
    echo '<label class="bg-choice"><input type="radio" name="ns-bg" value="#fff"><span class="bg-swatch bg-swatch-white" aria-hidden="true"></span><span>White</span></label>';
    echo '</div>';
    echo '<p class="ns-help">Create the series first. Then open an album, turn on Series Selection Mode, and check this series on the images you want to include.</p>';
    echo '<p class="ns-error" id="ns-error"></p>';
    echo '<div class="an-btns"><button onclick="newSeriesClose()">Cancel</button><button class="an-save" onclick="newSeriesCreate()">Create Series</button></div>';
    echo '</div></div>';
    echo '<script data-cfasync="false">';
    echo 'var NS_CSRF=' . json_encode($csrf) . ';';
    echo 'var NS_MULTI=' . ($multi ? 'true' : 'false') . ';';
    echo <<<'JS'
function newSeriesOpen(){
  var m=document.getElementById('ns-modal');
  m.classList.add('open');
  var err=document.getElementById('ns-error');
  if(err){err.style.display='none';err.textContent='';}
  var inp=document.getElementById(NS_MULTI?'ns-title':'ns-title-en');
  if(inp){inp.focus();inp.select();}
}
function newSeriesClose(){document.getElementById('ns-modal').classList.remove('open');}
function newSeriesError(msg){var err=document.getElementById('ns-error');if(err){err.textContent=msg||'Could not create series.';err.style.display='block';}}
function newSeriesCreate(){
  var title=document.getElementById('ns-title').value.trim();
  var titleEn=document.getElementById('ns-title-en').value.trim();
  if(NS_MULTI){if(!title&&!titleEn){newSeriesError('Please enter a series title.');return;}}
  else{if(!titleEn){newSeriesError('Please enter a series title.');return;}if(!title)title=titleEn;}
  var bg=document.querySelector('input[name="ns-bg"]:checked');
  fetch('?create_series=1',{
    method:'POST',
    headers:{'X-CSRF-Token':NS_CSRF},
    body:new URLSearchParams({title:title,title_en:titleEn,bg_color:bg?bg.value:''})
  }).then(function(r){return r.json().catch(function(){return {ok:false,error:'Could not create series.'};});})
    .then(function(j){if(j.ok&&j.edit){location.href=j.edit;}else{newSeriesError(j.error||'Could not create series.');}});
}
document.getElementById('ns-modal').addEventListener('click',function(e){if(e.target===this)newSeriesClose();});
document.addEventListener('keydown',function(e){var m=document.getElementById('ns-modal');if(!m||!m.classList.contains('open'))return;if(e.key==='Escape')newSeriesClose();if(e.key==='Enter'&&e.target.tagName!=='TEXTAREA')newSeriesCreate();});
JS;
    echo '</script>';
}

function upload_modal_html(array $albs): void {
    if (!is_admin()) return;
    $csrf = $_SESSION['csrf'] ?? '';
    $has_albums = !empty($albs);
    $limit_text = 'Up to ' . UPLOAD_MAX_FILES . ' images per upload, ' . format_bytes(UPLOAD_MAX_BYTES) . ' per file, max long edge ' . UPLOAD_MAX_LONG_EDGE . ' px and ' . number_format(UPLOAD_MAX_PIXELS) . ' pixels.';
    echo '<div id="up-modal"><div id="up-box">';
    echo '<p class="an-label">Upload Images</p>';
    echo '<div class="up-targets">';
    if ($has_albums) {
        echo '<label><input type="radio" name="up-mode" value="existing" checked onchange="uploadModeToggle()"> Existing Album</label>';
        echo '<label><input type="radio" name="up-mode" value="new" onchange="uploadModeToggle()"> New Album</label>';
    } else {
        echo '<label><input type="radio" name="up-mode" value="new" checked onchange="uploadModeToggle()"> New Album</label>';
    }
    echo '</div>';
    echo '<div class="up-existing-fields"' . ($has_albums ? '' : ' style="display:none"') . '>';
    echo '<p class="an-label">Album</p>';
    echo '<select id="up-album">';
    foreach ($albs as $al) {
        echo '<option value="' . htmlspecialchars($al['slug']) . '">' . htmlspecialchars($al['name'] ?? $al['slug']) . '</option>';
    }
    echo '</select>';
    echo '</div>';
    echo '<div class="up-new-fields"' . ($has_albums ? '' : ' style="display:block"') . '>';
    echo '<p class="an-label">New Album Name</p>';
    echo '<input id="up-new-name" type="text" maxlength="160" placeholder="Album name" oninput="uploadSlugSuggest()">';
    echo '<p class="an-label" style="margin-top:10px">Folder Name</p>';
    echo '<input id="up-new-slug" type="text" maxlength="100" placeholder="auto-generated">';
    echo '</div>';
    echo '<p class="an-label" style="margin-top:14px">Images</p>';
    echo '<input id="up-file" type="file" accept="image/jpeg,image/png,image/webp" multiple>';
    echo '<p class="ns-help">JPEG, PNG, and WebP images are supported. Uploads are saved as originals; thumbnails and display images are generated on demand. ' . htmlspecialchars($limit_text) . '</p>';
    echo '<div class="up-progress"><span id="up-progress-bar"></span></div>';
    echo '<p class="up-status" id="up-status"></p>';
    echo '<div class="an-btns"><button onclick="uploadClose()">Cancel</button><button class="an-save" id="up-save" onclick="uploadStart()">Upload</button></div>';
    echo '</div></div>';
    echo '<script data-cfasync="false">';
    echo 'var UP_CSRF=' . json_encode($csrf) . ';';
    echo 'var UPLOAD_MAX_FILES=' . UPLOAD_MAX_FILES . ';';
    echo <<<'JS'
function uploadOpen(){var m=document.getElementById('up-modal');m.classList.add('open');uploadModeToggle();var f=document.getElementById('up-file');if(f)f.value='';uploadSetStatus('');uploadSetProgress(0);}
function uploadClose(){document.getElementById('up-modal').classList.remove('open');}
function uploadMode(){var m=document.querySelector('input[name="up-mode"]:checked');return m?m.value:'existing';}
function uploadModeToggle(){var isNew=uploadMode()==='new';document.querySelectorAll('.up-existing-fields').forEach(function(el){el.style.display=isNew?'none':'';});document.querySelectorAll('.up-new-fields').forEach(function(el){el.style.display=isNew?'block':'none';});}
function uploadSlugSuggest(){var name=document.getElementById('up-new-name').value.trim();var slug=name.normalize('NFKD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,80);var inp=document.getElementById('up-new-slug');if(inp&&!inp.dataset.touched)inp.value=slug;}
(function(){var s=document.getElementById('up-new-slug');if(s)s.addEventListener('input',function(){s.dataset.touched='1';});var m=document.getElementById('up-modal');if(m)m.addEventListener('click',function(e){if(e.target===m)uploadClose();});})();
function uploadSetProgress(p){var b=document.getElementById('up-progress-bar');if(b)b.style.width=Math.max(0,Math.min(100,p))+'%';}
function uploadSetStatus(msg,err){var s=document.getElementById('up-status');if(s){s.textContent=msg||'';s.style.color=err?'#ff7777':'';}}
function uploadStart(){
  var files=document.getElementById('up-file').files;
  if(!files.length){uploadSetStatus('Choose at least one image.',true);return;}
  if(files.length>UPLOAD_MAX_FILES){uploadSetStatus('Choose at most '+UPLOAD_MAX_FILES+' images.',true);return;}
  var fd=new FormData();
  fd.append('csrf',UP_CSRF);
  fd.append('target_mode',uploadMode());
  if(uploadMode()==='new'){
    var name=document.getElementById('up-new-name').value.trim();
    if(!name){uploadSetStatus('Enter a new album name.',true);return;}
    fd.append('new_album_name',name);
    fd.append('new_album_slug',document.getElementById('up-new-slug').value.trim());
  }else{
    fd.append('album',document.getElementById('up-album').value);
  }
  Array.prototype.forEach.call(files,function(file){fd.append('images[]',file);});
  var btn=document.getElementById('up-save');
  btn.disabled=true;
  uploadSetStatus('Uploading '+files.length+' image'+(files.length===1?'':'s')+'...');
  uploadSetProgress(0);
  var xhr=new XMLHttpRequest();
  xhr.open('POST','?upload_images=1');
  xhr.setRequestHeader('X-CSRF-Token',UP_CSRF);
  xhr.upload.onprogress=function(e){if(e.lengthComputable)uploadSetProgress((e.loaded/e.total)*100);};
  xhr.onload=function(){
    btn.disabled=false;
    var j={ok:false,error:'Upload failed.'};
    try{j=JSON.parse(xhr.responseText||'{}');}catch(e){}
    if(xhr.status>=200&&xhr.status<300&&j.ok){
      uploadSetProgress(100);
      var extra=j.errors&&j.errors.length?' Some files were skipped.':'';
      uploadSetStatus('Uploaded '+j.uploaded+' image'+(j.uploaded===1?'':'s')+'.'+extra);
      setTimeout(function(){location.href=j.url||('./?a='+encodeURIComponent(j.album));},650);
    }else{
      uploadSetStatus(j.error||'Upload failed.',true);
    }
  };
  xhr.onerror=function(){btn.disabled=false;uploadSetStatus('Upload failed.',true);};
  xhr.send(fd);
}
JS;
    echo '</script>';
}

function admin_bar_html(): void {
    if (!is_admin()) return;
    $csrf_tok = htmlspecialchars($_SESSION['csrf'] ?? '');
    $can_create_series = first_empty_series_id(load_series()) !== null;
    $albs = albums();
    $actions  = '';
    if ($can_create_series) {
        $actions .= '<button class="admin-sm-toggle" onclick="newSeriesOpen()">New Series</button>';
    }
    $actions .= '<a href="' . htmlspecialchars(analytics_admin_url()) . '">Analytics</a>';
    $actions .= '<a href="#" onclick="settingsOpen();return false">General Settings</a>';
    $actions .= '<a href="#" onclick="fetch(\'./\',{method:\'POST\',headers:{\'X-CSRF-Token\':\'' . $csrf_tok . '\'},body:new URLSearchParams({logout:1}),cache:\'no-store\',credentials:\'same-origin\'}).then(()=>location.replace(\'./\'));return false">Logout</a>';
    echo '<div class="admin-bar"><span class="admin-bar-label">Admin Mode <span class="admin-bar-version">' . htmlspecialchars(APP_VERSION) . '</span></span><div class="admin-bar-actions">' . $actions . '</div></div>';
    echo '<script data-cfasync="false">';
    echo 'function seriesModeLabel(on){var b=document.getElementById("series-selection-toggle");if(b)b.textContent=on?"SERIES SELECT MODE ON":"SERIES SELECT MODE OFF";}';
    echo '(function(){seriesModeLabel(localStorage.getItem("lb_series_mode")==="1");})();';
    echo 'function seriesModeToggle(){var on=localStorage.getItem("lb_series_mode")==="1";on=!on;localStorage.setItem("lb_series_mode",on?"1":"0");seriesModeLabel(on);var g=document.getElementById("gallery");if(g){if(on)g.classList.add("series-mode");else g.classList.remove("series-mode");}}';
    echo '</script>';
    if ($can_create_series) new_series_modal_html();
    upload_modal_html($albs);
}

// ─── series public page ───────────────────────────────────────────────────────

function page_series(string $id): void {
    $sdata  = load_series();
    $series = $sdata[$id];
    $base   = base_url();
    $site_title = site_title_text();
    $st     = site_title_html();
    $admin  = is_admin();
    $valid_imgs = series_valid_images($series, $admin);
    $public_title = series_title_value($series, '');

    if ((!series_has_admin_content($series) && !$valid_imgs) || (!$admin && ($public_title === '' || !$valid_imgs))) {
        http_response_code(404);
        html_head('Series Not Found — ' . $site_title, '');
        echo '<nav class="nav"><a href="' . htmlspecialchars(public_url()) . '" class="nav-back"><span class="nav-title">' . $st . '</span></a></nav>';
        echo '<div style="padding:40px 24px;opacity:.4;font-size:.75rem;">Series not found.</div>';
        html_foot();
        return;
    }

    $loc_title = series_title_value($series, 'Untitled Series');
    $loc_desc  = lf($series, 'description');
    [$_title_de, $_title_en] = series_title_parts($series, 'Untitled Series');
    $title = $loc_title . ' — ' . $site_title;
    $desc  = $loc_desc ? substr(strip_tags(parse_markdown($loc_desc)), 0, 160) : DEFAULT_SITE_DESC;

    $hero_img = series_hero_image($series, $valid_imgs);
    $hero_url = $hero_img ? thumb_url_ar($hero_img['album'], $hero_img['file']) : '';
    html_head($title, $desc, $hero_url, absolute_url(series_url($id)));
    $sbg = in_array($series['bg_color'] ?? '', ['#000', '#888', '#fff'], true) ? $series['bg_color'] : '';
    if ($sbg !== '') {
        $sfg = ($sbg === '#fff') ? '#111' : '#fff';
        echo "<style>html,body{background:{$sbg};color:{$sfg}}</style>\n";
    }

    echo '<nav class="nav series-nav" id="page-nav">';
    echo '<a class="nav-back" href="' . htmlspecialchars(public_url()) . '"><span class="nav-title">' . $st . '</span></a>';
    echo nav_tools_html(absolute_url(series_url($id)), $title, 'series', '', '', $id);
    echo '</nav>';
    if (is_admin()) {
        admin_bar_html();
        settings_modal(albums());
    }
    echo '<div class="series-h1-row">';
    echo '<h1 class="series-h1">' . bi($_title_de, $_title_en) . '</h1>';
    if (is_admin()) echo '<a href="' . htmlspecialchars(series_editor_url($id)) . '" class="nav-edit" title="Series settings">Series Settings</a>';
    echo '</div>';

    $_desc_de = $series['description'] ?? '';
    $_desc_en = $series['description_en'] ?? '';
    if ($_desc_de || $_desc_en) {
        $_dhtml_de = $_desc_de ? parse_markdown($_desc_de) : '';
        $_dhtml_en = $_desc_en ? parse_markdown($_desc_en) : $_dhtml_de;
        echo '<div class="series-desc markdown-content">' . bi_html($_dhtml_de, $_dhtml_en) . '</div>';
    }

    if (!$valid_imgs) {
        echo '<section class="se-empty-state">';
        echo '<h2>No images in this series yet</h2>';
        echo '<p>Open an album, turn on Series Selection Mode, and check "' . htmlspecialchars($loc_title) . '" on each image you want here.</p>';
        echo series_album_links_html();
        echo '<div class="se-album-links"><a class="se-copy-btn" href="' . htmlspecialchars(series_editor_url($id)) . '">Series Settings</a></div>';
        echo '</section>';
        html_foot();
        return;
    }

    $_series_captions_on = !empty($series['captions']);
    echo '<main class="grid series-grid" id="series-gallery">';
    $img_urls = [];
    $thumb_urls = [];
    $img_albums = [];
    $img_files = [];
    $share_urls = [];
    $meta_image_urls = [];
    foreach ($valid_imgs as $idx => $img) {
        $large_url = image_url($img['album'], $img['file']);
        $thumb_url = thumb_url_ar($img['album'], $img['file']);
        echo '<button class="tile" data-idx="' . $idx . '" data-album="' . htmlspecialchars($img['album']) . '" data-file="' . htmlspecialchars($img['file']) . '" onclick="lb(' . $idx . ')" aria-label="' . htmlspecialchars($img['file']) . '">';
        $_scap = caption_pair($img['album'], $img['file']);
        $_salt = htmlspecialchars(lf(['caption' => $_scap['de'], 'caption_en' => $_scap['en']], 'caption'), ENT_QUOTES);
        echo '<img src="' . htmlspecialchars($thumb_url) . '" data-large="' . htmlspecialchars($large_url) . '" alt="' . $_salt . '" draggable="false" loading="lazy">';
        if ($_series_captions_on) {
            $_scap = caption_html($img['album'], $img['file']);
            if ($_scap !== '') echo '<span class="series-cap">' . $_scap . '</span>';
        }
        echo '</button>';
        $img_urls[] = $large_url;
        $thumb_urls[] = $thumb_url;
        $img_albums[] = $img['album'];
        $img_files[] = $img['file'];
        $share_urls[] = canonical_image_url($img['album'], $img['file']);
        $meta_image_urls[] = og_image_url($img['album'], $img['file']);
    }
    echo '</main>';

    $seen_albs = [];
    foreach ($valid_imgs as $img) {
        if (!isset($seen_albs[$img['album']])) $seen_albs[$img['album']] = true;
    }
    if ($seen_albs) {
        $all_albs  = array_column(albums(), null, 'slug');
        $alb_links = [];
        foreach (array_keys($seen_albs) as $slug) {
            $alb_rec = $all_albs[$slug] ?? ['name' => $slug, 'name_en' => ''];
            $alb_links[] = '<a class="series-source-link" data-album="' . htmlspecialchars($slug) . '" href="' . htmlspecialchars(album_url($slug)) . '">' . bi($alb_rec['name'] ?? $slug, $alb_rec['name_en'] ?? '') . '</a>';
        }
        $_und = bi('und', 'and');
        if (count($alb_links) === 1) {
            $alb_str = $alb_links[0];
        } elseif (count($alb_links) === 2) {
            $alb_str = $alb_links[0] . ' ' . $_und . ' ' . $alb_links[1];
        } else {
            $last = array_pop($alb_links);
            $alb_str = implode(', ', $alb_links) . ' ' . $_und . ' ' . $last;
        }
        $quelle = count($seen_albs) === 1
            ? setting_label_html('source_label', 'Quelle', 'Source')
            : setting_label_html('sources_label', 'Quellen', 'Sources');
        echo '<div class="series-mehr series-desc">' . $quelle . ': ' . $alb_str . '</div>';
    }

    echo '<div id="lb" role="dialog" aria-modal="true"' . ($admin ? ' class="lb-admin"' : '') . '>';
    echo '<span id="lb-close" onclick="lbClose()" title="Close (Esc)" role="button" aria-label="Close lightbox">' . icon_arrow_left() . '</span>';
    echo '<span id="lb-prev" onclick="lbMove(-1)" title="Previous">&#8249;</span>';
    echo '<img id="lb-img" src="" alt="" draggable="false">';
    echo '<div id="lb-caption" style="display:none"></div>';
    if ($admin) { caption_editor_html(); }
    echo '<span id="lb-next" onclick="lbMove(1)" title="Next">&#8250;</span>';
    echo '<button id="lb-share" class="share-link" type="button" onclick="lbShareCurrent()">' . htmlspecialchars(share_label_text()) . '</button>';
    echo '<span id="lb-counter"></span>';
    echo '</div>';

    echo '<script data-cfasync="false">';
    echo 'var ALBUMS=' . json_encode($img_albums, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var FILES=' . json_encode($img_files, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var IMGS=' . json_encode($img_urls, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var THUMBS=' . json_encode($thumb_urls, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var SHARE_URLS=' . json_encode($share_urls, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var META_IMAGE_URLS=' . json_encode($meta_image_urls, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var SHARE_INDEX=-1;';
    echo 'var CAPTIONS=' . json_encode(array_map(fn(array $img) => caption_html($img['album'], $img['file']), $valid_imgs), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ';';
    echo 'var ALTS=' . json_encode(array_map(function(array $img) { $p = caption_pair($img['album'], $img['file']); return lf(['caption' => $p['de'], 'caption_en' => $p['en']], 'caption'); }, $valid_imgs), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ';';
    echo 'var CAPTIONS_DATA=' . json_encode(array_map(fn(array $img) => caption_pair($img['album'], $img['file']), $valid_imgs), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ';';
    echo 'var LB_CAPTIONS_ON=' . ($_series_captions_on ? 'true' : 'false') . ';';
    echo 'var LB_SERIES_ID=' . json_encode($id, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var ALBUM_PAGE_URL=' . json_encode(series_url($id), JSON_UNESCAPED_SLASHES) . ';';
    echo 'var ALBUM_BACK_URL=' . json_encode(public_url(), JSON_UNESCAPED_SLASHES) . ';';
    echo 'var LARGE_GEN_URL=' . json_encode(public_url('?gen_large=1'), JSON_UNESCAPED_SLASHES) . ';';
    echo 'var cur=0;';
    echo 'lbInstallAnalytics({viewType:"series",series:' . json_encode($id, JSON_UNESCAPED_SLASHES) . ',seriesTitle:' . json_encode($loc_title, JSON_UNESCAPED_SLASHES) . ',albums:ALBUMS,files:FILES,currentAlbum:function(i){return ALBUMS[i]||"";},currentPhoto:function(){return FILES[cur]||"";}});';
    echo <<<'JS'
var largeQueue=[],largeActive=0,largeReady={},largeLimit=5;
function swapSeriesLarge(i){
  var tile=document.querySelector('#series-gallery .tile[data-idx="'+i+'"]');
  if(!tile)return;
  var img=tile.querySelector('img'),large=img&&img.getAttribute('data-large');
  if(large){img.src=large;img.removeAttribute('data-large');}
}
function queueLarge(i,show){
  if(i<0||i>=IMGS.length)return;
  if(largeReady[i]){if(show)showLarge(i);swapSeriesLarge(i);return;}
  largeQueue=largeQueue.filter(function(j){return j.i!==i;});
  var job={i:i,show:!!show};
  if(show)largeQueue.unshift(job);else largeQueue.push(job);
  pumpLargeQueue();
}
function pumpLargeQueue(){
  while(largeActive<largeLimit&&largeQueue.length){
  var job=largeQueue.shift();
  largeActive++;
  var url=LARGE_GEN_URL+'&a='+encodeURIComponent(ALBUMS[job.i])+'&f='+encodeURIComponent(FILES[job.i]);
  lbDebug('[Lightbox] generating large image',url);
  fetch(url,{cache:'no-store',credentials:'same-origin'}).then(function(r){
    lbDebug('[Lightbox] large generation response',r.status,r.statusText);
    if(!r.ok)return r.text().then(function(t){throw new Error(t||('HTTP '+r.status));});
    return r.json();
  }).then(function(data){
    if(data.ok!==false){
      largeReady[job.i]=true;
      swapSeriesLarge(job.i);
      if(job.show&&cur===job.i)showLarge(job.i);
      else lbPreloadLarge(job.i);
    }
  }).catch(function(e){lbWarn('[Lightbox] large generation failed',FILES[job.i],e);})
    .finally(function(){largeActive=Math.max(0,largeActive-1);pumpLargeQueue();});
  }
}
lbInstallLightbox();
document.querySelectorAll('.series-source-link[data-album]').forEach(function(a){
  a.addEventListener('click',function(){if(window.lbAnalyticsSeriesSourceClick)lbAnalyticsSeriesSourceClick(a.dataset.album||'');});
});
(function(){
  function byView(a,b){
    var ar=a.getBoundingClientRect(),br=b.getBoundingClientRect();
    var av=ar.bottom>0&&ar.top<innerHeight,bv=br.bottom>0&&br.top<innerHeight;
    if(av!==bv)return av?-1:1;
    return ar.top-br.top||ar.left-br.left;
  }
  Array.prototype.slice.call(document.querySelectorAll('#series-gallery .tile')).sort(byView).forEach(function(tile){
    queueLarge(parseInt(tile.dataset.idx,10),false);
  });
})();
JS;
    echo '</script>';
    if ($admin) {
        $csrf = $_SESSION['csrf'] ?? '';
        echo '<script data-cfasync="false">';
        echo 'var CTX_CSRF=' . json_encode($csrf) . ';';
        echo 'var CAPTIONS_API=' . (caption_api_key() !== null ? 'true' : 'false') . ';';
        echo 'var seriesToastTimer=null;';
        echo 'function showSeriesToast(msg){var t=document.getElementById("series-toast");if(!t)return;t.textContent=msg;clearTimeout(seriesToastTimer);t.classList.remove("show");void t.offsetWidth;t.classList.add("show");seriesToastTimer=setTimeout(function(){t.classList.remove("show");},1000);}';
        caption_editor_js();
        echo '</script>';
        echo '<div id="series-toast" role="status" aria-live="polite"></div>';
    }
    echo '<script data-cfasync="false">(function(){document.querySelectorAll("#series-gallery .tile img").forEach(function(img){function done(ok){if(!ok)lbWarn("[Lightbox] series image failed",img.currentSrc||img.src);img.closest(".tile").classList.add("loaded");}if(img.complete&&img.naturalWidth)done(true);else{img.addEventListener("load",function(){done(true);});img.addEventListener("error",function(){done(false);});}});})();</script>';

    html_foot();
}

// ─── caption editor (admin) ──────────────────────────────────────────────────

function page_caption_editor(string $album): void {
    $site_title  = site_title_text();
    $st          = htmlspecialchars($site_title);
    $cfg         = parse_config(IMG_DIR . '/' . $album);
    $default_name = default_album_name($album);
    $album_name  = htmlspecialchars(lf($cfg + ['name' => $default_name, 'name_en' => ''], 'name') ?: $default_name);
    $imgs        = images_in($album);
    $multi       = multilingual_enabled();
    $pl          = htmlspecialchars(primary_lang_label());
    $has_key     = caption_api_key() !== null;
    $csrf        = $_SESSION['csrf'] ?? '';

    html_head('Create Captions — ' . $site_title, '');
    echo '<nav class="nav" id="page-nav">';
    echo '<a class="nav-back" href="' . htmlspecialchars(album_url($album)) . '"><span class="nav-title">' . $st . '</span></a>';
    echo '<span class="nav-sep">/</span>';
    echo '<span class="nav-album">' . $album_name . '</span>';
    echo '<span class="nav-sep">/</span>';
    echo '<span class="nav-album">Create Captions</span>';
    echo '</nav>';
    admin_bar_html();
    settings_modal(albums());

    echo '<div class="bc-toolbar">';
    echo '<button class="nav-edit" onclick="bcSelectAll(this)" id="bc-sel-all">Select All</button>';
    echo '<span class="bc-count">' . count($imgs) . ' image' . (count($imgs) === 1 ? '' : 's') . '</span>';
    echo '</div>';

    echo '<div class="bc-grid">';
    foreach ($imgs as $file) {
        $pair      = caption_pair($album, $file);
        $de_esc    = htmlspecialchars($pair['de'], ENT_QUOTES);
        $en_esc    = htmlspecialchars($pair['en'], ENT_QUOTES);
        $file_esc  = htmlspecialchars($file, ENT_QUOTES);
        $thumb_url = htmlspecialchars(thumb_url_ar($album, $file));
        echo '<div class="bc-row' . ($multi ? ' bc-multi' : '') . '" data-file="' . $file_esc . '">';
        echo '<input type="checkbox" class="bc-cb" aria-label="Select">';
        echo '<img class="bc-thumb" src="' . $thumb_url . '" loading="lazy" alt="">';
        echo '<div class="bc-inputs">';
        if ($multi) {
            echo '<input type="text" class="bc-in" data-lang="de" placeholder="Caption (' . $pl . ')" value="' . $de_esc . '" data-orig="' . $de_esc . '">';
            echo '<input type="text" class="bc-in" data-lang="en" placeholder="Caption (EN)" value="' . $en_esc . '" data-orig="' . $en_esc . '">';
        } else {
            echo '<input type="text" class="bc-in" data-lang="en" placeholder="Caption" value="' . $en_esc . '" data-orig="' . $en_esc . '">';
        }
        echo '</div>';
        echo '<button class="bc-save" disabled onclick="bcSaveRow(this.closest(\'.bc-row\'))">Save</button>';
        echo '</div>';
    }
    echo '</div>';

    echo '<div class="bc-footer">';
    if ($has_key) {
        echo '<button class="bc-gen-btn" onclick="bcGenSelected(this)">&#10024; Generate captions for all selected images</button>';
    } else {
        echo '<p class="cap-no-key" style="text-align:left;opacity:.7">Add <code>LIGHTBOX_GOOGLE_API_KEY</code> to <code>.env</code> for AI captions. You can still save captions manually.</p>';
    }
    echo '</div>';

    echo '<script data-cfasync="false">';
    echo 'var CTX_ALBUM=' . json_encode($album, JSON_UNESCAPED_SLASHES) . ';';
    echo 'var CTX_CSRF=' . json_encode($csrf) . ';';
    echo 'var BC_MULTI=' . ($multi ? 'true' : 'false') . ';';
    echo <<<'JS'
function bcRowDirty(row){
  var changed=false;
  row.querySelectorAll('.bc-in').forEach(function(inp){if(inp.value.trim()!==(inp.dataset.orig||''))changed=true;});
  var btn=row.querySelector('.bc-save');
  if(btn){btn.disabled=!changed;btn.classList.remove('bc-ok','bc-err');}
}
document.querySelectorAll('.bc-row').forEach(function(row){
  row.querySelectorAll('.bc-in').forEach(function(inp){inp.addEventListener('input',function(){bcRowDirty(row);});});
});
function bcSaveRow(row){
  return new Promise(function(resolve){
    var file=row.dataset.file;
    var de='',en='';
    row.querySelectorAll('.bc-in').forEach(function(inp){if(inp.dataset.lang==='de')de=inp.value.trim();if(inp.dataset.lang==='en')en=inp.value.trim();});
    var btn=row.querySelector('.bc-save');
    if(btn)btn.disabled=true;
    fetch('?save_caption=1&a='+encodeURIComponent(CTX_ALBUM)+'&f='+encodeURIComponent(file),{
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'caption='+encodeURIComponent(de)+'&caption_en='+encodeURIComponent(en)+'&csrf='+encodeURIComponent(CTX_CSRF)
    }).then(function(r){
      if(r.ok){
        row.querySelectorAll('.bc-in').forEach(function(inp){inp.dataset.orig=inp.value.trim();});
        if(btn){btn.disabled=true;btn.classList.add('bc-ok');btn.textContent='Saved';setTimeout(function(){btn.textContent='Save';btn.classList.remove('bc-ok');},1200);}
      }else{
        if(btn){btn.disabled=false;btn.classList.add('bc-err');}
      }
      resolve();
    }).catch(function(){if(btn){btn.disabled=false;btn.classList.add('bc-err');}resolve();});
  });
}
function bcSelectAll(btn){
  var cbs=document.querySelectorAll('.bc-cb');
  var allChecked=Array.prototype.every.call(cbs,function(cb){return cb.checked;});
  cbs.forEach(function(cb){cb.checked=!allChecked;});
  btn.textContent=allChecked?'Select All':'Deselect All';
}
function bcGenSelected(btn){
  var rows=Array.prototype.filter.call(document.querySelectorAll('.bc-row'),function(r){var cb=r.querySelector('.bc-cb');return cb&&cb.checked;});
  if(!rows.length)return;
  btn.disabled=true;
  var idx=0,active=0,concurrency=3;
  function processRow(row){
    var file=row.dataset.file;
    var cb=row.querySelector('.bc-cb');
    var spinner=document.createElement('span');spinner.className='bc-spinner';
    if(cb){cb.style.display='none';cb.parentNode.insertBefore(spinner,cb);}
    row.classList.add('bc-row-busy');
    function restoreCb(){spinner.remove();if(cb)cb.style.display='';}
    function done(){active--;pump();}
    fetch('?ai_caption=1&a='+encodeURIComponent(CTX_ALBUM)+'&f='+encodeURIComponent(file),{
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'csrf='+encodeURIComponent(CTX_CSRF)
    }).then(function(r){return r.json();}).then(function(d){
      if(d.ok===false){
        row.classList.remove('bc-row-busy');
        row.classList.add('bc-row-err');
        restoreCb();
        done();
        return;
      }
      row.querySelectorAll('.bc-in').forEach(function(inp){
        if(inp.dataset.lang==='en'&&d.en)inp.value=d.en;
        if(inp.dataset.lang==='de'&&d.de)inp.value=d.de;
      });
      bcSaveRow(row).then(function(){
        row.classList.remove('bc-row-busy');
        row.classList.add('bc-row-done');
        restoreCb();
        done();
      });
    }).catch(function(){
      row.classList.remove('bc-row-busy');
      restoreCb();
      done();
    });
  }
  function pump(){
    while(active<concurrency&&idx<rows.length){active++;processRow(rows[idx++]);}
    if(active===0)btn.disabled=false;
  }
  pump();
}
JS;
    echo '</script>';

    html_foot();
}

// ─── series editor (admin) ────────────────────────────────────────────────────

function page_series_editor(string $id): void {
    $sdata  = load_series();
    $series = $sdata[$id];
    $settings = load_settings();
    $site_title = site_title_text();
    $st     = htmlspecialchars(lf($settings, 'site_title') ?: DEFAULT_SITE_TITLE);
    $multi  = multilingual_enabled();
    $pl     = htmlspecialchars(primary_lang_label());
    $primary_style = $multi ? '' : ' style="display:none"';
    $series_en_label = $multi ? 'Series Title (EN)' : 'Series Title';
    $desc_en_label = $multi ? 'Description (EN, Markdown)' : 'Description (Markdown)';
    $stitle_raw = (string)$series['title'];
    $stitle_en_raw = (string)($series['title_en'] ?? '');
    $sdesc_raw = (string)$series['description'];
    $sdesc_en_raw = (string)($series['description_en'] ?? '');
    if (!$multi && $stitle_en_raw === '') $stitle_en_raw = $stitle_raw;
    if (!$multi && $sdesc_en_raw === '') $sdesc_en_raw = $sdesc_raw;
    $stitle    = htmlspecialchars($stitle_raw);
    $stitle_en = htmlspecialchars($stitle_en_raw);
    $sdesc     = htmlspecialchars($sdesc_raw);
    $sdesc_en  = htmlspecialchars($sdesc_en_raw);
    $sbg    = in_array($series['bg_color'] ?? '', ['#000', '#888', '#fff'], true) ? $series['bg_color'] : '';
    $sdfs   = htmlspecialchars(preg_replace('/[^0-9.a-z%]/', '', $series['desc_font_size'] ?? ''));
    $s_hero = $series['hero'] ?? '';
    $csrf   = $_SESSION['csrf'] ?? '';
    $editor_title = series_title_value($series, 'New Series');
    $editor_title_html = htmlspecialchars($editor_title);

    $icon_expand_se   = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 16 16"><path fill="currentColor" fill-rule="evenodd" d="M7.754 2.004a.75.75 0 0 0 0 1.5h4.75v4.742a.75.75 0 0 0 1.5 0V2.754a.75.75 0 0 0-.75-.75zm.492 11.992a.75.75 0 0 0 0-1.5h-4.75V7.754a.75.75 0 0 0-1.5 0v5.492a.75.75 0 0 0 .75.75z" clip-rule="evenodd"/></svg>';
    $icon_collapse_se = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 16 16"><path fill="currentColor" fill-rule="evenodd" d="M15.25 6.993a.75.75 0 0 0 0-1.5H10.5V.75a.75.75 0 1 0-1.5 0v5.493c0 .414.336.75.75.75zM.75 9.007a.75.75 0 1 0 0 1.5H5.5v4.743a.75.75 0 0 0 1.5 0V9.757a.75.75 0 0 0-.75-.75z" clip-rule="evenodd"/></svg>';

    html_head($editor_title . ' Editor — ' . $site_title, '');

    echo '<nav class="nav" id="page-nav">';
    echo '<a class="nav-back" href="' . htmlspecialchars(public_url()) . '"><span class="nav-title">' . $st . '</span></a>';
    echo '<span class="nav-sep">/</span>';
    echo '<span class="nav-album">' . $editor_title_html . ' Editor</span>';
    echo '</nav>';

    admin_bar_html();
    settings_modal(albums());

    echo '<div class="se-inputs">';
    echo '<label class="se-field-label"' . $primary_style . '>Series Title (' . $pl . ')</label>';
    echo '<input type="text" id="se-title" value="' . $stitle . '" placeholder="Series Title" maxlength="200"' . $primary_style . '>';
    echo '<label class="se-field-label">' . $series_en_label . '</label>';
    echo '<input type="text" id="se-title-en" value="' . $stitle_en . '" placeholder="Series Title" maxlength="200">';
    echo '<label class="se-field-label"' . $primary_style . '>Description (' . $pl . ', Markdown)</label>';
    echo '<textarea id="se-desc" placeholder="# Heading&#10;&#10;Description text..."' . $primary_style . '>' . $sdesc . '</textarea>';
    echo '<label class="se-field-label">' . $desc_en_label . '</label>';
    echo '<textarea id="se-desc-en" placeholder="# Heading&#10;&#10;Description text...">' . $sdesc_en . '</textarea>';
    $chk = function(string $val) use ($sbg) { return $val === $sbg ? ' checked' : ''; };
    echo '<label class="se-field-label">Background</label>';
    echo '<div class="bg-choice-row" role="radiogroup" aria-label="Series background">';
    echo '<label class="bg-choice"><input type="radio" name="se-bg" value=""' . $chk('') . '><span class="bg-swatch bg-swatch-default" aria-hidden="true"></span><span>Default</span></label>';
    echo '<label class="bg-choice"><input type="radio" name="se-bg" value="#000"' . $chk('#000') . '><span class="bg-swatch bg-swatch-black" aria-hidden="true"></span><span>Black</span></label>';
    echo '<label class="bg-choice"><input type="radio" name="se-bg" value="#888"' . $chk('#888') . '><span class="bg-swatch bg-swatch-grey" aria-hidden="true"></span><span>Grey</span></label>';
    echo '<label class="bg-choice"><input type="radio" name="se-bg" value="#fff"' . $chk('#fff') . '><span class="bg-swatch bg-swatch-white" aria-hidden="true"></span><span>White</span></label>';
    echo '</div>';
    $se_captions_checked = !empty($series['captions']) ? ' checked' : '';
    echo '<label class="sm-check" style="display:inline-flex;margin-top:12px"><input type="checkbox" id="se-captions"' . $se_captions_checked . '> Display captions</label>';
    echo '<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px">';
    echo '<button class="se-save-btn" onclick="seSave()">Save &amp; Close</button>';
    echo '<button class="se-copy-btn" onclick="seCopyLink(this)">Copy Link</button>';
    echo '<a class="se-copy-btn" href="' . htmlspecialchars(series_url($id)) . '" target="_blank" rel="noopener">Open ↗</a>';
    echo '<button class="se-delete-btn" onclick="seDelete()">Delete Series</button>';
    echo '</div>';
    echo '<div class="se-aspect-row"><button class="nav-toggle" id="aspect-toggle" onclick="aspectToggle()" title="Toggle aspect ratio"><span id="aspect-icon-sq">' . $icon_collapse_se . '</span><span id="aspect-icon-ar" style="display:none">' . $icon_expand_se . '</span></button></div>';
    echo '</div>';

    $valid_imgs = series_valid_images($series, true);

    if (!$valid_imgs) {
        echo '<section class="se-empty-state">';
        echo '<h2>No images in this series yet</h2>';
        echo '<p>Open an album, turn on Series Selection Mode, and check "' . $editor_title_html . '" on each image you want to include.</p>';
        echo series_album_links_html();
        echo '</section>';
    }
    if ($valid_imgs) {
        echo '<div class="se-add-note admin-grid-hint">Drag and drop images to change their order. The star icon determines the series hero image.</div>';
    }
    echo '<main class="grid" id="gallery">';
    foreach ($valid_imgs as $img) {
        $turl    = htmlspecialchars(thumb_url_ar($img['album'], $img['file']));
        $fkey    = htmlspecialchars($img['key']);
        $is_hero = ($img['key'] === $s_hero);
        $star    = $is_hero ? '&#9733;' : '&#9734;';
        echo '<div class="tile" draggable="true" data-file="' . $fkey . '">';
        echo '<img src="' . $turl . '" alt="" draggable="false" loading="lazy">';
        echo '<span class="album-badge">' . htmlspecialchars($img['album']) . '</span>';
        echo '<span class="admin-star' . ($is_hero ? ' is-hero' : '') . '" data-file="' . $fkey . '" onclick="seSetHero(this,event)" title="Set as hero">' . $star . '</span>';
        echo '<button class="se-remove" onclick="seRemove(this)" title="Remove">&#10005;</button>';
        echo '</div>';
    }
    echo '</main>';

    if ($valid_imgs) {
        echo '<div class="se-add-note">Add more images from any album with Series Selection Mode.</div>';
    }

    echo '<script data-cfasync="false">';
    echo 'var SE_ID=' . json_encode($id) . ';';
    echo 'var SE_CSRF=' . json_encode($csrf) . ';';
    echo 'var SE_BASE=' . json_encode(base_url()) . ';';
    echo 'var SE_PUBLIC_URL=' . json_encode(absolute_url(series_url($id)), JSON_UNESCAPED_SLASHES) . ';';
    echo 'var SE_HOME_URL=' . json_encode(public_url(), JSON_UNESCAPED_SLASHES) . ';';
    echo 'var SE_SERIES_URL=' . json_encode(series_url($id), JSON_UNESCAPED_SLASHES) . ';';
    echo 'var SE_MULTI=' . ($multi ? 'true' : 'false') . ';';
    echo <<<'JS'
function seCopyLink(btn){
  navigator.clipboard.writeText(SE_PUBLIC_URL).then(function(){
    var orig=btn.textContent;btn.textContent='Copied!';setTimeout(function(){btn.textContent=orig;},1500);
  });
}
function seSave(){
  var order=Array.from(document.querySelectorAll('#gallery .tile')).map(function(t){return t.dataset.file;}).filter(Boolean);
  var bg=document.querySelector('input[name="se-bg"]:checked');
  var title=document.getElementById('se-title').value;
  var titleEn=document.getElementById('se-title-en').value;
  var desc=document.getElementById('se-desc').value;
  var descEn=document.getElementById('se-desc-en').value;
  if(!SE_MULTI){if(!title)title=titleEn;if(!desc)desc=descEn;}
  var caps=document.getElementById('se-captions');
  fetch('?save_series=1',{
    method:'POST',
    headers:{'X-CSRF-Token':SE_CSRF},
    body:new URLSearchParams({id:SE_ID,title:title,title_en:titleEn,description:desc,description_en:descEn,bg_color:bg?bg.value:'',order:order.join(','),captions:caps&&caps.checked?'1':'0'})
  }).then(function(r){if(r.ok)location.href=SE_SERIES_URL;});
}
function seRemove(btn){var tile=btn.closest('.tile');if(tile)tile.remove();}
function seDelete(){
  var title=(document.getElementById('se-title').value||document.getElementById('se-title-en').value||'this series').trim();
  if(!confirm('Delete "'+title+'"? This removes the series and its image assignments. Source images stay in their albums.'))return;
  fetch('?delete_series=1',{
    method:'POST',
    headers:{'X-CSRF-Token':SE_CSRF},
    body:new URLSearchParams({id:SE_ID})
  }).then(function(r){if(r.ok)location.href=SE_HOME_URL;});
}
function seSetHero(el,e){
  e.stopPropagation();
  fetch('?set_series_hero=1',{method:'POST',headers:{'X-CSRF-Token':SE_CSRF},body:new URLSearchParams({id:SE_ID,f:el.dataset.file})}).then(function(r){
    if(!r.ok)return;
    document.querySelectorAll('#gallery .admin-star').forEach(function(s){var h=s.dataset.file===el.dataset.file;s.textContent=h?'★':'☆';s.classList.toggle('is-hero',h);});
  });
}
(function(){document.querySelectorAll('#gallery .tile img').forEach(function(img){function finish(ok){var tile=img.closest('.tile');if(ok){var nw=img.naturalWidth,nh=img.naturalHeight;if(nw&&nh){img.dataset.scale=(Math.max(nw,nh)/Math.min(nw,nh)).toFixed(4);}if(!window._arMode)img.style.transform=img.dataset.scale?'scale('+img.dataset.scale+')':'';}tile.classList.add('loaded');tile.classList.remove('thumb-pending');}if(img.complete&&img.naturalWidth)finish(true);else{img.addEventListener('load',function(){finish(true);});img.addEventListener('error',function(){finish(false);});}});})();
(function(){var KEY='lb_ar_mode';var ar=localStorage.getItem(KEY)==='1';window._arMode=ar;var si=document.getElementById('aspect-icon-sq');var ai=document.getElementById('aspect-icon-ar');function setIcons(a){si.style.display=a?'none':'';ai.style.display=a?'':'none';}setIcons(ar);document.querySelectorAll('#gallery .tile img').forEach(function(img){img.style.transform=ar?'':img.dataset.scale?'scale('+img.dataset.scale+')':'';});window.aspectToggle=function(){ar=!ar;window._arMode=ar;localStorage.setItem(KEY,ar?'1':'0');setIcons(ar);document.querySelectorAll('#gallery .tile img').forEach(function(img){var s=img.dataset.scale||'1';img.style.transition='transform .35s ease-in-out';img.style.transform=ar?'scale(1)':'scale('+s+')';});};})();
// drag-to-reorder without auto-save (save button handles it)
(function(){
  var grid=document.getElementById('gallery');
  var dragging=null;
  grid.addEventListener('dragstart',function(e){var t=e.target.closest('.tile');if(!t)return;dragging=t;e.dataTransfer.effectAllowed='move';requestAnimationFrame(function(){if(dragging)dragging.classList.add('dnd-drag');});});
  grid.addEventListener('dragend',function(){if(dragging)dragging.classList.remove('dnd-drag');dragging=null;});
  grid.addEventListener('dragover',function(e){e.preventDefault();if(!dragging)return;var t=e.target.closest('.tile');if(!t||t===dragging)return;var r=t.getBoundingClientRect();if(e.clientX>r.left+r.width/2){if(t.nextElementSibling!==dragging)t.after(dragging);}else{if(t.previousElementSibling!==dragging)t.before(dragging);}});
  grid.addEventListener('drop',function(e){e.preventDefault();});
})();
JS;
    echo '</script>';

    html_foot();
}
