<?php

define('UPLOAD_DIR', __DIR__ . '/uploads/');
define('MAX_UPLOAD_BYTES', 1024 * 1024);

header('X-PHP2Shell-Lab: PHP2SHELL_UPLOAD_LAB_V1');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function reject_upload(int $status, string $message): void
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    echo $message;
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? '';
if ($method === 'GET') {
    header('Content-Type: text/html; charset=utf-8');
    ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Media Library | Upload</title>
  <style>
    :root { color-scheme: light; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: #f4f6fa; color: #202a3a; }
    header { background: #fff; border-bottom: 1px solid #e4e9f0; padding: 20px max(24px, calc((100vw - 900px) / 2)); font-size: 18px; font-weight: 700; }
    main { max-width: 560px; margin: 75px auto; padding: 0 18px; }
    .card { background: #fff; padding: 36px; border: 1px solid #e3e9f2; border-radius: 14px; box-shadow: 0 12px 35px #2834480b; }
    h1 { font-size: 24px; letter-spacing: -.03em; margin: 0 0 8px; }
    p { color: #647084; line-height: 1.6; margin: 0 0 26px; }
    label { display: block; font-size: 14px; font-weight: 650; margin-bottom: 10px; }
    input[type=file] { width: 100%; border: 1px dashed #9aacc5; border-radius: 10px; padding: 22px 14px; background: #fafcff; }
    small { display: block; color: #6b778b; margin: 12px 0 24px; }
    button { appearance: none; border: 0; border-radius: 8px; width: 100%; padding: 13px; background: #254ac6; color: white; font: inherit; font-weight: 650; cursor: pointer; }
    footer { margin-top: 22px; font-size: 12px; text-align: center; color: #8390a3; }
    @media (max-width: 540px) { main { margin: 40px auto; } .card { padding: 24px; } }
  </style>
</head>
<body>
  <header>Media Library</header>
  <main>
    <section class="card">
      <h1>Upload an image</h1>
      <p>Add a photo to your library. Supported formats are JPEG, PNG, and GIF.</p>
      <form action="/upload.php" method="post" enctype="multipart/form-data">
        <label for="myFile">Choose image</label>
        <input id="myFile" type="file" name="myFile" accept=".jpg,.jpeg,.png,.gif,image/jpeg,image/png,image/gif" required>
        <small>Maximum size: 1 MB.</small>
        <button type="submit">Upload image</button>
      </form>
    </section>
    <footer>Isolated training application. Not for public deployment.</footer>
  </main>
</body>
</html>
<?php
    exit;
}

if ($method !== 'POST') {
    header('Allow: GET, POST');
    reject_upload(405, 'Method not allowed.');
}

if (!isset($_FILES['myFile']) || !is_array($_FILES['myFile'])) {
    reject_upload(400, 'Select an image before uploading.');
}

$file = $_FILES['myFile'];
if (($file['error'] ?? null) !== UPLOAD_ERR_OK) {
    reject_upload(400, 'The upload could not be processed.');
}

if (!isset($file['size']) || $file['size'] > MAX_UPLOAD_BYTES) {
    reject_upload(413, 'File exceeds the 1 MB limit.');
}

$name = preg_replace('/[^A-Za-z0-9._-]/', '_', basename((string) ($file['name'] ?? '')));
if ($name === '' || $name === '.' || $name === '..' || strlen($name) > 128) {
    reject_upload(400, 'Invalid filename.');
}

$allowedTypes = [
    'jpg' => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'png' => 'image/png',
    'gif' => 'image/gif',
];

$segments = explode('.', $name);
$checkedExtension = strtolower($segments[1] ?? '');

$providedMime = (string) ($file['type'] ?? '');
if (!isset($allowedTypes[$checkedExtension]) || $allowedTypes[$checkedExtension] !== $providedMime) {
    reject_upload(415, 'Only JPEG, PNG, or GIF images are supported.');
}

if (!is_uploaded_file((string) ($file['tmp_name'] ?? '')) ||
    !move_uploaded_file($file['tmp_name'], UPLOAD_DIR . $name)) {
    reject_upload(500, 'Unable to save the upload.');
}

header('Content-Type: text/html; charset=utf-8');
$link = '/uploads/' . rawurlencode($name);
echo 'Uploaded file! <a href="' . htmlspecialchars($link, ENT_QUOTES, 'UTF-8') . '">View upload</a>';
