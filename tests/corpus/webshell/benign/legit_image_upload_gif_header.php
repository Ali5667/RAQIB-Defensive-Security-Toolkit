<?php
// كود فحص رأس ملفات GIF المرفوعة (magic bytes) — يتحقق من التوقيع فقط، ما ينفذ أي كود
$handle = fopen($_FILES['avatar']['tmp_name'], 'rb');
$header = fread($handle, 6);
fclose($handle);
if (!in_array($header, ['GIF87a', 'GIF89a'], true)) {
    http_response_code(400);
    exit('Invalid image header');
}
