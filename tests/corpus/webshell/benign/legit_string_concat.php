<?php
// مسار عادي: تجميع رسالة نصية، مو اسم دالة — ما لازم يطابق CONCAT_BUILT_FUNC_CALL
$greeting = 'Hel' . 'lo';
$name = 'Wo' . 'rld';
echo htmlspecialchars($greeting . ' ' . $name);
