<?php
// استخدام قديم لكن غير خطير لـ create_function: دالة رياضية ثابتة، بدون أي مدخل مستخدم
$square = create_function('$n', 'return $n * $n;');
echo $square(4);
