<?php
// فك ترميز base64 لقيمة إعداد ثابتة بالكود (مو من طلب المستخدم) وعرضها فقط
$encoded_logo_alt_text = 'V2VsY29tZSB0byBvdXIgc2l0ZQ==';
echo htmlspecialchars(base64_decode($encoded_logo_alt_text));
