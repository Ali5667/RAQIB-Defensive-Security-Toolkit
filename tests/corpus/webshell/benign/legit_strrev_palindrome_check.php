<?php
// أداة تعليمية بسيطة تتحقق هل الكلمة "طردية" (palindrome) — لا علاقة لها بالتنفيذ
function is_palindrome(string $word): bool {
    return strtolower($word) === strtolower(strrev($word));
}
echo is_palindrome($_GET['word'] ?? '') ? 'yes' : 'no';
