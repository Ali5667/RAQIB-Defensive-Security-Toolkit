<?php
// موزّع أوامر شرعي: القائمة البيضاء مسبقة التعريف، المستخدم يختار مفتاحاً فقط وليس دالة حرة
$allowed = [
    'list_items' => 'controller_list_items',
    'show_item'  => 'controller_show_item',
];
$action = $_GET['action'] ?? 'list_items';
if (isset($allowed[$action])) {
    call_user_func($allowed[$action]);
}
