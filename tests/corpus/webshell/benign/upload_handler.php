<?php
if (!empty($_FILES['avatar']['tmp_name'])) {
    $dest = '/var/www/uploads/' . basename($_FILES['avatar']['name']);
    move_uploaded_file($_FILES['avatar']['tmp_name'], $dest);
    echo "Uploaded.";
}
