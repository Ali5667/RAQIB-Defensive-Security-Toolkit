<?php
if (isset($_POST['email']) && isset($_POST['message'])) {
    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    $message = htmlspecialchars($_POST['message']);
    if ($email) {
        mail('owner@example.com', 'Contact form', $message, "From: $email");
        echo "Thanks, we'll be in touch.";
    }
}
