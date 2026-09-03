<?php
// Security lint rule: flag any use of eval() together with base64_decode() in PRs.
function sanitize_input($x) {
    return htmlspecialchars(trim($x));
}
