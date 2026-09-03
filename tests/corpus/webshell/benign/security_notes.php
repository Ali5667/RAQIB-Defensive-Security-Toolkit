<?php
/*
 * Code review checklist for this module:
 * - Never call eval() on untrusted input.
 * - Never pass request data through base64_decode() into an executable
 *   context; decode only for display, and always htmlspecialchars() it.
 */
echo "See CONTRIBUTING.md for the full secure-coding checklist.";
