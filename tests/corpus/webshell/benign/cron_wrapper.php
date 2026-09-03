<?php
// Nightly maintenance wrapper invoked by system cron, no user input involved.
exec('/usr/bin/php /var/www/scripts/cleanup.php >> /var/log/cleanup.log 2>&1');
