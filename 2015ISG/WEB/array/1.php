 <?php

if(empty($_GET['user'])) echo "error";
$user = ['admin', (string)time()];
$test = array(-9223372036854775808 => 'admin',1 => (string)time() );
$flag = "hehe";
echo (string)time();
echo $test[0];
if($test === $user && $test[0] != 'admin'){echo $flag;}
?>