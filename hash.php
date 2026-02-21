<?php
$password = "100"; // তোমার আসল password
$hash = password_hash($password, PASSWORD_DEFAULT);
echo $hash;
?>
