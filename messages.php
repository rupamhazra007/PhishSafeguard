<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$servername="localhost"; $username="root"; $password=""; $dbname="phishing_db";
$conn=new mysqli($servername,$username,$password,$dbname);
if($conn->connect_error) die("Connection failed: ".$conn->connect_error);

$res=$conn->query("SELECT * FROM contact_messages ORDER BY submitted_at DESC");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Contact Messages</title>
<style>
body{font-family:Arial;background:#f5f5f5;padding:20px;}
table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 0 10px rgba(0,0,0,0.1);}
th,td{padding:10px;border:1px solid #ccc;text-align:left;}
th{background:#0b3d91;color:#fff;}
</style>
</head>
<body>
<h2>📩 Contact Messages</h2>
<table>
<tr><th>ID</th><th>Name</th><th>Email</th><th>Subject</th><th>Message</th><th>Submitted At</th></tr>
<?php while($row=$res->fetch_assoc()){ 
 echo "<tr>
   <td>{$row['id']}</td>
   <td>{$row['name']}</td>
   <td>{$row['email']}</td>
   <td>{$row['subject']}</td>
   <td>{$row['message']}</td>
   <td>{$row['submitted_at']}</td>
 </tr>";
} ?>
</table>
</body>
</html>
