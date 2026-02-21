<?php
// report.php
session_start();
$servername="localhost"; $username="root"; $password=""; $dbname="phishing_db";
$conn=new mysqli($servername,$username,$password,$dbname);
if($conn->connect_error) die("Connection failed: ".$conn->connect_error);

if($_SERVER['REQUEST_METHOD']==='POST'){
    $url = isset($_POST['url']) ? trim($_POST['url']) : '';
    $name = isset($_POST['name']) ? trim($_POST['name']) : 'Anonymous';
    $email = isset($_POST['email']) ? trim($_POST['email']) : '';
    $note = isset($_POST['note']) ? trim($_POST['note']) : '';

    $stmt = $conn->prepare("INSERT INTO reports (url,reporter,email,note) VALUES (?,?,?,?)");
    $stmt->bind_param('ssss',$url,$name,$email,$note);
    $stmt->execute();
    $stmt->close();

    $_SESSION['msg'] = "Report submitted. Thanks for helping the community!";
    header("Location: index.php");
    exit();
}
header("Location: index.php");
exit();
