<?php
if (session_status() === PHP_SESSION_NONE) session_start();

function db() {
  $conn = new mysqli("localhost","root","","phishing_db");
  if ($conn->connect_error) die("DB Error: ".$conn->connect_error);
  $conn->set_charset("utf8mb4");
  return $conn;
}

function current_user() {
  return [
    'id' => $_SESSION['user_id'] ?? null,
    'username' => $_SESSION['username'] ?? null,
    'is_admin' => $_SESSION['is_admin'] ?? 0,
    'lang' => $_SESSION['lang'] ?? 'en'
  ];
}

function t($key) {
  $lang = $_SESSION['lang'] ?? 'en';
  $dict = [
    'en'=>[
      'welcome'=>'Welcome',
      'logout'=>'Logout',
      'home'=>'Home',
      'about'=>'About',
      'contact'=>'Contact Us',
      'history'=>'History',
      'admin'=>'Admin',
      'check_url'=>'Check a URL',
      'stats'=>'URL Analysis',
      'monthly'=>'Monthly URL Checks',
      'safe'=>'Safe',
      'phishing'=>'Phishing'
    ],
    'bn'=>[
      'welcome'=>'স্বাগতম',
      'logout'=>'লগআউট',
      'home'=>'হোম',
      'about'=>'এবাউট',
      'contact'=>'কন্ট্যাক্ট',
      'history'=>'হিস্টরি',
      'admin'=>'অ্যাডমিন',
      'check_url'=>'একটি URL চেক করুন',
      'stats'=>'URL বিশ্লেষণ',
      'monthly'=>'মাসিক URL চেক',
      'safe'=>'সেইফ',
      'phishing'=>'ফিশিং'
    ]
  ];
  return $dict[$lang][$key] ?? $key;
}

function ensure_auth() {
  if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
  }
}
