<?php
// make_admin.php
// Run this once to make your account admin

$servername = "localhost";
$username   = "root";
$password   = "";
$dbname     = "phishing_db";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Your details
$email    = "hazrarupam222@gmail.com";
$plain_pw = "100";

// Bcrypt hash of your password
$hashedPassword = password_hash($plain_pw, PASSWORD_DEFAULT);

// Check if user exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    // Update existing user
    $stmt->close();
    $update = $conn->prepare("UPDATE users SET password=?, is_admin=1 WHERE email=?");
    $update->bind_param("ss", $hashedPassword, $email);
    if ($update->execute()) {
        echo "✅ User '$email' updated as ADMIN with password '$plain_pw'";
    } else {
        echo "❌ Error updating user: " . $conn->error;
    }
    $update->close();
} else {
    // Insert new user
    $stmt->close();
    $username = "Rupam";
    $insert = $conn->prepare("INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, 1)");
    $insert->bind_param("sss", $username, $email, $hashedPassword);
    if ($insert->execute()) {
        echo "✅ Admin user created! Email: $email | Password: $plain_pw";
    } else {
        echo "❌ Error inserting user: " . $conn->error;
    }
    $insert->close();
}

$conn->close();
?>
