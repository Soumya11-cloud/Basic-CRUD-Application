<?php
require 'config.php';
if (!isset($_SESSION['user_id'])) header("Location: login.php");

$id = (int)$_GET['id'];
$conn->query("DELETE FROM posts WHERE id = $id");

header("Location: dashboard.php");
?>
