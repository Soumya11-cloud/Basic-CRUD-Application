<?php
require 'config.php';
if (!isset($_SESSION['user_id'])) header("Location: login.php");

$id = (int)$_GET['id'];
$post = $conn->query("SELECT * FROM posts WHERE id = $id")->fetch_assoc();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $title = trim($_POST['title']);
    $content = trim($_POST['content']);

    $stmt = $conn->prepare("UPDATE posts SET title=?, content=? WHERE id=?");
    $stmt->bind_param("ssi", $title, $content, $id);
    $stmt->execute();

    header("Location: dashboard.php");
}
?>

<h2>Edit Post</h2>
<form method="post">
    <input type="text" name="title" value="<?= htmlspecialchars($post['title']) ?>" required><br><br>
    <textarea name="content" rows="5" cols="30" required><?= htmlspecialchars($post['content']) ?></textarea><br><br>
    <button type="submit">Update</button>
</form>
