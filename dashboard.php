<?php
require 'config.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$result = $conn->query("SELECT * FROM posts ORDER BY created_at DESC");
?>

<h2>Welcome <?= htmlspecialchars($_SESSION['username']) ?></h2>
<a href="create.php">Create New Post</a> | 
<a href="logout.php">Logout</a>
<hr>

<?php while ($row = $result->fetch_assoc()): ?>
    <h3><?= htmlspecialchars($row['title']) ?></h3>
    <p><?= nl2br(htmlspecialchars($row['content'])) ?></p>
    <small><?= $row['created_at'] ?></small><br>
    <a href="edit.php?id=<?= $row['id'] ?>">Edit</a> |
    <a href="delete.php?id=<?= $row['id'] ?>" onclick="return confirm('Delete this post?')">Delete</a>
    <hr>
<?php endwhile; ?>
