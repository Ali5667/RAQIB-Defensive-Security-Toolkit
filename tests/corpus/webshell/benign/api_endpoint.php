<?php
header('Content-Type: application/json');
$stmt = $mysqli->prepare("SELECT id, name FROM products WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
echo json_encode($stmt->get_result()->fetch_assoc());
