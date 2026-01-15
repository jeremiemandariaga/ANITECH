<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
header('Content-Type: application/json');

$host = 'localhost';
$db   = 'anitech';
$user = 'root';
$pass = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';

// ===== SIGNUP =====
if ($action === 'signup') {
    $name = trim($input['name'] ?? '');
    $email = trim($input['email'] ?? '');
    $password = $input['password'] ?? '';
    $account_type = in_array($input['account_type'], ['admin','secretary','farmer']) ? $input['account_type'] : 'farmer';

    if (!$name || !$email || !$password) {
        echo json_encode(['success' => false, 'message' => 'All fields are required.']);
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => 'Invalid email address.']);
        exit;
    }

    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        echo json_encode(['success' => false, 'message' => 'Email is already registered.']);
        exit;
    }

    $hashed = password_hash($password, PASSWORD_DEFAULT);
    $pdo->prepare("INSERT INTO users (name, email, password, account_type) VALUES (?, ?, ?, ?)")
        ->execute([$name, $email, $hashed, $account_type]);

    echo json_encode(['success' => true, 'message' => 'Account created successfully!']);
    exit;
}

// ===== LOGIN =====
if ($action === 'login') {
    $email = trim($input['email'] ?? '');
    $password = $input['password'] ?? '';
    $account_type = in_array($input['account_type'], ['admin','secretary','farmer']) ? $input['account_type'] : 'farmer';

    if (!$email || !$password) {
        echo json_encode(['success' => false, 'message' => 'Email and password are required.']);
        exit;
    }

    $stmt = $pdo->prepare("SELECT id, name, email, password, account_type FROM users WHERE email = ? AND account_type = ?");
    $stmt->execute([$email, $account_type]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_name'] = $user['name'];
        $_SESSION['account_type'] = $user['account_type'];

        echo json_encode([
            'success' => true,
            'message' => 'Login successful!',
            'redirect' => 'dashboard.php'
        ]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid email, password, or account type.']);
    }
    exit;
}

echo json_encode(['success' => false, 'message' => 'Unknown action.']);
?>