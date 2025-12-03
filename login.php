<?php
// Start session
session_start();

// Database configuration - UPDATED FOR YOUR DATABASE
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';  // XAMPP default has no password
$db_name = 'simple_login';  // Your database name
$table_name = 'login_ajax';  // Your table name

// Create connection
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check connection
if ($conn->connect_error) {
    die("Database connection failed. Please check your MySQL is running.");
}

// Handle login request
if (isset($_POST['action']) && $_POST['action'] == 'login') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    
    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Please fill all fields']);
        exit;
    }
    
    // Check user in YOUR table: login_ajax
    $stmt = $conn->prepare("SELECT id, username, password, email, full_name FROM $table_name WHERE username = ? AND is_active = 1");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows == 1) {
        $user = $result->fetch_assoc();
        
        // Verify password
        if (password_verify($password, $user['password'])) {
            // Update last login time
            $update_stmt = $conn->prepare("UPDATE $table_name SET last_login = NOW() WHERE id = ?");
            $update_stmt->bind_param("i", $user['id']);
            $update_stmt->execute();
            $update_stmt->close();
            
            // Set session variables
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['logged_in'] = true;
            
            echo json_encode([
                'success' => true,
                'message' => 'Login successful!',
                'username' => $user['username'],
                'full_name' => $user['full_name'],
                'email' => $user['email']
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Wrong password']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'User not found or inactive']);
    }
    
    $stmt->close();
    exit;
}

// Handle logout
if (isset($_POST['action']) && $_POST['action'] == 'logout') {
    session_destroy();
    echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
    exit;
}

// Handle registration
if (isset($_POST['action']) && $_POST['action'] == 'register') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $email = trim($_POST['email']);
    $full_name = trim($_POST['full_name']);
    
    if (empty($username) || empty($password) || empty($email) || empty($full_name)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        exit;
    }
    
    // Check if username or email already exists
    $check_stmt = $conn->prepare("SELECT id FROM $table_name WHERE username = ? OR email = ?");
    $check_stmt->bind_param("ss", $username, $email);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    
    if ($check_result->num_rows > 0) {
        echo json_encode(['success' => false, 'message' => 'Username or email already exists']);
        $check_stmt->close();
        exit;
    }
    $check_stmt->close();
    
    // Hash password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    
    // Insert new user
    $insert_stmt = $conn->prepare("INSERT INTO $table_name (username, password, email, full_name, created_at, is_active) VALUES (?, ?, ?, ?, NOW(), 1)");
    $insert_stmt->bind_param("ssss", $username, $hashed_password, $email, $full_name);
    
    if ($insert_stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Registration successful! Please login.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Registration failed: ' . $conn->error]);
    }
    
    $insert_stmt->close();
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple Login System</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Arial', sans-serif;
        }
        
        body {
            background: wheat;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 450px;
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2575fc 0%, #6a11cb 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 14px;
        }
        
        .tab-container {
            display: flex;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }
        
        .tab {
            flex: 1;
            padding: 15px;
            background: none;
            border: none;
            font-size: 16px;
            font-weight: 600;
            color: #6c757d;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .tab.active {
            background: white;
            color: #2575fc;
            border-bottom: 3px solid #2575fc;
        }
        
        .form-container {
            padding: 30px;
        }
        
        .form {
            display: none;
        }
        
        .form.active {
            display: block;
            animation: fadeIn 0.5s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .input-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #495057;
            font-weight: 600;
            font-size: 14px;
        }
        
        input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: #2575fc;
            box-shadow: 0 0 0 3px rgba(37, 117, 252, 0.1);
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #2575fc 0%, #6a11cb 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(37, 117, 252, 0.2);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none !important;
        }
        
        .logout-btn {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        }
        
        .logout-btn:hover {
            box-shadow: 0 10px 20px rgba(220, 53, 69, 0.2);
        }
        
        .message {
            padding: 12px 15px;
            border-radius: 8px;
            margin-top: 20px;
            text-align: center;
            font-weight: 500;
            display: none;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            display: block;
        }
        
        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            display: block;
        }
        
        .user-info {
            text-align: center;
            padding: 30px;
        }
        
        .user-card {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            margin: 25px 0;
            border-left: 4px solid #2575fc;
            text-align: left;
        }
        
        .user-card p {
            margin: 10px 0;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }
        
        .user-card p:last-child {
            border-bottom: none;
        }
        
        .demo-section {
            background: #e9f7fe;
            padding: 20px;
            border-radius: 10px;
            margin-top: 25px;
            border: 1px solid #b3e5fc;
        }
        
        .demo-section h4 {
            color: #0d6efd;
            margin-bottom: 15px;
            text-align: center;
        }
        
        .demo-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            justify-content: center;
            margin-top: 10px;
        }
        
        .demo-btn {
            padding: 8px 15px;
            background: #0d6efd;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }
        
        .demo-btn:hover {
            background: #0b5ed7;
            transform: translateY(-2px);
        }
        
        .demo-credentials {
            font-size: 13px;
            color: #666;
            margin-top: 5px;
            text-align: center;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,0.3);
            border-top: 3px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .hidden {
            display: none !important;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 13px;
            border-top: 1px solid #e9ecef;
        }
        
        @media (max-width: 480px) {
            .container {
                margin: 10px;
                max-width: 100%;
            }
            
            .header, .form-container {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <?php if (isset($_SESSION['logged_in']) && $_SESSION['logged_in']): ?>
        <!-- Logged In View -->
        <div class="container">
            <div class="header">
                <h1>Welcome Back!</h1>
                <p>You are successfully logged into the system</p>
            </div>
            
            <div class="user-info">
                <div class="user-card">
                    <p><strong>👤 Username:</strong> <?php echo htmlspecialchars($_SESSION['username']); ?></p>
                    <p><strong>📧 Email:</strong> <?php echo htmlspecialchars($_SESSION['email']); ?></p>
                    <p><strong>👨‍💼 Full Name:</strong> <?php echo htmlspecialchars($_SESSION['full_name']); ?></p>
                    <p><strong>🟢 Status:</strong> <span style="color: #28a745;">✓ Active Session</span></p>
                </div>
                
                <button class="btn logout-btn" id="logoutBtn">
                    <span id="logoutBtnText">Logout</span>
                    <span id="logoutBtnLoading" class="hidden">
                        <span class="loading"></span>
                    </span>
                </button>
                
                <div id="message" class="message"></div>
            </div>
            
            <div class="footer">
                Simple Login System • Database: <?php echo $db_name; ?> • Table: <?php echo $table_name; ?>
            </div>
        </div>
    <?php else: ?>
        <!-- Login/Register View -->
        <div class="container">
            <div class="header">
                <h1>Simple Login System</h1>
                <p>Database: <?php echo $db_name; ?> • Table: <?php echo $table_name; ?></p>
            </div>
            
            <div class="tab-container">
                <button class="tab active" data-tab="login">🔑 Login</button>
                <button class="tab" data-tab="register">📝 Register</button>
            </div>
            
            <div class="form-container">
                <!-- Login Form -->
                <div id="loginForm" class="form active">
                    <form id="loginFormElement">
                        <div class="input-group">
                            <label for="loginUsername">Username</label>
                            <input type="text" id="loginUsername" name="username" placeholder="Enter your username" required>
                        </div>
                        
                        <div class="input-group">
                            <label for="loginPassword">Password</label>
                            <input type="password" id="loginPassword" name="password" placeholder="Enter your password" required>
                        </div>
                        
                        <button type="submit" class="btn" id="loginBtn">
                            <span id="loginBtnText">Login to System</span>
                            <span id="loginBtnLoading" class="hidden">
                                <span class="loading"></span>
                            </span>
                        </button>
                    </form>
                </div>
                
                <!-- Register Form -->
                <div id="registerForm" class="form">
                    <form id="registerFormElement">
                        <div class="input-group">
                            <label for="regFullName">Full Name</label>
                            <input type="text" id="regFullName" name="full_name" placeholder="Enter your full name" required>
                        </div>
                        
                        <div class="input-group">
                            <label for="regEmail">Email Address</label>
                            <input type="email" id="regEmail" name="email" placeholder="Enter your email" required>
                        </div>
                        
                        <div class="input-group">
                            <label for="regUsername">Username</label>
                            <input type="text" id="regUsername" name="username" placeholder="Choose a username" required>
                        </div>
                        
                        <div class="input-group">
                            <label for="regPassword">Password</label>
                            <input type="password" id="regPassword" name="password" placeholder="Choose a password" required>
                        </div>
                        
                        <button type="submit" class="btn" id="registerBtn">
                            <span id="registerBtnText">Create Account</span>
                            <span id="registerBtnLoading" class="hidden">
                                <span class="loading"></span>
                            </span>
                        </button>
                    </form>
                </div>
                
                <div id="message" class="message"></div>
                
                <div class="demo-section">
                    <h4>📋 Quick Test Accounts</h4>
                    <div class="demo-buttons">
                        <button class="demo-btn" onclick="fillCredentials('admin', 'admin123')">Use Admin</button>
                        <button class="demo-btn" onclick="fillCredentials('john', 'john123')">Use John</button>
                        <button class="demo-btn" onclick="fillCredentials('jane', 'jane123')">Use Jane</button>
                        <button class="demo-btn" onclick="fillCredentials('test', 'test123')">Use Test</button>
                    </div>
                    <p class="demo-credentials">These accounts must exist in your database</p>
                </div>
            </div>
            
            <div class="footer">
                Simple Login System • AJAX + PHP + MySQL • Database: <?php echo $db_name; ?>
            </div>
        </div>
    <?php endif; ?>

    <script>
        // Tab switching functionality
        document.addEventListener('DOMContentLoaded', function() {
            const tabs = document.querySelectorAll('.tab');
            const forms = document.querySelectorAll('.form');
            
            tabs.forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.tab;
                    
                    // Update active tab
                    tabs.forEach(t => t.classList.remove('active'));
                    this.classList.add('active');
                    
                    // Show corresponding form
                    forms.forEach(form => {
                        form.classList.remove('active');
                        if (form.id === tabName + 'Form') {
                            form.classList.add('active');
                        }
                    });
                    
                    // Clear messages
                    const message = document.getElementById('message');
                    if (message) message.style.display = 'none';
                });
            });
            
            // Login form submission
            const loginForm = document.getElementById('loginFormElement');
            if (loginForm) {
                loginForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    performLogin();
                });
            }
            
            // Register form submission
            const registerForm = document.getElementById('registerFormElement');
            if (registerForm) {
                registerForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    performRegister();
                });
            }
            
            // Logout button
            const logoutBtn = document.getElementById('logoutBtn');
            if (logoutBtn) {
                logoutBtn.addEventListener('click', function() {
                    performLogout();
                });
            }
            
            // Auto-fill first demo account for testing
            const usernameInput = document.getElementById('loginUsername');
            if (usernameInput && !usernameInput.value) {
                usernameInput.value = 'admin';
                document.getElementById('loginPassword').value = 'admin123';
            }
        });
        
        // Perform login via AJAX
        function performLogin() {
            const username = document.getElementById('loginUsername').value.trim();
            const password = document.getElementById('loginPassword').value;
            const loginBtn = document.getElementById('loginBtn');
            const loginBtnText = document.getElementById('loginBtnText');
            const loginBtnLoading = document.getElementById('loginBtnLoading');
            const message = document.getElementById('message');
            
            // Validate inputs
            if (!username || !password) {
                showMessage('Please enter both username and password', 'error');
                return;
            }
            
            // Show loading state
            loginBtn.disabled = true;
            loginBtnText.classList.add('hidden');
            loginBtnLoading.classList.remove('hidden');
            message.style.display = 'none';
            
            // Prepare form data
            const formData = new FormData();
            formData.append('action', 'login');
            formData.append('username', username);
            formData.append('password', password);
            
            // Send AJAX request
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    showMessage('✅ ' + data.message + ' Redirecting...', 'success');
                    // Reload page to show logged in view
                    setTimeout(() => {
                        window.location.reload();
                    }, 1500);
                } else {
                    showMessage('❌ ' + data.message, 'error');
                    loginBtn.disabled = false;
                    loginBtnText.classList.remove('hidden');
                    loginBtnLoading.classList.add('hidden');
                }
            })
            .catch(error => {
                showMessage('⚠️ Network error. Please try again.', 'error');
                console.error('Error:', error);
                loginBtn.disabled = false;
                loginBtnText.classList.remove('hidden');
                loginBtnLoading.classList.add('hidden');
            });
        }
        
        // Perform registration via AJAX
        function performRegister() {
            const full_name = document.getElementById('regFullName').value.trim();
            const email = document.getElementById('regEmail').value.trim();
            const username = document.getElementById('regUsername').value.trim();
            const password = document.getElementById('regPassword').value;
            const registerBtn = document.getElementById('registerBtn');
            const registerBtnText = document.getElementById('registerBtnText');
            const registerBtnLoading = document.getElementById('registerBtnLoading');
            const message = document.getElementById('message');
            
            // Validate all fields
            if (!full_name || !email || !username || !password) {
                showMessage('All fields are required', 'error');
                return;
            }
            
            // Validate email format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                showMessage('Please enter a valid email address', 'error');
                return;
            }
            
            // Validate password length
            if (password.length < 6) {
                showMessage('Password should be at least 6 characters', 'error');
                return;
            }
            
            // Show loading state
            registerBtn.disabled = true;
            registerBtnText.classList.add('hidden');
            registerBtnLoading.classList.remove('hidden');
            message.style.display = 'none';
            
            // Prepare form data
            const formData = new FormData();
            formData.append('action', 'register');
            formData.append('full_name', full_name);
            formData.append('email', email);
            formData.append('username', username);
            formData.append('password', password);
            
            // Send AJAX request
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage('✅ ' + data.message, 'success');
                    // Switch to login tab and clear form
                    setTimeout(() => {
                        document.querySelector('.tab[data-tab="login"]').click();
                        document.getElementById('registerFormElement').reset();
                        registerBtn.disabled = false;
                        registerBtnText.classList.remove('hidden');
                        registerBtnLoading.classList.add('hidden');
                    }, 2000);
                } else {
                    showMessage('❌ ' + data.message, 'error');
                    registerBtn.disabled = false;
                    registerBtnText.classList.remove('hidden');
                    registerBtnLoading.classList.add('hidden');
                }
            })
            .catch(error => {
                showMessage('⚠️ Network error. Please try again.', 'error');
                registerBtn.disabled = false;
                registerBtnText.classList.remove('hidden');
                registerBtnLoading.classList.add('hidden');
            });
        }
        
        // Perform logout via AJAX
        function performLogout() {
            const logoutBtn = document.getElementById('logoutBtn');
            const logoutBtnText = document.getElementById('logoutBtnText');
            const logoutBtnLoading = document.getElementById('logoutBtnLoading');
            const message = document.getElementById('message');
            
            logoutBtn.disabled = true;
            logoutBtnText.classList.add('hidden');
            logoutBtnLoading.classList.remove('hidden');
            message.style.display = 'none';
            
            const formData = new FormData();
            formData.append('action', 'logout');
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage('✅ ' + data.message + ' Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                }
            })
            .catch(error => {
                showMessage('⚠️ Logout error', 'error');
                logoutBtn.disabled = false;
                logoutBtnText.classList.remove('hidden');
                logoutBtnLoading.classList.add('hidden');
            });
        }
        
        // Show message function
        function showMessage(text, type) {
            const message = document.getElementById('message');
            if (message) {
                message.textContent = text;
                message.className = 'message ' + type;
                message.style.display = 'block';
                
                // Auto-hide success messages after 5 seconds
                if (type === 'success') {
                    setTimeout(() => {
                        message.style.display = 'none';
                    }, 5000);
                }
            }
        }
        
        // Fill demo credentials function
        function fillCredentials(username, password) {
            const loginUsername = document.getElementById('loginUsername');
            const loginPassword = document.getElementById('loginPassword');
            
            if (loginUsername && loginPassword) {
                loginUsername.value = username;
                loginPassword.value = password;
                showMessage(`Filled credentials for ${username}`, 'success');
                
                // Switch to login tab if not already there
                const loginTab = document.querySelector('.tab[data-tab="login"]');
                if (!loginTab.classList.contains('active')) {
                    loginTab.click();
                }
            }
        }
    </script>
</body>
</html>