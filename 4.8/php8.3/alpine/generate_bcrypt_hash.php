<?php

// Prompt for password
echo "Enter password: ";
$inputPassword = trim(fgets(STDIN));

echo "Confirm password: ";
$confirmPassword = trim(fgets(STDIN));

// Check if passwords match
if ($inputPassword !== $confirmPassword) {
    echo "Error: Passwords do not match!\n";
    exit(1);
}

// Generate bcrypt hash
$hash = password_hash($inputPassword, PASSWORD_BCRYPT);

// Output the generated hash
echo "Generated bcrypt hash: " . $hash . "\n";
