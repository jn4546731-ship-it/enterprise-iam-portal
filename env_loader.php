<?php
/**
 * Lightweight Enterprise Environment Variable Loader
 * Zero-dependency native PHP 8 implementation.
 * Loads variables from .env into $_ENV, $_SERVER, and putenv().
 */

function loadEnv(string $filePath): bool {
    if (!file_exists($filePath)) {
        return false;
    }

    $rawContent = @file_get_contents($filePath);
    if ($rawContent === false) {
        return false;
    }

    // Normalize Windows CRLF to LF
    $rawContent = str_replace("\r\n", "\n", $rawContent);
    $lines = explode("\n", $rawContent);

    foreach ($lines as $line) {
        $line = trim($line);

        // Skip comments and empty lines
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }

        // Split at the first '=' character
        $separatorPos = strpos($line, '=');
        if ($separatorPos === false) {
            continue;
        }

        $key = trim(substr($line, 0, $separatorPos));
        $value = trim(substr($line, $separatorPos + 1));

        // Strip inline comments if not inside quotes
        if (!str_starts_with($value, '"') && !str_starts_with($value, "'")) {
            $commentPos = strpos($value, ' #');
            if ($commentPos !== false) {
                $value = trim(substr($value, 0, $commentPos));
            }
        }

        // Strip matching outer quotes
        if (
            (str_starts_with($value, '"') && str_ends_with($value, '"')) ||
            (str_starts_with($value, "'") && str_ends_with($value, "'"))
        ) {
            $value = substr($value, 1, -1);
        }

        // Assign to environment superglobals
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
        putenv("{$key}={$value}");
    }

    return true;
}

/**
 * Safe accessor function for environment variables with fallback default.
 */
function env(string $key, mixed $default = null): mixed {
    if (isset($_ENV[$key])) {
        return $_ENV[$key];
    }
    if (isset($_SERVER[$key])) {
        return $_SERVER[$key];
    }
    $val = getenv($key);
    if ($val !== false) {
        return $val;
    }
    return $default;
}
