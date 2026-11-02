<?php
// Generates a 16-character Base32 secret for the Google Authenticator App
function generateMfaSecret() {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < 16; $i++) {
        $secret .= $chars[random_int(0, 31)];
    }
    return $secret;
}

// Verifies the 6-digit token against the secret, allowing for slight clock drift
function verifyMfaToken($secret, $code) {
    $base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $base32charsFlipped = array_flip(str_split($base32chars));
    $secret = strtoupper(str_replace('=', '', $secret));
    $binaryString = '';
    
    // Decode Base32 string to binary
    foreach (str_split($secret) as $char) {
        if (isset($base32charsFlipped[$char])) {
            $binaryString .= str_pad(decbin($base32charsFlipped[$char]), 5, '0', STR_PAD_LEFT);
        }
    }
    
    $decodedSecret = '';
    foreach (str_split($binaryString, 8) as $chunk) {
        if (strlen($chunk) == 8) {
            $decodedSecret .= chr(bindec($chunk));
        }
    }
    
    $currentTimeSlice = floor(time() / 30);
    
    // Check current 30-second time slice, plus/minus 1 window (to account for network delay/clock drift)
    for ($i = -1; $i <= 1; $i++) {
        $timeSlice = $currentTimeSlice + $i;
        $timePacked = pack('N*', 0) . pack('N*', $timeSlice);
        $hash = hash_hmac('sha1', $timePacked, $decodedSecret, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        
        $value = unpack('N', substr($hash, $offset, 4));
        $value = $value[1] & 0x7FFFFFFF;
        $calculatedCode = str_pad($value % 1000000, 6, '0', STR_PAD_LEFT);
        
        if (hash_equals($calculatedCode, str_pad($code, 6, '0', STR_PAD_LEFT))) {
            return true;
        }
    }
    return false;
}
?>