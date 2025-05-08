rule Base64_Obfuscation {
  meta:
    description = "Detects long Base64 strings typical of obfuscated code"
    author      = "Luigi Papalia"
    date        = "2025-05-08"

  strings:
    // Matches sequences of 40+ Base64 chars, with optional '=' padding
    $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/

  condition:
    $b64
}