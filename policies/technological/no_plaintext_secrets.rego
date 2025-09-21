package security

deny[msg] {
    some env
    re_match("(?i)secret", input.env[env])
} if {
    msg := sprintf("Environment variable contains potential plaintext secret: %s", [input.env[env]])
}
