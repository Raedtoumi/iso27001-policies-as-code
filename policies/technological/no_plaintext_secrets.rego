package security

# Deny if any environment variable contains the word "SECRET"
deny[msg] {
    some i
    input.env[i] != null
    contains(tolower(input.env[i]), "secret")
    msg := sprintf("Environment variable contains plaintext secret: %s", [input.env[i]])
}
