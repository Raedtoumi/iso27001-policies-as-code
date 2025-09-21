package security

deny[msg] {
    some i
    input.env[i] != null
    contains(tolower(input.env[i]), "secret")
    msg := sprintf("Environment variable contains plaintext secret: %s", [input.env[i]])
}
