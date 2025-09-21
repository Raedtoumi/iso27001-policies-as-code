package technological.no_plaintext_secrets

deny[msg] {
    secret := input.secrets[_]
    not secret.encrypted
    msg := sprintf("Secret '%s' is stored in plaintext", [secret.name])
}