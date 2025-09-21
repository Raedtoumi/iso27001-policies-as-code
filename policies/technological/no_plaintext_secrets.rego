package technological.no_plaintext_secrets

deny[msg] {
    some i
    secret := input.secrets[i]
    not secret.encrypted
    msg := sprintf("Secret '%s' is stored in plaintext", [secret.name])
}