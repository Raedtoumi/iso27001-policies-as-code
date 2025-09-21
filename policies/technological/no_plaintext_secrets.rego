package technological.no_plaintext_secrets

deny[msg] {
    some secret in input.secrets
    secret.encrypted == false
    msg := sprintf("Secret '%s' is stored in plaintext", [secret.name])
}