package security

allow {
    not deny
}

deny[msg] {
    data.technological.no_latest_tag.deny[_]
}

deny[msg] {
    data.technological.no_plaintext_secrets.deny[_]
}