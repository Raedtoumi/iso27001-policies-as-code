package security

# Import and aggregate all policy decisions
import data.technological.no_latest_tag.deny as latest_tag_deny
import data.technological.no_plaintext_secrets.deny as plaintext_secrets_deny

deny[msg] {
    msg := latest_tag_deny[_]
}

deny[msg] {
    msg := plaintext_secrets_deny[_]
}

# Main decision rule
default allow = false

allow {
    count(deny) == 0
}