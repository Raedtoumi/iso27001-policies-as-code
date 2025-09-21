package main

# Aggregate all policy decisions
deny[msg] {
    msg := data.technological.no_latest_tag.deny[_]
}

deny[msg] {
    msg := data.technological.no_plaintext_secrets.deny[_]
}

# Main decision rule
allow {
    count(deny) == 0
}

allow = false {
    count(deny) > 0
}