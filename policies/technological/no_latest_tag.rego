package security

# Deny if container image uses the "latest" tag
deny[msg] {
    input.image.tag == "latest"
    msg := "Do not use 'latest' tag for container images."
}
