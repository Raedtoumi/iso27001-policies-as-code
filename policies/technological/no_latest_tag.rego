package security

deny[msg] {
    some i
    input.containers[i].tag == "latest"
    msg := sprintf("Container %s uses 'latest' tag", [input.containers[i].name])
}
