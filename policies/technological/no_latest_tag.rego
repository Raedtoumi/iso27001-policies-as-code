package security

deny[msg] {
    some container
    input.containers[container].tag == "latest"
} if {
    msg := sprintf("Container %s uses 'latest' tag", [input.containers[container].name])
}
