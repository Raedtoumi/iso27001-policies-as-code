package technological.no_latest_tag

deny[msg] {
    some container in input.containers
    container.image == "latest"
    msg := sprintf("Container '%s' uses the 'latest' tag which is prohibited", [container.name])
}