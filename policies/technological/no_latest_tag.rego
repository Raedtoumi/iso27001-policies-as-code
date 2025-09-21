package technological.no_latest_tag

deny[msg] {
    some i
    container := input.containers[i]
    endswith(container.image, ":latest")
    msg := sprintf("Container '%s' uses prohibited 'latest' tag: %s", [container.name, container.image])
}