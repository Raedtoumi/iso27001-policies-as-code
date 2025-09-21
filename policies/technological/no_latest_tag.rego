package technological.no_latest_tag

deny[msg] {
    input.containers[_].image == "latest"
    msg := "Container uses the 'latest' tag which is prohibited"
}