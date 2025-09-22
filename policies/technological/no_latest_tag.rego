package technological.no_latest_tag

import future.keywords.contains
import future.keywords.if

deny contains msg if {
	some container in input.containers
	endswith(container.image, ":latest")
	msg := sprintf("Container '%s' uses prohibited 'latest' tag: %s", [container.name, container.image])
}
