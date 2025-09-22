package security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
	some msg in data.technological.no_latest_tag.deny
}

deny contains msg if {
	some msg in data.technological.no_plaintext_secrets.deny
}

default allow := false

allow if {
	count(deny) == 0
}
