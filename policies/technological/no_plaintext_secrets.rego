package technological.no_plaintext_secrets

import future.keywords.contains
import future.keywords.if

deny contains msg if {
	some secret in input.secrets
	not secret.encrypted
	msg := sprintf("Secret '%s' is stored in plaintext", [secret.name])
}
