package security

default allow = false

# Deny if secrets contain hardcoded values
allow {
  not input.spec.template.spec.containers[_].env[_].value
}
