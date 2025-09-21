package security

default allow = false

# Deny Docker images using :latest
allow {
  input.kind == "Deployment"
  not endswith(input.spec.template.spec.containers[_].image, ":latest")
}