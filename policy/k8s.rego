package kubernetes.security

deny contains msg if {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  container.securityContext.runAsNonRoot != true

  msg := sprintf("Container %s must run as non-root", [container.name])
}
