package kubernetes.security

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not container.securityContext.runAsNonRoot == true

  msg := sprintf("Container %v must run as non-root", [container.name])
}
