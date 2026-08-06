package armo_builtins

deny[msga] {
  binding := input[_]
  binding.kind == "ClusterRoleBinding"
  subject := binding.subjects[idx]
  subject.kind == "ServiceAccount"
  not exempt_serviceaccount(binding, subject)
  path := sprintf("subjects[%d]", [idx])
  msga := {
    "alertMessage": sprintf("ClusterRoleBinding '%s' grants cluster-wide access to service account '%s/%s'", [binding.metadata.name, object.get(subject, "namespace", "default"), subject.name]),
    "packagename": "armo_builtins",
    "alertScore": 8,
    "failedPaths": [path],
    "reviewPaths": [path],
    "fixPaths": [],
    "alertObject": {
      "k8sApiObjects": [binding]
    }
  }
}

# Exempt Kubernetes controller bindings: a system: ClusterRole bound to a
# kube-system service account. Require both fields. A binding name or subject
# namespace alone does not identify a controller binding.
exempt_serviceaccount(binding, subject) {
  startswith(binding.roleRef.name, "system:")
  namespace := object.get(subject, "namespace", "")
  namespace == "kube-system"
}

# Kubescape operator namespace
exempt_serviceaccount(binding, subject) {
  namespace := object.get(subject, "namespace", "")
  namespace == "kubescape"
  startswith(binding.metadata.name, "kubescape")
}

# Service mesh control plane
exempt_serviceaccount(binding, subject) {
  namespace := object.get(subject, "namespace", "")
  namespace == "istio-system"
  subject.name == "istiod"
  startswith(binding.metadata.name, "istio")
}

# Istio's CNI plugin uses its own service account rather than istiod.
exempt_serviceaccount(binding, subject) {
  namespace := object.get(subject, "namespace", "")
  namespace == "istio-system"
  subject.name == "istio-cni"
  startswith(binding.metadata.name, "istio-cni")
}

# Certificate management
exempt_serviceaccount(binding, subject) {
  namespace := object.get(subject, "namespace", "")
  namespace == "cert-manager"
  subject.name == "cert-manager"
  startswith(binding.metadata.name, "cert-manager-")
}

# Policy engine (Kyverno itself requires cluster-wide ClusterRoleBindings)
exempt_serviceaccount(binding, subject) {
  namespace := object.get(subject, "namespace", "")
  namespace == "kyverno"
  startswith(subject.name, "kyverno-")
  kyverno_binding_name(binding.metadata.name)
}

# Kyverno uses both kyverno:<controller> and kyverno-<controller> binding
# names across releases.
kyverno_binding_name(name) {
  startswith(name, "kyverno:")
}

kyverno_binding_name(name) {
  startswith(name, "kyverno-")
}
