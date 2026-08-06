package armo_builtins

deny[msga] {
  namespace := input[_]
  namespace.kind == "Namespace"
  not is_system_namespace(namespace.metadata.name)
  not terminating_namespace(namespace)
  not restricted_pss(namespace)
  msga := {
    "alertMessage": sprintf("namespace '%s' does not enforce the restricted Pod Security Standard", [namespace.metadata.name]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": ["metadata.labels[pod-security.kubernetes.io/enforce]"],
    "fixPaths": [
      {
        "path": "metadata.labels[pod-security.kubernetes.io/enforce]",
        "value": "restricted"
      }
    ],
    "alertObject": {
      "k8sApiObjects": [namespace]
    }
  }
}

restricted_pss(namespace) {
  namespace.metadata.labels["pod-security.kubernetes.io/enforce"] == "restricted"
}

terminating_namespace(namespace) {
  object.get(namespace, "status", {}).phase == "Terminating"
}

is_system_namespace(name) {
  name == "kube-system"
}

is_system_namespace(name) {
  name == "kube-public"
}

is_system_namespace(name) {
  name == "kube-node-lease"
}

is_system_namespace(name) {
  name == "kubescape"
}
