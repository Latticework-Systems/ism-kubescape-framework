package armo_builtins

deny[msga] {
  resource := input[_]
  labels := workload_labels(resource)
  namespace := workload_namespace(resource)
  not exempt_namespace(namespace)
  not selected_by_ingress_policy(namespace, labels)
  msga := {
    "alertMessage": sprintf("%s '%s' is not selected by both ingress and egress NetworkPolicies", [resource.kind, resource.metadata.name]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [],
    "fixPaths": [],
    "alertObject": {
      "k8sApiObjects": [resource]
    }
  }
}

deny[msga] {
  resource := input[_]
  labels := workload_labels(resource)
  namespace := workload_namespace(resource)
  not exempt_namespace(namespace)
  selected_by_ingress_policy(namespace, labels)
  not selected_by_egress_policy(namespace, labels)
  msga := {
    "alertMessage": sprintf("%s '%s' is not selected by both ingress and egress NetworkPolicies", [resource.kind, resource.metadata.name]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [],
    "fixPaths": [],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

selected_by_ingress_policy(namespace, labels) {
  policy := input[_]
  policy.kind == "NetworkPolicy"
  policy_namespace(policy) == namespace
  policy_has_ingress(policy)
  selector_matches(policy.spec.podSelector, labels)
}

selected_by_egress_policy(namespace, labels) {
  policy := input[_]
  policy.kind == "NetworkPolicy"
  policy_namespace(policy) == namespace
  policy_has_egress(policy)
  selector_matches(policy.spec.podSelector, labels)
}

policy_has_egress(policy) {
  policy.spec.policyTypes[_] == "Egress"
}

policy_has_egress(policy) {
  count(object.get(policy.spec, "egress", [])) > 0
}

policy_has_ingress(policy) {
  policy.spec.policyTypes[_] == "Ingress"
}

policy_has_ingress(policy) {
  count(object.get(policy.spec, "ingress", [])) > 0
}

selector_matches(selector, _) {
  count(selector) == 0
}

selector_matches(selector, labels) {
  match_labels := object.get(selector, "matchLabels", {})
  count(match_labels) > 0
  count({key | match_labels[key] == labels[key]}) == count(match_labels)
}

workload_labels(resource) := object.get(resource.metadata, "labels", {}) {
  resource.kind == "Pod"
}

workload_labels(resource) := object.get(resource.spec.template.metadata, "labels", {}) {
  is_workload_kind(resource.kind)
}

workload_labels(resource) := object.get(resource.spec.jobTemplate.spec.template.metadata, "labels", {}) {
  resource.kind == "CronJob"
}

workload_namespace(resource) := object.get(resource.metadata, "namespace", "default") {
  resource.kind == "Pod"
}

workload_namespace(resource) := object.get(resource.metadata, "namespace", "default") {
  is_workload_kind(resource.kind)
}

workload_namespace(resource) := object.get(resource.metadata, "namespace", "default") {
  resource.kind == "CronJob"
}

policy_namespace(policy) := object.get(policy.metadata, "namespace", "default")

exempt_namespace(namespace) {
  namespace == "kube-system"
}

exempt_namespace(namespace) {
  namespace == "kube-public"
}

exempt_namespace(namespace) {
  namespace == "kube-node-lease"
}

is_workload_kind(kind) {
  kind == "Deployment"
}

is_workload_kind(kind) {
  kind == "ReplicaSet"
}

is_workload_kind(kind) {
  kind == "DaemonSet"
}

is_workload_kind(kind) {
  kind == "StatefulSet"
}

is_workload_kind(kind) {
  kind == "Job"
}
