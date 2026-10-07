package armo_builtins

deny[msga] {
  resource := input[_]
  spec := workload_spec(resource)
  not exempt_namespace(object.get(resource.metadata, "namespace", "default"))
  container := spec.containers[idx]
  not drops_all(container)
  failed_path := sprintf("%s.containers[%d].securityContext.capabilities.drop", [spec_path(resource.kind), idx])
  msga := finding(resource, container.name, failed_path)
}

deny[msga] {
  resource := input[_]
  spec := workload_spec(resource)
  not exempt_namespace(object.get(resource.metadata, "namespace", "default"))
  container := spec.initContainers[idx]
  not drops_all(container)
  failed_path := sprintf("%s.initContainers[%d].securityContext.capabilities.drop", [spec_path(resource.kind), idx])
  msga := finding(resource, container.name, failed_path)
}

# Dropping ALL and then adding capabilities back restores them, so added
# capabilities fail too. The Pod Security Standards restricted profile allows
# only NET_BIND_SERVICE to be added back.
deny[msga] {
  resource := input[_]
  spec := workload_spec(resource)
  not exempt_namespace(object.get(resource.metadata, "namespace", "default"))
  container := spec.containers[idx]
  added := disallowed_added(container)
  count(added) > 0
  failed_path := sprintf("%s.containers[%d].securityContext.capabilities.add", [spec_path(resource.kind), idx])
  msga := add_back_finding(resource, container.name, added, failed_path)
}

deny[msga] {
  resource := input[_]
  spec := workload_spec(resource)
  not exempt_namespace(object.get(resource.metadata, "namespace", "default"))
  container := spec.initContainers[idx]
  added := disallowed_added(container)
  count(added) > 0
  failed_path := sprintf("%s.initContainers[%d].securityContext.capabilities.add", [spec_path(resource.kind), idx])
  msga := add_back_finding(resource, container.name, added, failed_path)
}

capabilities(container) := object.get(object.get(container, "securityContext", {}), "capabilities", {})

drops_all(container) {
  drop := object.get(capabilities(container), "drop", [])
  upper(drop[_]) == "ALL"
}

# Kubernetes accepts capability names with or without the CAP_ prefix.
disallowed_added(container) := {name |
  cap := object.get(capabilities(container), "add", [])[_]
  name := trim_prefix(upper(cap), "CAP_")
  name != "NET_BIND_SERVICE"
}

finding(resource, name, path) := {
  "alertMessage": sprintf("container '%s' does not drop all Linux capabilities", [name]),
  "packagename": "armo_builtins",
  "alertScore": 7,
  "failedPaths": [path],
  "fixPaths": [],
  "alertObject": {"k8sApiObjects": [resource]}
}

add_back_finding(resource, name, added, path) := {
  "alertMessage": sprintf("container '%s' adds Linux capabilities: %s", [name, concat(", ", sort(added))]),
  "packagename": "armo_builtins",
  "alertScore": 7,
  "failedPaths": [path],
  "fixPaths": [],
  "alertObject": {"k8sApiObjects": [resource]}
}

workload_spec(resource) := resource.spec { resource.kind == "Pod" }
workload_spec(resource) := resource.spec.template.spec { is_workload_kind(resource.kind) }
workload_spec(resource) := resource.spec.jobTemplate.spec.template.spec { resource.kind == "CronJob" }
spec_path(kind) := "spec" { kind == "Pod" }
spec_path(kind) := "spec.template.spec" { is_workload_kind(kind) }
spec_path(kind) := "spec.jobTemplate.spec.template.spec" { kind == "CronJob" }
is_workload_kind(kind) { kind == "Deployment" }
is_workload_kind(kind) { kind == "ReplicaSet" }
is_workload_kind(kind) { kind == "DaemonSet" }
is_workload_kind(kind) { kind == "StatefulSet" }
is_workload_kind(kind) { kind == "Job" }
exempt_namespace(namespace) { namespace == "kube-system" }
exempt_namespace(namespace) { namespace == "kube-public" }
exempt_namespace(namespace) { namespace == "kube-node-lease" }
