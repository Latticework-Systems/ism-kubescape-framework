package armo_builtins

# Match upstream Kubescape privileged-container semantics and retain local
# initContainer coverage.
deny[msga] {
  resource := input[_]
  resource.kind == "Pod"
  container := resource.spec.containers[idx]
  failed_paths := privileged_paths(container, idx, "spec.", "containers")
  count(failed_paths) > 0
  msga := violation(resource, container.name, failed_paths)
}

deny[msga] {
  resource := input[_]
  resource.kind == "Pod"
  container := resource.spec.initContainers[idx]
  failed_paths := privileged_paths(container, idx, "spec.", "initContainers")
  count(failed_paths) > 0
  msga := violation(resource, container.name, failed_paths)
}

deny[msga] {
  resource := input[_]
  resource.kind == "Pod"
  container := resource.spec.ephemeralContainers[idx]
  failed_paths := privileged_paths(container, idx, "spec.", "ephemeralContainers")
  count(failed_paths) > 0
  msga := violation(resource, container.name, failed_paths)
}

deny[msga] {
  resource := input[_]
  is_workload_kind(resource.kind)
  container := resource.spec.template.spec.containers[idx]
  failed_paths := privileged_paths(container, idx, "spec.template.spec.", "containers")
  count(failed_paths) > 0
  msga := violation(resource, container.name, failed_paths)
}

deny[msga] {
  resource := input[_]
  is_workload_kind(resource.kind)
  container := resource.spec.template.spec.initContainers[idx]
  failed_paths := privileged_paths(container, idx, "spec.template.spec.", "initContainers")
  count(failed_paths) > 0
  msga := violation(resource, container.name, failed_paths)
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

deny[msga] {
  resource := input[_]
  resource.kind == "CronJob"
  container := resource.spec.jobTemplate.spec.template.spec.containers[idx]
  failed_paths := privileged_paths(container, idx, "spec.jobTemplate.spec.template.spec.", "containers")
  count(failed_paths) > 0
  msga := violation(resource, container.name, failed_paths)
}

deny[msga] {
  resource := input[_]
  resource.kind == "CronJob"
  container := resource.spec.jobTemplate.spec.template.spec.initContainers[idx]
  failed_paths := privileged_paths(container, idx, "spec.jobTemplate.spec.template.spec.", "initContainers")
  count(failed_paths) > 0
  msga := violation(resource, container.name, failed_paths)
}

violation(resource, container_name, failed_paths) = result {
  result := {
    "alertMessage": sprintf("container '%s' is privileged or adds SYS_ADMIN", [container_name]),
    "packagename": "armo_builtins",
    "alertScore": 9,
    "failedPaths": failed_paths,
    "deletePaths": failed_paths,
    "fixPaths": [],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

privileged_paths(container, idx, start_of_path, container_type) = paths {
  security_context := object.get(container, "securityContext", {})
  capability_paths := [sprintf("%s%s[%d].securityContext.capabilities.add[%d]", [start_of_path, container_type, idx, cap_idx]) |
    capability := object.get(object.get(security_context, "capabilities", {}), "add", [])[cap_idx]
    capability == "SYS_ADMIN"
  ]
  privileged_path := [path |
    object.get(security_context, "privileged", false) == true
    path := sprintf("%s%s[%d].securityContext.privileged", [start_of_path, container_type, idx])
  ]
  paths := array.concat(capability_paths, privileged_path)
}
