package armo_builtins

deny[msga] {
  resource := input[_]
  resource.kind == "Pod"
  not exempt_namespace(resource.metadata.namespace)
  container := resource.spec.containers[idx]
  not readonly_root_fs(container)
  failed_path := sprintf("spec.containers[%d].securityContext.readOnlyRootFilesystem", [idx])
  msga := {
    "alertMessage": sprintf("container '%s' does not enforce a read-only root filesystem", [container.name]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "fixPaths": [{"path": failed_path, "value": "true"}],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  resource.kind == "Pod"
  not exempt_namespace(resource.metadata.namespace)
  container := resource.spec.initContainers[idx]
  not readonly_root_fs(container)
  failed_path := sprintf("spec.initContainers[%d].securityContext.readOnlyRootFilesystem", [idx])
  msga := {
    "alertMessage": sprintf("container '%s' does not enforce a read-only root filesystem", [container.name]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "fixPaths": [{"path": failed_path, "value": "true"}],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  is_workload_kind(resource.kind)
  not exempt_namespace(resource.metadata.namespace)
  container := resource.spec.template.spec.containers[idx]
  not readonly_root_fs(container)
  failed_path := sprintf("spec.template.spec.containers[%d].securityContext.readOnlyRootFilesystem", [idx])
  msga := {
    "alertMessage": sprintf("container '%s' does not enforce a read-only root filesystem", [container.name]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "fixPaths": [{"path": failed_path, "value": "true"}],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  is_workload_kind(resource.kind)
  not exempt_namespace(resource.metadata.namespace)
  container := resource.spec.template.spec.initContainers[idx]
  not readonly_root_fs(container)
  failed_path := sprintf("spec.template.spec.initContainers[%d].securityContext.readOnlyRootFilesystem", [idx])
  msga := {
    "alertMessage": sprintf("container '%s' does not enforce a read-only root filesystem", [container.name]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "fixPaths": [{"path": failed_path, "value": "true"}],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  resource.kind == "CronJob"
  not exempt_namespace(resource.metadata.namespace)
  container := resource.spec.jobTemplate.spec.template.spec.containers[idx]
  not readonly_root_fs(container)
  failed_path := sprintf("spec.jobTemplate.spec.template.spec.containers[%d].securityContext.readOnlyRootFilesystem", [idx])
  msga := {
    "alertMessage": sprintf("container '%s' does not enforce a read-only root filesystem", [container.name]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "fixPaths": [{"path": failed_path, "value": "true"}],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  resource.kind == "CronJob"
  not exempt_namespace(resource.metadata.namespace)
  container := resource.spec.jobTemplate.spec.template.spec.initContainers[idx]
  not readonly_root_fs(container)
  failed_path := sprintf("spec.jobTemplate.spec.template.spec.initContainers[%d].securityContext.readOnlyRootFilesystem", [idx])
  msga := {
    "alertMessage": sprintf("container '%s' does not enforce a read-only root filesystem", [container.name]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "fixPaths": [{"path": failed_path, "value": "true"}],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

readonly_root_fs(container) {
  object.get(object.get(container, "securityContext", {}), "readOnlyRootFilesystem", false) == true
}

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
