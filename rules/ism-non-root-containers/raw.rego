package armo_builtins

deny[msga] {
  resource := input[_]
  spec := workload_spec(resource)
  not exempt_namespace(object.get(resource.metadata, "namespace", "default"))
  container := spec.containers[idx]
  not runs_as_non_root(spec, container)
  failed_path := sprintf("%s.containers[%d].securityContext.runAsNonRoot", [spec_path(resource.kind), idx])
  msga := finding(resource, container.name, failed_path)
}

deny[msga] {
  resource := input[_]
  spec := workload_spec(resource)
  not exempt_namespace(object.get(resource.metadata, "namespace", "default"))
  container := spec.initContainers[idx]
  not runs_as_non_root(spec, container)
  failed_path := sprintf("%s.initContainers[%d].securityContext.runAsNonRoot", [spec_path(resource.kind), idx])
  msga := finding(resource, container.name, failed_path)
}

finding(resource, name, path) := {
  "alertMessage": sprintf("container '%s' is not required to run as non-root", [name]),
  "packagename": "armo_builtins",
  "alertScore": 8,
  "failedPaths": [path],
  "fixPaths": [{"path": path, "value": "true"}],
  "alertObject": {"k8sApiObjects": [resource]}
}

runs_as_non_root(_, container) {
  object.get(object.get(container, "securityContext", {}), "runAsNonRoot", null) == true
}

runs_as_non_root(spec, container) {
  object.get(object.get(container, "securityContext", {}), "runAsNonRoot", null) == null
  object.get(object.get(spec, "securityContext", {}), "runAsNonRoot", false) == true
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
