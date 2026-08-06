package armo_builtins

deny[msga] {
  resource := input[_]
  spec := workload_spec(resource)
  not exempt_namespace(object.get(resource.metadata, "namespace", "default"))
  uses_host_namespace(spec)
  msga := finding(resource)
}

deny[msga] {
  resource := input[_]
  spec := workload_spec(resource)
  not exempt_namespace(object.get(resource.metadata, "namespace", "default"))
  volume := object.get(spec, "volumes", [])[idx]
  object.get(volume, "hostPath", null) != null
  msga := finding(resource)
}

deny[msga] {
  resource := input[_]
  spec := workload_spec(resource)
  not exempt_namespace(object.get(resource.metadata, "namespace", "default"))
  container := spec.containers[_]
  port := object.get(container, "ports", [])[_]
  object.get(port, "hostPort", 0) > 0
  msga := finding(resource)
}

uses_host_namespace(spec) { object.get(spec, "hostNetwork", false) == true }
uses_host_namespace(spec) { object.get(spec, "hostPID", false) == true }
uses_host_namespace(spec) { object.get(spec, "hostIPC", false) == true }

finding(resource) := {
  "alertMessage": sprintf("%s '%s' requests direct host access", [resource.kind, resource.metadata.name]),
  "packagename": "armo_builtins",
  "alertScore": 8,
  "failedPaths": [],
  "fixPaths": [],
  "alertObject": {"k8sApiObjects": [resource]}
}

workload_spec(resource) := resource.spec { resource.kind == "Pod" }
workload_spec(resource) := resource.spec.template.spec { is_workload_kind(resource.kind) }
workload_spec(resource) := resource.spec.jobTemplate.spec.template.spec { resource.kind == "CronJob" }
is_workload_kind(kind) { kind == "Deployment" }
is_workload_kind(kind) { kind == "ReplicaSet" }
is_workload_kind(kind) { kind == "DaemonSet" }
is_workload_kind(kind) { kind == "StatefulSet" }
is_workload_kind(kind) { kind == "Job" }
exempt_namespace(namespace) { namespace == "kube-system" }
exempt_namespace(namespace) { namespace == "kube-public" }
exempt_namespace(namespace) { namespace == "kube-node-lease" }
