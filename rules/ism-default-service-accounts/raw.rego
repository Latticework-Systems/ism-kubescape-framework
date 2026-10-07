package armo_builtins

deny[msga] {
  service_account := input[_]
  service_account.kind == "ServiceAccount"
  metadata := object.get(service_account, "metadata", {})
  object.get(metadata, "name", "") == "default"
  object.get(service_account, "automountServiceAccountToken", true) != false

  namespace := object.get(metadata, "namespace", "default")
  message := sprintf("default ServiceAccount '%s/%s' may automount API tokens", [namespace, "default"])
  msga := finding(service_account, message, ["automountServiceAccountToken"], [{"path": "automountServiceAccountToken", "value": "false"}])
}

deny[msga] {
  namespace := input[_]
  namespace.kind == "Namespace"
  metadata := object.get(namespace, "metadata", {})
  namespace_name := object.get(metadata, "name", "")
  namespace_name != ""
  not has_dedicated_service_account(namespace_name)

  message := sprintf("namespace '%s' has no ServiceAccount other than default", [namespace_name])
  msga := finding(namespace, message, [], [])
}

has_dedicated_service_account(namespace_name) {
  service_account := input[_]
  service_account.kind == "ServiceAccount"
  metadata := object.get(service_account, "metadata", {})
  object.get(metadata, "namespace", "") == namespace_name
  object.get(metadata, "name", "") != "default"
}

finding(resource, message, failed_paths, fix_paths) := {
  "alertMessage": message,
  "packagename": "armo_builtins",
  "alertScore": 7,
  "failedPaths": failed_paths,
  "fixPaths": fix_paths,
  "alertObject": {"k8sApiObjects": [resource]}
}
