package armo_builtins

deny[msga] {
  resource := input[_]
  resource.kind == "Pod"
  container := resource.spec.containers[idx]
  not image_is_allowed(container.image)
  failed_path := sprintf("spec.containers[%d].image", [idx])
  msga := {
    "alertMessage": sprintf("container image '%s' is not from an approved registry or repository", [container.image]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "reviewPaths": [failed_path],
    "fixPaths": [],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  resource.kind == "Pod"
  container := resource.spec.initContainers[idx]
  not image_is_allowed(container.image)
  failed_path := sprintf("spec.initContainers[%d].image", [idx])
  msga := {
    "alertMessage": sprintf("container image '%s' is not from an approved registry or repository", [container.image]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "reviewPaths": [failed_path],
    "fixPaths": [],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  is_workload_kind(resource.kind)
  container := resource.spec.template.spec.containers[idx]
  not image_is_allowed(container.image)
  failed_path := sprintf("spec.template.spec.containers[%d].image", [idx])
  msga := {
    "alertMessage": sprintf("container image '%s' is not from an approved registry or repository", [container.image]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "reviewPaths": [failed_path],
    "fixPaths": [],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  is_workload_kind(resource.kind)
  container := resource.spec.template.spec.initContainers[idx]
  not image_is_allowed(container.image)
  failed_path := sprintf("spec.template.spec.initContainers[%d].image", [idx])
  msga := {
    "alertMessage": sprintf("container image '%s' is not from an approved registry or repository", [container.image]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "reviewPaths": [failed_path],
    "fixPaths": [],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  resource.kind == "CronJob"
  container := resource.spec.jobTemplate.spec.template.spec.containers[idx]
  not image_is_allowed(container.image)
  failed_path := sprintf("spec.jobTemplate.spec.template.spec.containers[%d].image", [idx])
  msga := {
    "alertMessage": sprintf("container image '%s' is not from an approved registry or repository", [container.image]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "reviewPaths": [failed_path],
    "fixPaths": [],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

deny[msga] {
  resource := input[_]
  resource.kind == "CronJob"
  container := resource.spec.jobTemplate.spec.template.spec.initContainers[idx]
  not image_is_allowed(container.image)
  failed_path := sprintf("spec.jobTemplate.spec.template.spec.initContainers[%d].image", [idx])
  msga := {
    "alertMessage": sprintf("container image '%s' is not from an approved registry or repository", [container.image]),
    "packagename": "armo_builtins",
    "alertScore": 7,
    "failedPaths": [failed_path],
    "reviewPaths": [failed_path],
    "fixPaths": [],
    "alertObject": {"k8sApiObjects": [resource]}
  }
}

# Read the allow list from control inputs. latticework_ism_scan.sh resolves the
# registry ConfigMap through the API and writes the value into those inputs.
image_is_allowed(image) {
  allowed := data.postureControlInputs.imageRepositoryAllowList[_]
  prefix := normalized_allow_entry(allowed)
  prefix != ""
  image_matches_prefix(normalized_image(image), prefix)
}

image_matches_prefix(image, prefix) {
  endswith(prefix, "/")
  startswith(image, prefix)
}

image_matches_prefix(image, prefix) {
  not endswith(prefix, "/")
  image == prefix
}

image_matches_prefix(image, prefix) {
  not endswith(prefix, "/")
  startswith(image, sprintf("%s/", [prefix]))
}

image_matches_prefix(image, prefix) {
  not endswith(prefix, "/")
  startswith(image, sprintf("%s:", [prefix]))
}

image_matches_prefix(image, prefix) {
  not endswith(prefix, "/")
  startswith(image, sprintf("%s@", [prefix]))
}

normalized_allow_entry(entry) = normalized {
  trimmed := trim_space(entry)
  endswith(trimmed, "*")
  normalized := substring(trimmed, 0, count(trimmed) - 1)
}

normalized_allow_entry(entry) = normalized {
  trimmed := trim_space(entry)
  not endswith(trimmed, "*")
  normalized := trimmed
}

normalized_image(image) = normalized {
  explicit_registry(image)
  normalized := image
}

normalized_image(image) = normalized {
  not explicit_registry(image)
  count(split(image, "/")) == 1
  normalized := sprintf("docker.io/library/%s", [image])
}

normalized_image(image) = normalized {
  not explicit_registry(image)
  count(split(image, "/")) > 1
  normalized := sprintf("docker.io/%s", [image])
}

explicit_registry(image) {
  count(split(image, "/")) > 1
  first := split(image, "/")[0]
  contains(first, ".")
}

explicit_registry(image) {
  count(split(image, "/")) > 1
  first := split(image, "/")[0]
  contains(first, ":")
}

explicit_registry(image) {
  count(split(image, "/")) > 1
  first := split(image, "/")[0]
  first == "localhost"
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
