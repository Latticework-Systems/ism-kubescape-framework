package armo_builtins

deny[msga] {
  binding := input[_]
  is_binding_kind(binding.kind)
  binding.roleRef.kind == "ClusterRole"
  binding.roleRef.name == "cluster-admin"
  subject := binding.subjects[idx]
  path := sprintf("subjects[%d]", [idx])
  msga := {
    "alertMessage": sprintf("%s '%s' grants cluster-admin to %s '%s'", [binding.kind, binding.metadata.name, subject.kind, subject_name(subject)]),
    "packagename": "armo_builtins",
    "alertScore": 9,
    "failedPaths": [path, "roleRef.name"],
    "reviewPaths": [path, "roleRef.name"],
    "fixPaths": [],
    "alertObject": {
      "k8sApiObjects": [binding]
    }
  }
}

subject_name(subject) = name {
  subject.kind == "ServiceAccount"
  name := sprintf("%s/%s", [object.get(subject, "namespace", "default"), subject.name])
}

subject_name(subject) = name {
  subject.kind != "ServiceAccount"
  name := subject.name
}

is_binding_kind(kind) {
  kind == "RoleBinding"
}

is_binding_kind(kind) {
  kind == "ClusterRoleBinding"
}
