package armo_builtins

deny[msga] {
  role := input[_]
  is_role_kind(role.kind)
  not exempt_role(role)
  rule := role.rules[rule_idx]
  rule.resources[idx] == "*"
  path := sprintf("rules[%d].resources[%d]", [rule_idx, idx])
  msga := {
    "alertMessage": sprintf("%s '%s' contains wildcard RBAC permissions", [role.kind, role.metadata.name]),
    "packagename": "armo_builtins",
    "alertScore": 8,
    "failedPaths": [path],
    "reviewPaths": [path],
    "fixPaths": [],
    "alertObject": {
      "k8sApiObjects": [role]
    }
  }
}

deny[msga] {
  role := input[_]
  is_role_kind(role.kind)
  not exempt_role(role)
  rule := role.rules[rule_idx]
  rule.verbs[idx] == "*"
  path := sprintf("rules[%d].verbs[%d]", [rule_idx, idx])
  msga := {
    "alertMessage": sprintf("%s '%s' contains wildcard RBAC permissions", [role.kind, role.metadata.name]),
    "packagename": "armo_builtins",
    "alertScore": 8,
    "failedPaths": [path],
    "reviewPaths": [path],
    "fixPaths": [],
    "alertObject": {
      "k8sApiObjects": [role]
    }
  }
}

deny[msga] {
  role := input[_]
  is_role_kind(role.kind)
  not exempt_role(role)
  rule := role.rules[rule_idx]
  rule.apiGroups[idx] == "*"
  path := sprintf("rules[%d].apiGroups[%d]", [rule_idx, idx])
  msga := {
    "alertMessage": sprintf("%s '%s' contains wildcard RBAC permissions", [role.kind, role.metadata.name]),
    "packagename": "armo_builtins",
    "alertScore": 8,
    "failedPaths": [path],
    "reviewPaths": [path],
    "fixPaths": [],
    "alertObject": {
      "k8sApiObjects": [role]
    }
  }
}

is_role_kind(kind) {
  kind == "Role"
}

is_role_kind(kind) {
  kind == "ClusterRole"
}

# Kubernetes labels the RBAC objects it bootstraps. Require that label with the
# system: name prefix; ClusterRole names alone do not identify default roles.
exempt_role(role) {
  role.kind == "ClusterRole"
  startswith(role.metadata.name, "system:")
  role.metadata.labels["kubernetes.io/bootstrapping"] == "rbac-defaults"
}
