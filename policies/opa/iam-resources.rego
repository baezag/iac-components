package IAM
import rego.v1

selected_resources_types := {
    `^aws_iam.*`,
    `^aws_kms.*`,
}

deny contains msg if {
  resource := input.managed_resources[_]
  some pattern in selected_resources_types
  regex.match(pattern, resource.type)
  resource.pos.filename != "iam.tf"

  msg := sprintf(
    "Resource %v must be in iam.tf (found in %v)",
    [resource.type, resource.pos.filename],
  )
}