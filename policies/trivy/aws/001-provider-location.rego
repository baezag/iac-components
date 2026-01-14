# METADATA
# title: Provider misconfiguration
# description: Provider is outside of protected file
# custom:
#   id: ID001
#   avd_id: AWS-CLP-001
#   severity: HIGH
package trivy.aws.ID001
import rego.v1

deny contains msg if {
  filename := input.aws.meta.tfproviders[_][_].filepath
  not contains(filename, "protected")

  msg := sprintf(
    "AWS provider must be defined only in protected files but found in %s",
    [filename],
  )
}