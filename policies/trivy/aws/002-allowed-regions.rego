# METADATA
# title: Invalid region
# description: Region is not allowed
# custom:
#   id: ID002
#   avd_id: AWS-CLP-002
#   severity: HIGH
package trivy.aws.ID002
import rego.v1

allowed_regions := {"us-east-1", "us-west-2"}

deny contains msg if {
  region := input.aws.meta.tfproviders[_].region.value
  not allowed_regions[region]

  msg := sprintf(
    "Region %s is not allowed. Allowed regions: %v",
    [region, allowed_regions],
  )
}