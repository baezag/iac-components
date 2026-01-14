package CLP

import rego.v1

selected_resources_types := {
    `^aws_vpc.*`,
    `^aws_subnet.*`,
    `^aws_nat_.*`,
    `^aws_internet_.*`,
    `^aws_ec2_transit_gateway.*`,
    `^aws_route53.*`,
}

excepted_resources_types := {
    `^aws_route53_record`,
}

deny contains msg if {
  resource := input.managed_resources[_]
  
  some pattern in selected_resources_types
  regex.match(pattern, resource.type)
  
  some ex_pattern in excepted_resources_types
  not regex.match(ex_pattern, resource.type) 
  not contains(resource.pos.filename, "protected")

  msg := sprintf(
    "Resource %v must be in protected file (found in %v)",
    [resource.type, resource.pos.filename],
  )
}