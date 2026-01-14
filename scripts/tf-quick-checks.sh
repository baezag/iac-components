#!/usr/bin/env bash
rc=0

invalid_files () {
    echo "$INVALID_FILES" | while read f
    do
        echo "  - $f"
    done
    rc=1
}


# Quick check de providers
INVALID_FILES=$(grep -rlw 'provider' --include="*.tf" --exclude="*protected.tf" --exclude-dir="iac-components" .)

if [[ -n "$INVALID_FILES" ]]; then
  echo "❌ Provider AWS definido en archivos incorrectos:"
  invalid_files
else
  echo "✅ Providers ubicados correctamente"
fi

# Quick check de aws_iam
INVALID_FILES=$(grep -rl 'resource *"aws_iam_' --include="*.tf" --exclude="iam.tf" --exclude-dir="iac-components" .)

if [[ -n "$INVALID_FILES" ]]; then
  echo "❌ Recursos IAM encontrados fuera de iam.tf:"
  invalid_files
else
  echo "✅ Recursos IAM ubicados correctamente"
fi

# Quick check de aws_kms
INVALID_FILES=$(grep -rl 'resource *"aws_kms_' --include="*.tf" --exclude="iam.tf" .)

if [[ -n "$INVALID_FILES" ]]; then
  echo "❌ Recursos KMS encontrados fuera de iam.tf:"
    invalid_files
else
  echo "✅ Recrusos KMS resources ubicados correctamente"
fi

exit $rc