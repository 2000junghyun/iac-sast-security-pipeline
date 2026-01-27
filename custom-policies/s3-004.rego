# METADATA
# title: S3 버킷은 라이프사이클 정책 설정 필요
# description: |
#   S3 버킷은 라이프사이클 정책을 통해 객체 보관 주기를 관리해야 합니다.
#   라이프사이클 규칙은 스토리지 비용 절감 및 규정 준수 요구사항 충족에 필수적입니다.
#   오래된 데이터를 자동으로 다른 스토리지 클래스로 전환하거나 삭제할 수 있습니다.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://wiki.kabang.io/display/SSTVULN/%5BS3-004%5D+S3+Bucket
# custom:
#   id: USER-S3-004
#   avd_id: USER-S3-004
#   provider: aws
#   service: s3
#   severity: LOW
#   short_code: enable-lifecycle-configuration
#   recommended_action: S3 버킷에 라이프사이클 정책 설정
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
package user.aws.s3.s3004

import rego.v1

deny contains res if {
	some bucket in input.aws.s3.buckets
	not has_enabled_lifecycle_rules(bucket)
	res := result.new(
		"S3 버킷에 활성화된 라이프사이클 정책이 설정되어 있지 않습니다",
		object.get(bucket, "lifecycleconfiguration", bucket),
	)
}

has_enabled_lifecycle_rules(bucket) if {
	bucket.lifecycleconfiguration
	some rule in bucket.lifecycleconfiguration
	rule.status.value == "Enabled"
}