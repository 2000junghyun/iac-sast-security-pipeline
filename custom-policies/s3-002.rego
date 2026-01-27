# METADATA
# title: S3 버킷은 버전 관리 활성화 필요
# description: |
#   중요 정보를 포함하는 S3 버킷은 버전 관리를 활성화해야 합니다.
#   버전 관리는 실수로 인한 삭제나 악의적인 수정으로부터 데이터를 보호합니다.
#   모든 객체의 변경 이력을 추적하여 이전 버전으로 복원할 수 있습니다.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://wiki.kabang.io/display/SSTVULN/%5BS3-002%5D+S3+Bucket
# custom:
#   id: USER-S3-002
#   avd_id: USER-S3-002
#   provider: aws
#   service: s3
#   severity: MEDIUM
#   short_code: enable-versioning
#   recommended_action: S3 버킷에 버전 관리 활성화
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
package user.aws.s3.s3002

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some bucket in input.aws.s3.buckets
	not is_versioning_enabled(bucket)
	res := result.new(
		"S3 버킷에 버전 관리가 활성화되어 있지 않습니다",
		metadata.obj_by_path(bucket, ["versioning", "enabled"]),
	)
}

is_versioning_enabled(bucket) if {
	bucket.versioning.enabled.value == true
}