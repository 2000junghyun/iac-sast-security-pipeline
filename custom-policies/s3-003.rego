# METADATA
# title: S3 버킷은 서버 측 암호화 활성화 필요
# description: |
#   모든 S3 버킷 객체는 서버 측 암호화를 사용하여 저장되어야 합니다.
#   민감한 데이터(개인정보, 금융정보)는 AWS KMS 고객 관리형 키(CMK)를 사용해야 합니다.
#   암호화되지 않은 데이터는 물리적 액세스 시 데이터 유출 위험이 있습니다.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://wiki.kabang.io/display/SSTVULN/%5BS3-003%5D+S3+Bucket
# custom:
#   id: USER-S3-003
#   avd_id: USER-S3-003
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: enable-server-side-encryption
#   recommended_action: S3 버킷에 서버 측 암호화 활성화
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
package user.aws.s3.s3003

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some bucket in input.aws.s3.buckets
	not is_encryption_enabled(bucket)
	res := result.new(
		"S3 버킷에 서버 측 암호화가 활성화되어 있지 않습니다",
		metadata.obj_by_path(bucket, ["encryption", "enabled"]),
	)
}

is_encryption_enabled(bucket) if {
	bucket.encryption.enabled.value == true
}