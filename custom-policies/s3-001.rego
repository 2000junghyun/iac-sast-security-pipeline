# METADATA
# title: S3 버킷은 모든 퍼블릭 액세스 차단 필요
# description: |
#   S3 버킷은 퍼블릭 액세스를 차단하여 데이터 유출을 방지해야 합니다.
#   퍼블릭 ACL과 퍼블릭 정책을 모두 차단해야 합니다.
#   퍼블릭 액세스가 허용되면 민감한 데이터가 인터넷에 노출될 수 있습니다.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://wiki.kabang.io/display/SSTVULN/%5BS3-001%5D+S3+Bucket
# custom:
#   id: USER-S3-001
#   avd_id: USER-S3-001
#   provider: aws
#   service: s3
#   severity: CRITICAL
#   short_code: block-all-public-access
#   recommended_action: S3 버킷에 퍼블릭 액세스 차단 활성화
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
package user.aws.s3.s3001

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some bucket in input.aws.s3.buckets
	not has_public_access_block(bucket)
	res := result.new(
		"S3 버킷에 퍼블릭 액세스 차단이 설정되어 있지 않습니다",
		bucket,
	)
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	has_public_access_block(bucket)
	not all_public_access_blocked(bucket)
	res := result.new(
		"S3 버킷의 퍼블릭 액세스 차단이 완전하지 않습니다",
		bucket.publicaccessblock,
	)
}

has_public_access_block(bucket) if {
	bucket.publicaccessblock
}

all_public_access_blocked(bucket) if {
	bucket.publicaccessblock.blockpublicacls.value == true
	bucket.publicaccessblock.blockpublicpolicy.value == true
	bucket.publicaccessblock.ignorepublicacls.value == true
	bucket.publicaccessblock.restrictpublicbuckets.value == true
}