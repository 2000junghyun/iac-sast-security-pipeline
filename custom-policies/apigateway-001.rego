# title: API Gateway 캐시는 활성화 시 암호화 필요
# description: |
#   API Gateway 스테이지에서 메서드에 대한 캐싱이 활성화된 경우 캐시 데이터는 암호화되어야 합니다.
#   이는 민감한 데이터를 무단 액세스로부터 보호합니다.
#   잠재적으로 민감한 정보가 포함된 캐시 응답이 안전하게 저장되도록 보장합니다.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://wiki.kabang.io/display/SSTVULN/%5BAPIGWSTG-001%5D+Amazon+API+Gateway+REST+API+Stage
# custom:
#   id: USER-APIGWSTG-001
#   avd_id: USER-APIGWSTG-001
#   provider: aws
#   service: apigateway
#   severity: HIGH
#   short_code: cache-encryption-required
#   recommended_action: API Gateway 스테이지 메서드 설정에 캐시 데이터 암호화 활성화
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
package user.aws.apigateway.apigwstg001

import rego.v1

# 캐시가 활성화된 경우 암호화 필수
deny contains res if {
	some api in input.aws.apigateway.v1.apis
	isManaged(api)
	some stage in api.stages
	isManaged(stage)
	some settings in stage.restmethodsettings
	isManaged(settings)
	
	# 캐시가 활성화되어 있는 경우
	settings.cacheenabled.value == true
	
	# 캐시 데이터 암호화가 비활성화된 경우
	cache_data_not_encrypted(settings)
	
	res := result.new(
		sprintf("API Gateway stage '%s' has caching enabled but cache data is not encrypted", [stage.name.value]),
		settings.cachedataencrypted,
	)
}

# 캐시가 비활성화된 경우도 FAIL
deny contains res if {
	some api in input.aws.apigateway.v1.apis
	isManaged(api)
	some stage in api.stages
	isManaged(stage)
	some settings in stage.restmethodsettings
	isManaged(settings)
	
	# 캐시가 비활성화된 경우
	cache_disabled(settings)
	
	res := result.new(
		sprintf("API Gateway stage '%s' does not have caching enabled", [stage.name.value]),
		settings.cacheenabled,
	)
}

# 캐시가 비활성화된 경우
cache_disabled(settings) if {
	not settings.cacheenabled
}

cache_disabled(settings) if {
	settings.cacheenabled.value == false
}

# 캐시 데이터 암호화가 설정되지 않은 경우
cache_data_not_encrypted(settings) if {
	not settings.cachedataencrypted
}

# 캐시 데이터 암호화가 명시적으로 false인 경우
cache_data_not_encrypted(settings) if {
	settings.cachedataencrypted.value == false
}