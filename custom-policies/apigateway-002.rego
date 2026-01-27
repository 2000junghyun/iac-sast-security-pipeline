# METADATA
# title: API Gateway 스테이지는 CloudWatch 액세스 로깅 활성화 필요
# description: |
#   API Gateway 스테이지는 모니터링 및 문제 해결을 위해 CloudWatch Logs에 액세스 로깅을 활성화해야 합니다.
#   액세스 로그는 API에 대한 요청의 상세 정보를 제공합니다.
#   이는 보안 감사 및 성능 분석에 필수적입니다.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://wiki.kabang.io/display/SSTVULN/%5BAPIGWSTG-002%5D+Amazon+API+Gateway+REST+API+Stage
# custom:
#   id: USER-APIGWSTG-002
#   avd_id: USER-APIGWSTG-002
#   provider: aws
#   service: apigateway
#   severity: MEDIUM
#   short_code: access-logging-required
#   recommended_action: API Gateway 스테이지에 CloudWatch 액세스 로깅 활성화
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
package user.aws.apigateway.apigwstg002

import rego.v1

# API Gateway v1 (REST API) 스테이지 로깅 검증
deny contains res if {
	some api in input.aws.apigateway.v1.apis
	isManaged(api)
	some stage in api.stages
	isManaged(stage)
	
	# CloudWatch 로그 그룹 ARN이 설정되지 않은 경우
	access_logging_not_configured(stage)
	
	res := result.new(
		sprintf("API Gateway v1 stage '%s' does not have CloudWatch access logging configured", [stage.name.value]),
		stage.accesslogging,
	)
}

# API Gateway v2 (HTTP/WebSocket API) 스테이지 로깅 검증
deny contains res if {
	some api in input.aws.apigateway.v2.apis
	isManaged(api)
	some stage in api.stages
	isManaged(stage)
	
	# CloudWatch 로그 그룹 ARN이 설정되지 않은 경우
	access_logging_not_configured(stage)
	
	res := result.new(
		sprintf("API Gateway v2 stage '%s' does not have CloudWatch access logging configured", [stage.name.value]),
		stage.accesslogging,
	)
}

# 액세스 로깅이 설정되지 않은 경우
access_logging_not_configured(stage) if {
	not stage.accesslogging
}

access_logging_not_configured(stage) if {
	stage.accesslogging
	not stage.accesslogging.cloudwatchloggrouparn
}

access_logging_not_configured(stage) if {
	stage.accesslogging
	stage.accesslogging.cloudwatchloggrouparn
	stage.accesslogging.cloudwatchloggrouparn.value == ""
}