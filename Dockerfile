# 빌드 스테이지
FROM golang:1.21-alpine AS builder

WORKDIR /app

# HTTP 저장소로 변경하여 SSL 문제 우회
RUN sed -i 's/https/http/g' /etc/apk/repositories && \
    apk --no-cache add ca-certificates git && \
    update-ca-certificates

# 소스 코드 복사
COPY . .

# 바이너리 빌드 (vendor 사용)
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o trivy-tf-scanner ./cmd/server

# 실행 스테이지
FROM alpine:latest

WORKDIR /app

# HTTP 저장소로 변경하여 SSL 문제 우회 후 패키지 설치
RUN sed -i 's/https/http/g' /etc/apk/repositories && \
    apk --no-cache add ca-certificates wget

# Trivy 다운로드 (Linux x86_64용)
RUN wget --no-check-certificate https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy_0.58.1_Linux-64bit.tar.gz && \
    tar -xzf trivy_0.58.1_Linux-64bit.tar.gz && \
    mv trivy /app/trivy && \
    chmod +x /app/trivy && \
    rm trivy_0.58.1_Linux-64bit.tar.gz

# 빌드된 바이너리 복사
COPY --from=builder /app/trivy-tf-scanner .

# trivy-parser 실행 파일 복사 (Linux 버전을 trivy-parser로 이름 변경)
COPY trivy-parser-linux ./trivy-parser
RUN chmod +x /app/trivy-parser

# Custom policies 복사
COPY custom-policies ./custom-policies

# 필요한 디렉토리 생성
RUN mkdir -p /app/storage /app/scan-results

# 포트 노출
EXPOSE 9093

# 실행
CMD ["./trivy-tf-scanner"]