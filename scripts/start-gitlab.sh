#!/bin/bash

# Docker Compose 시작 스크립트
# gitlab-net 네트워크를 확인하고 필요시 생성

set -e

NETWORK_NAME="gitlab-net"
SUBNET="172.30.0.0/16"

echo "🔍 Checking network: $NETWORK_NAME"

# 네트워크 존재 여부 확인
if docker network inspect $NETWORK_NAME >/dev/null 2>&1; then
    echo "✅ Network '$NETWORK_NAME' already exists"
else
    echo "🔧 Creating network '$NETWORK_NAME' with subnet $SUBNET"
    docker network create \
        --driver bridge \
        --subnet $SUBNET \
        $NETWORK_NAME
    echo "✅ Network '$NETWORK_NAME' created successfully"
fi

# GitLab 시작
echo ""
echo "🚀 Starting GitLab..."
docker-compose -f docker-compose.gitlab.yml up -d

echo ""
echo "✅ GitLab started successfully"
echo "📝 Access GitLab at: http://localhost"
echo "⏱️  Initial setup may take 5-10 minutes"
echo ""
echo "To check status:"
echo "  docker-compose -f docker-compose.gitlab.yml logs -f"
