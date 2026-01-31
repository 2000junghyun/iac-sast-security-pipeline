# Docker 셋업 가이드

## gitlab-net 네트워크 구성

이 프로젝트는 GitLab과 IaC Scanner가 통신하기 위해 `gitlab-net`이라는 Docker 네트워크를 사용합니다.

---

## 네트워크 전략

### 분리 실행 방식
- `docker-compose.gitlab.yml`: external 네트워크 사용
- `docker-compose.yml`: external 네트워크 사용
- **네트워크를 수동으로 먼저 생성** 필요

### 네트워크 아키텍처

```
┌────────────────────────────────────────────────────────────┐
│                   gitlab-net (172.30.0.0/16)               │
│                                                            │
│  ┌──────────────────────┐      ┌──────────────────────┐    │
│  │  local-gitlab        │      │  iac-scanner         │    │
│  │  172.30.0.2          │◄────►│  172.30.0.3          │    │
│  │                      │      │                      │    │
│  │  Hostname:           │      │  Hostname:           │    │
│  │  local-gitlab        │      │  iac-scanner         │    │
│  └──────────────────────┘      └──────────────────────┘    │
│            │                              │                │
└────────────┼──────────────────────────────┼────────────────┘
             │                              │
             ▼                              ▼
      Host: 80, 2222              Host: 8080
```

**통신 방식:**
- 컨테이너 → 컨테이너: DNS 이름 사용 (`http://local-gitlab:80`)
- 호스트 → 컨테이너: 포트 매핑 사용 (`http://localhost:80`)

---

## 실행 방법

### 방법 1: 수동 실행 (GitLab + IaC Scanner 별도)

#### 1단계: 네트워크 생성
```bash
# gitlab-net 네트워크 생성 (한 번만 실행)
docker network create \
  --driver bridge \
  --subnet 172.30.0.0/16 \
  gitlab-net

# 생성 확인
docker network ls | grep gitlab-net
```

#### 2단계: GitLab 시작
```bash
docker-compose -f docker-compose.gitlab.yml up -d
```

#### 3단계: IaC Scanner 시작
```bash
docker-compose up -d
```

### 방법 2: 스크립트 사용
```bash
# 네트워크 자동 확인 및 GitLab 시작
./scripts/start-gitlab.sh

# IaC Scanner 시작
docker-compose up -d
```

---

## 추가 자료

### Docker 네트워크 공식 문서
- https://docs.docker.com/network/
- https://docs.docker.com/compose/networking/

### 관련 파일
- `docker-compose.yml` - IaC Scanner 전용 (external 네트워크)
- `scripts/docker-compose.gitlab.yml` - GitLab 전용 (external 네트워크)
- `scripts/start-gitlab.sh` - 네트워크 자동 확인 스크립트

---
## 트러블슈팅

### 문제 1: "network gitlab-net not found"

**원인:** 네트워크가 생성되지 않았음

**해결:**
```bash
# 네트워크 생성
docker network create \
  --driver bridge \
  --subnet 172.30.0.0/16 \
  gitlab-net

# 다시 시작
docker-compose -f docker-compose.gitlab.yml up -d
```

---

### 문제 2: "network already exists"

**원인:** 이미 같은 이름의 네트워크가 존재

**해결 A: 기존 네트워크 재사용**
```bash
# 네트워크 설정 확인
docker network inspect gitlab-net

# 서브넷이 172.30.0.0/16이면 그대로 사용
docker-compose -f docker-compose.gitlab.yml up -d
```

**해결 B: 네트워크 재생성**
```bash
# 경고: 연결된 컨테이너가 있으면 중지 필요
docker-compose down
docker-compose -f docker-compose.gitlab.yml down

# 네트워크 삭제
docker network rm gitlab-net

# 네트워크 재생성
docker network create \
  --driver bridge \
  --subnet 172.30.0.0/16 \
  gitlab-net

# 서비스 재시작
docker-compose -f docker-compose.gitlab.yml up -d
docker-compose up -d
```

---

### 문제 3: 서브넷 충돌

**에러 메시지:**
```
Error response from daemon: Pool overlaps with other one on this address space
```

**원인:** `172.30.0.0/16` 대역이 다른 네트워크와 충돌

**해결:** 다른 서브넷 사용
```bash
# 1. compose 파일에서 서브넷 변경 (예: 172.31.0.0/16)
# 2. 네트워크 재생성
docker network create \
  --driver bridge \
  --subnet 172.31.0.0/16 \
  gitlab-net
```

---

### 문제 4: 컨테이너 간 통신 불가

**증상:**
```bash
docker exec -it iac-scanner ping local-gitlab
# ping: local-gitlab: Name or service not known
```

**원인:** 컨테이너가 같은 네트워크에 없음

**해결:**
```bash
# 1. 네트워크 확인
docker network inspect gitlab-net

# 2. 컨테이너가 연결되어 있는지 확인
docker inspect iac-scanner | grep NetworkMode
docker inspect local-gitlab | grep NetworkMode

# 3. 수동으로 네트워크 연결 (필요시)
docker network connect gitlab-net iac-scanner
docker network connect gitlab-net local-gitlab

# 4. 테스트
docker exec -it iac-scanner ping -c 3 local-gitlab
```
