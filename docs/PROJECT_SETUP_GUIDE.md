# 프로젝트 셋업 가이드

## 단계별 셋업 방법

### 1단계: Docker 설정

**DOCKER_SETUP_GUIDE.md 확인**

---

### 2단계: GitLab 초기 설정

#### 2-1. 웹 UI 접속
```
http://localhost
```

#### 2-2. Root 패스워드 확인
```bash
# 자동 생성된 root 패스워드 확인
docker exec -it local-gitlab grep 'Password:' /etc/gitlab/initial_root_password

# 출력 예시:
# Password: aBc123XyZ...
```

#### 2-3. 로그인 및 프로젝트 생성
1. Username: `root`
2. Password: (위에서 확인한 패스워드)
3. 새 프로젝트 생성 (예: `test-group/iac-test`)

#### 2-4. Project Access Token 생성
```
프로젝트 > Settings > Access Tokens
- Token name: iac-scanner
- Role: Developer
- Scopes: ✅ api, ✅ read_repository
- Create token → 생성된 토큰 복사
```

#### 2-5. GitLab CI/CD Variables 설정
```
프로젝트 > Settings > CI/CD > Variables > Add variable

변수 1:
- Key: IAC_SCANNER_SECRET
- Value: my-secure-secret-key
- Type: Variable
- Environment scope: All (default)
- Flags: 
  ⚠️ Protect variable: 반드시 체크 해제 (모든 브랜치에서 사용 가능하도록)
  ☑️ Mask variable: 선택 (로그에서 값 숨김)
```

**중요:** `IAC_SCANNER_SECRET` 값은 `.env` 파일의 `WEBHOOK_SECRET`과 **반드시 동일**해야 합니다!

#### 2-6. GitLab Runner 설정

**2-6-1. Runner 컨테이너 생성 및 시작**
```bash
# gitlab-net 네트워크에 Runner 컨테이너 추가
docker run -d \
  --name gitlab-runner \
  --network gitlab-net \
  --restart always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v gitlab-runner-config:/etc/gitlab-runner \
  gitlab/gitlab-runner:latest
```

**2-6-2. Runner 등록**
```bash
# Runner 등록 명령어 실행
docker exec -it gitlab-runner gitlab-runner register \
  --url http://local-gitlab \
  --token glrt-GITLAB-REGISTRATION-TOKEN \
  --executor docker \
  --docker-image alpine:latest \
  --docker-network-mode gitlab-net \
  --docker-volumes /var/run/docker.sock:/var/run/docker.sock \
  --non-interactive
```

**Registration Token 확인 방법:**
```
프로젝트 > Settings > CI/CD > Runners > Expand
→ "New project runner" 버튼 클릭
→ Runner description 입력 후 "Create runner"
→ 표시되는 Registration token 복사
```

**2-6-3. Runner 상태 확인**
```bash
# Runner 등록 확인
docker exec gitlab-runner gitlab-runner verify

# 예상 출력:
# Verifying runner... is valid    runner=abcdefgh
```

GitLab UI에서도 확인:
```
프로젝트 > Settings > CI/CD > Runners
→ "Available specific runners" 섹션에 Runner 표시 확인
→ 초록색 원: 활성화됨
```

---

### 3단계: IaC Scanner .env 설정

```bash
cat > .env << 'EOF'
GITLAB_URL=http://local-gitlab:80
GITLAB_TOKENS=test-group/iac-test:glpat-YOUR-TOKEN-HERE
WEBHOOK_SECRET=my-secure-secret-key
SERVER_PORT=8080
EOF
```

**중요:** `glpat-YOUR-TOKEN-HERE`를 2-4단계에서 생성한 실제 토큰으로 교체

---

## 테스트 시나리오

### 테스트 1: API 직접 호출

```bash
# Health check
curl http://localhost:8080/health

# Service info
curl http://localhost:8080/
```

### 테스트 2: 수동 스캔 트리거

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "X-API-Secret: my-secure-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": 1,
    "project_path": "test-group/iac-test",
    "mr_iid": 1,
    "source_branch": "feature-test",
    "file_paths": ["main.tf"],
    "is_public": false
  }'
```

### 테스트 3: MR 생성으로 자동 스캔

1. Terraform 파일 추가 (`main.tf`)
```hcl
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
```

2. 브랜치 생성 및 푸시
```bash
git checkout -b feature-test
git add main.tf
git commit -m "Add S3 bucket"
git push origin feature-test
```

3. GitLab에서 Merge Request 생성
4. Webhook이 자동으로 Scanner 호출
5. MR에 댓글로 스캔 결과 표시 확인

---

## 상태 확인

### 컨테이너 상태
```bash
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
```

예상 출력:
```
NAMES         IMAGE                      STATUS                  PORTS
iac-scanner   iac-scanner               Up 5 minutes            0.0.0.0:8080->8080/tcp
local-gitlab     gitlab/gitlab-ce:latest   Up 20 minutes (healthy) 0.0.0.0:80->80/tcp, ...
```

### 로그 확인
```bash
# 실시간 로그
docker-compose logs -f                              # IaC Scanner
docker-compose -f docker-compose.gitlab.yml logs -f  # GitLab

# 최근 로그 (마지막 100줄)
docker logs --tail 100 iac-scanner
docker logs --tail 100 local-gitlab
```

### 리소스 사용량
```bash
docker stats local-gitlab iac-scanner
```

---

## 트러블슈팅

### 문제 1: GitLab이 시작되지 않음
```bash
# 메모리 부족 확인
docker stats local-gitlab

# 로그 확인
docker logs local-gitlab | grep -i error

# 해결: 메모리 할당 증가 (Docker Desktop 설정)
# 최소 4GB RAM 권장
```

### 문제 2: IaC Scanner가 GitLab에 접근 못함
```bash
# 네트워크 확인
docker network inspect gitlab-net

# 두 컨테이너가 모두 있는지 확인
# GitLab DNS 해석 테스트
docker exec -it iac-scanner ping -c 3 local-gitlab
```
