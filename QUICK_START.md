# Auth Converter 빠른 시작 가이드

## 프로그램 실행

```bash
cd "/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter"
npm start
```

브라우저에서 http://localhost:3000 접속

## 주요 기능

### 1. JSON 파일 뷰어
- JSON 파일을 드래그 앤 드롭하거나 선택하여 열기
- 포맷팅된 JSON 보기
- 내용 복사

### 2. MCP 서버 병합
- 여러 MCP 설정 파일을 하나로 병합
- Claude Code 또는 Claude Desktop 설정 선택
- 서버 이름 변경 기능

### 3. Extensions 변환 (자동 포트 설정)
- Claude Desktop Extensions를 MCP 서버로 변환
- **workspace-mcp의 경우 OAuth 포트 자동 감지 및 설정**
- **환경 변수 편집 및 추가 기능** (NEW!)
- 환경 변수 자동 구성

### 4. 인증 상태 확인 (포트 검증)
- Google Workspace MCP 서버 인증 상태 실시간 확인
- **포트 설정 검증 및 불일치 경고**
- 토큰 만료 여부 확인
- 인증/재인증 바로 실행
- **포트 설정 가이드 제공**

## 새로운 기능: 자동 포트 설정

### 작동 방식

1. **client_secret.json 업로드 시:**
   - redirect_uri에서 OAuth 포트 자동 감지 (예: 8765)
   - `oauth_port_map.json`에 client_id → port 매핑 저장

2. **Extension 변환 시:**
   - workspace-mcp 서버 자동 감지
   - 저장된 포트 매핑에서 올바른 포트 찾기
   - **자동 감지 성공 시:**
     - ✅ `WORKSPACE_MCP_PORT` 환경변수 자동 추가
     - 초록색 성공 메시지 표시
   - **자동 감지 실패 시:**
     - ⚠️ 노란색 경고 메시지 표시
     - 수동 포트 입력 필드가 표시됨
     - client_secret.json의 redirect_uri 포트를 직접 입력

3. **인증 상태 확인 시:**
   - 설정된 포트와 실제 포트 비교
   - 불일치 시 빨간색 경고 표시
   - 포트 미설정 시 권장 포트 제시
   - ✅ **문제를 사전에 발견하고 해결!**

### 환경 변수 편집 기능 (NEW!)

Extensions 탭에서 Claude Desktop Extensions의 환경 변수를 직접 편집할 수 있습니다:

1. **환경 변수 보기**: "▼ 환경 변수 보기" 버튼 클릭으로 현재 설정 확인
2. **환경 변수 편집**: "✏️ 편집" 버튼으로 기존 변수 수정
3. **새 변수 추가**: "+ 환경 변수 추가" 버튼으로 새로운 변수 추가
4. **실시간 저장**: 변경 사항이 즉시 Claude Desktop 설정에 저장됨

### 포트 상태 표시

#### 🟢 정상
```
🔌 OAuth Port: 8765 ✓
```
설정된 포트가 client_secret.json과 일치합니다.

#### 🟡 포트 미설정
```
ℹ️ 포트 미설정: WORKSPACE_MCP_PORT 환경변수를 추가하세요 (권장 포트: 8765)
```
WORKSPACE_MCP_PORT가 설정되지 않았습니다. 권장 포트를 참고하여 설정하세요.

#### 🔴 포트 불일치
```
⚠️ 포트 불일치 경고: 설정된 포트 8000가 client_secret.json의 포트 8765와 다릅니다.
WORKSPACE_MCP_PORT를 8765로 변경하세요.
```
설정된 포트가 잘못되었습니다. 즉시 수정이 필요합니다.

## 사용 시나리오

### 시나리오 1: 새로운 Google 계정 추가

1. "인증 상태 확인" 탭 선택
2. 워크스페이스 MCP 서버 확인
3. "📧 이메일 추가 & 인증" 버튼 클릭
4. 이메일 입력 (예: newuser@gmail.com)
5. client_secret.json 업로드
   - ✅ 포트가 자동으로 감지되어 저장됨
6. OAuth 인증 진행
7. 설정 저장 시 포트가 자동으로 포함됨
   - ✅ WORKSPACE_MCP_PORT 자동 추가!

### 시나리오 2: 기존 설정 검증

1. "인증 상태 확인" 탭 선택
2. 모든 워크스페이스 MCP 서버 상태 확인
3. 포트 상태 메시지 확인:
   - 🟢 정상: 아무 조치 불필요
   - 🟡 포트 미설정: 권장 포트로 설정 추가
   - 🔴 포트 불일치: 즉시 포트 수정

### 시나리오 3: Extension 변환 (자동 포트 설정)

1. "Extensions 변환" 탭 선택
2. workspace-mcp extension 선택
3. 계정 식별자 입력
4. "MCP 설정 생성" 클릭
5. ✅ 포트 자동 설정 메시지 확인:
   ```
   ✓ OAuth 포트 자동 설정: WORKSPACE_MCP_PORT가 8765로 자동 설정되었습니다.
   이제 인증 시 포트 불일치 문제가 발생하지 않습니다.
   ```
6. "Config에 병합" 클릭
7. 완료!

## 파일 위치

### OAuth 포트 매핑
```
~/.mcp-workspace/oauth_port_map.json
```
각 client_id와 OAuth 포트의 매핑 정보 저장

### Client Secrets
```
~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_{accountId}/client_secret.json
```
Google OAuth 클라이언트 시크릿 파일

### 토큰 파일
```
~/.google_workspace_mcp/credentials/{email}.json
또는
~/.mcp-workspace/token-{email}.json
```
인증 토큰 저장 위치

### Claude Code 설정
```
~/.claude.json
```
Claude Code MCP 서버 설정

### Claude Desktop 설정
```
~/Library/Application Support/Claude/claude_desktop_config.json
```
Claude Desktop MCP 서버 설정

## 문제 해결

### 포트 불일치 오류

**증상:**
- 빨간색 "포트 불일치 경고" 표시
- 인증 시 "Port 8000 is already in use" 오류

**해결:**
1. "인증 상태 확인"에서 권장 포트 확인
2. .claude.json 열기
3. 해당 서버의 env에 추가:
   ```json
   "WORKSPACE_MCP_PORT": "8765"
   ```
4. Claude Code 재시작
5. ✅ 포트 상태가 초록색으로 변경 확인

### 인증 실패

**증상:**
- "인증 필요" 상태 유지
- OAuth 플로우가 완료되지 않음

**해결:**
1. 포트 상태 먼저 확인 (위 참고)
2. 포트가 정상이면 "🔄 재인증" 클릭
3. 브라우저에서 Google 인증 진행
4. 완료 후 "인증됨" 상태 확인

### OAuth 콜백 서버 오류

**증상:**
- "Cannot start minimal OAuth server" 오류
- 특정 포트가 이미 사용 중

**해결:**
```bash
# 사용 중인 포트 확인
lsof -i :8765

# 프로세스 종료
kill -9 <PID>

# 또는 다른 포트 사용
# client_secret.json의 redirect_uri를 다른 포트로 변경
```

## 개발자 정보

### 서버 로그 확인
```bash
tail -f /tmp/auth-server-test.log
```

### 포트 매핑 확인
```bash
cat ~/.mcp-workspace/oauth_port_map.json
```

### 토큰 상태 확인
```bash
cd "/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter"
node test-mcp-auth.js
```

## 추가 정보

- **상세 개선 사항:** [IMPROVEMENTS.md](./IMPROVEMENTS.md)
- **문제 해결 가이드:** [FIX_SUMMARY.md](./FIX_SUMMARY.md)
- **프로젝트 구조:** [CLAUDE.md](./CLAUDE.md)

---
버전: 2.0.0 (2025-11-11)
업데이트: 자동 포트 설정 및 검증 기능 추가
