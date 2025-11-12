# workspace-mcp 인증 문제 해결 요약

## 문제 상황
auth converter 프로그램을 통해 Google OAuth client_secret.json을 업로드하고 인증을 완료했지만, Claude Code에서 workspace-mcp 도구를 호출하면 "인증이 안되었다"는 오류가 반복적으로 발생함.

## 근본 원인 분석

### 1. 토큰 자체는 정상
- 토큰 파일 위치: `~/.google_workspace_mcp/credentials/{email}.json`
- 토큰 형식: workspace MCP 형식 (token, refresh_token, client_id, client_secret 포함)
- Google API 검증: **성공** ✓
- 토큰 만료 여부: 정상 (35분 남음)

### 2. 핵심 문제: OAuth 콜백 포트 불일치

```
문제:
- workspace MCP 기본 포트: 8000
- client_secret.json redirect_uri: http://localhost:8765/oauth2callback
- 결과: 포트 불일치로 인해 MCP가 OAuth 플로우를 다시 시작하려고 시도 → 실패
```

로그에서 확인된 오류:
```
Port 8000 is already in use on localhost. Cannot start minimal OAuth server.
GoogleAuthenticationError: Cannot initiate OAuth flow - callback server unavailable
```

## 해결 방법

### 단계 1: MCP 설정 수정
`~/.claude.json` 파일에서 각 workspace-mcp 서버의 환경 변수에 `WORKSPACE_MCP_PORT` 추가:

```json
{
  "workspace-mcp-workspace-intenet8821": {
    "env": {
      "USER_GOOGLE_EMAIL": "intenet8821@gmail.com",
      "WORKSPACE_MCP_BASE_URI": "http://localhost",
      "WORKSPACE_MCP_PORT": "8765",  // ← 추가
      "OAUTHLIB_INSECURE_TRANSPORT": "true"
    }
  },
  "workspace-mcp-workspace-intenet1": {
    "env": {
      "USER_GOOGLE_EMAIL": "intenet1@gmail.com",
      "WORKSPACE_MCP_BASE_URI": "http://localhost",
      "WORKSPACE_MCP_PORT": "8766",  // ← 추가
      "OAUTHLIB_INSECURE_TRANSPORT": "true"
    }
  }
}
```

**중요**: 각 계정마다 다른 포트를 사용해야 함 (예: 8765, 8766)

### 단계 2: client_secret.json의 redirect_uri 확인

각 계정의 `client_secret.json` 파일의 `redirect_uris`가 MCP 포트와 일치하는지 확인:

```json
{
  "web": {
    "redirect_uris": [
      "http://localhost:8765/oauth2callback",  // ← MCP 포트와 일치
      "http://localhost/oauth2callback"
    ]
  }
}
```

### 단계 3: oauth_port_map.json 업데이트

auth converter 서버가 포트 매핑을 저장하는 파일:
`~/.mcp-workspace/oauth_port_map.json`

```json
{
  "CLIENT_ID_1": 8765,
  "CLIENT_ID_2": 8766
}
```

## 테스트 및 검증

### 진단 스크립트 사용
`test-mcp-auth.js`를 실행하여 토큰 상태 확인:

```bash
cd "/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter"
node test-mcp-auth.js
```

이 스크립트는:
1. 토큰 파일 위치 확인
2. 토큰 만료 여부 확인
3. Google API로 토큰 검증
4. 필요시 토큰 자동 갱신
5. 실제 Google API 호출 테스트

### 수동 테스트
Claude Code에서 workspace-mcp 도구 호출:
```
workspace-mcp-workspace-intenet8821을 사용하여 오늘 받은 이메일 확인
```

## 예방 조치

### 1. auth converter 프로그램 개선 사항
- OAuth 포트를 자동으로 감지하고 `oauth_port_map.json`에 저장 ✓ (이미 구현됨)
- client_secret.json 업로드 시 redirect_uri에서 포트 추출
- MCP 설정 생성 시 자동으로 `WORKSPACE_MCP_PORT` 포함

### 2. 다중 계정 설정 가이드
여러 Google 계정을 사용할 때:
- 각 계정마다 고유한 포트 할당 (8765, 8766, 8767, ...)
- client_secret.json의 redirect_uri를 해당 포트로 설정
- MCP 환경 변수에 올바른 포트 지정

### 3. 문제 발생 시 체크리스트
1. ☑ 토큰 파일 존재 여부: `~/.google_workspace_mcp/credentials/{email}.json`
2. ☑ 토큰 만료 여부: `expiry` 필드 확인
3. ☑ client_secret.json 포트: `redirect_uris` 확인
4. ☑ MCP 설정 포트: `WORKSPACE_MCP_PORT` 환경 변수 확인
5. ☑ 포트 충돌 여부: `lsof -i :8765` 등으로 확인
6. ☑ MCP 로그 확인: `mcp_server_debug.log` 파일

## 기술적 세부사항

### workspace MCP 포트 결정 로직 (main.py:88)
```python
port = int(os.getenv("PORT", os.getenv("WORKSPACE_MCP_PORT", 8000)))
```

우선순위:
1. `PORT` 환경 변수
2. `WORKSPACE_MCP_PORT` 환경 변수
3. 기본값: 8000

### 토큰 형식
workspace MCP는 두 가지 토큰 형식을 지원:
- 표준 OAuth: `access_token`, `refresh_token`
- workspace MCP: `token`, `refresh_token`

### 디버깅 명령어
```bash
# MCP 로그 확인
tail -f "/Users/gwanli/Library/Application Support/Claude/Claude Extensions/local.dxt.taylor-wilsdon.workspace-mcp/mcp_server_debug.log"

# 포트 사용 여부 확인
lsof -i :8765
lsof -i :8766

# 토큰 파일 확인
cat ~/.google_workspace_mcp/credentials/intenet8821@gmail.com.json | python3 -m json.tool
```

## 결론

문제는 **OAuth 콜백 포트 불일치**였으며, `WORKSPACE_MCP_PORT` 환경 변수를 추가하여 해결했습니다.

핵심은:
- ✓ 토큰 자체는 정상 작동
- ✓ 포트 설정만 맞추면 인증 정상 작동
- ✓ 다중 계정 사용 시 각 계정마다 다른 포트 필요

---
작성일: 2025-11-11
작성자: Claude Code Diagnostic Tool
