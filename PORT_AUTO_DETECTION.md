# Port Auto-Detection Feature

**날짜**: 2025-11-12
**이슈**: 이메일 추가 후에도 "ℹ️ 포트 미설정: WORKSPACE_MCP_PORT 환경변수를 추가하세요" 경고 메시지가 남아있음

---

## 🔍 문제 상황

사용자가 "이메일 추가 & 인증" 버튼으로 이메일을 추가한 후:
- ✅ `USER_GOOGLE_EMAIL` 환경변수는 정상적으로 추가됨
- ✅ OAuth 인증도 정상 작동
- ❌ **하지만** `WORKSPACE_MCP_PORT` 환경변수는 추가되지 않음
- ❌ 결과: 포트 미설정 경고 메시지가 계속 표시됨

**사용자 피드백**: "그런데 'ℹ️ 포트 미설정: WORKSPACE_MCP_PORT 환경변수를 추가하세요 (권장 포트: 8766)'는 왜 남아있지?"

---

## ✅ 해결 방법

### 자동 포트 감지 및 설정 기능 구현

**핵심 아이디어**: 이메일 추가 시 저장된 `client_secret.json`에서 포트를 자동으로 감지하여 Claude Config에 추가

---

## 📝 구현 내용

### 1. 프론트엔드: `processEmailAuth` 함수 수정

**파일**: `/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter/public/index.html`
**라인**: 2586-2621

**추가된 로직**:

```javascript
// Add email to server config
if (!projects[homeDir].mcpServers[serverName].env) {
  projects[homeDir].mcpServers[serverName].env = {};
}
projects[homeDir].mcpServers[serverName].env.USER_GOOGLE_EMAIL = email;

// Try to auto-detect and set WORKSPACE_MCP_PORT from saved client_secret
console.log('🔵 포트 자동 감지 시도 중...');
try {
  // Extract accountId from serverName (e.g., "workspace-mcp-workspace-intenet1" -> "intenet1")
  const accountIdMatch = serverName.match(/workspace-mcp-workspace-(.+)$/);
  if (accountIdMatch) {
    const accountId = accountIdMatch[1];
    console.log('🔵 accountId 추출:', accountId);

    // Check for saved client_secret file
    const checkPortResponse = await fetch('/api/get-oauth-port', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId })
    });

    if (checkPortResponse.ok) {
      const portData = await checkPortResponse.json();
      if (portData.success && portData.port) {
        console.log('🔵 포트 자동 감지 성공:', portData.port);
        projects[homeDir].mcpServers[serverName].env.WORKSPACE_MCP_PORT = portData.port.toString();
      } else {
        console.log('🔵 포트 자동 감지 실패, 기본값 사용');
      }
    }
  }
} catch (portError) {
  console.log('🔵 포트 자동 감지 오류 (무시):', portError.message);
  // Continue even if port detection fails
}
```

**동작 원리**:
1. 서버 이름에서 accountId 추출 (`workspace-mcp-workspace-intenet1` → `intenet1`)
2. 새로운 API 엔드포인트 `/api/get-oauth-port` 호출
3. 성공 시 `WORKSPACE_MCP_PORT` 환경변수 자동 추가
4. 실패해도 계속 진행 (이메일 추가는 정상 처리)

---

### 2. 백엔드: `/api/get-oauth-port` 엔드포인트 생성

**파일**: `/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter/server.js`
**라인**: 447-541

**엔드포인트 정의**:

```javascript
// Get OAuth port for a specific account from saved client_secret
app.post('/api/get-oauth-port', (req, res) => {
  try {
    const { accountId } = req.body;

    if (!accountId) {
      return res.status(400).json({
        success: false,
        error: 'accountId가 필요합니다'
      });
    }

    console.log(`🔍 Checking OAuth port for account: ${accountId}`);

    // Path to saved client_secret file
    const clientSecretPath = path.join(
      __dirname,
      '..',
      'google_workspace_mcp',
      `client_secret_${accountId}`,
      'client_secret.json'
    );

    console.log(`📁 Looking for client_secret at: ${clientSecretPath}`);

    if (!fs.existsSync(clientSecretPath)) {
      console.log(`❌ Client secret file not found for ${accountId}`);
      return res.json({
        success: false,
        error: 'Client secret 파일을 찾을 수 없습니다'
      });
    }

    // Read client_secret file
    const clientSecret = JSON.parse(fs.readFileSync(clientSecretPath, 'utf8'));
    const clientConfig = clientSecret.web || clientSecret.installed;

    if (!clientConfig || !clientConfig.client_id) {
      console.log(`❌ Invalid client_secret format for ${accountId}`);
      return res.json({
        success: false,
        error: 'Client secret 형식이 올바르지 않습니다'
      });
    }

    const clientId = clientConfig.client_id;
    console.log(`✓ Found client_id: ${clientId}`);

    // Try to get port from oauth_port_map.json
    const homeDir = os.homedir();
    const portMapPath = path.join(homeDir, '.mcp-workspace', 'oauth_port_map.json');

    if (fs.existsSync(portMapPath)) {
      const portMap = JSON.parse(fs.readFileSync(portMapPath, 'utf8'));

      if (portMap[clientId]) {
        const port = portMap[clientId];
        console.log(`✓ Found port ${port} for client_id ${clientId}`);
        return res.json({
          success: true,
          port: port,
          clientId: clientId,
          source: 'oauth_port_map'
        });
      }
    }

    // Fallback: Try to extract port from redirect_uri
    if (clientConfig.redirect_uris && clientConfig.redirect_uris.length > 0) {
      const redirectUri = clientConfig.redirect_uris[0];
      const portMatch = redirectUri.match(/:(\d+)\//);

      if (portMatch) {
        const port = parseInt(portMatch[1]);
        console.log(`✓ Extracted port ${port} from redirect_uri: ${redirectUri}`);
        return res.json({
          success: true,
          port: port,
          clientId: clientId,
          source: 'redirect_uri'
        });
      }
    }

    console.log(`❌ Could not determine port for ${accountId}`);
    return res.json({
      success: false,
      error: '포트를 확인할 수 없습니다'
    });

  } catch (error) {
    console.error('Error in get-oauth-port:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});
```

**포트 감지 전략** (우선순위 순):

1. **PRIORITY 1**: `oauth_port_map.json`에서 client_id로 조회
   - 파일 위치: `~/.mcp-workspace/oauth_port_map.json`
   - 구조: `{ "client_id": port_number }`
   - 가장 신뢰할 수 있는 소스

2. **PRIORITY 2**: `client_secret.json`의 `redirect_uris`에서 추출
   - 예: `http://localhost:8766/oauth2callback` → 포트 8766 추출
   - Fallback으로 사용

---

## 🎯 동작 흐름

### 전체 프로세스

```
1. 사용자가 "이메일 추가 & 인증" 버튼 클릭
   ↓
2. 커스텀 모달에서 이메일 입력 (예: intenet1@gmail.com)
   ↓
3. processEmailAuth 함수 실행
   ↓
4. 서버 이름에서 accountId 추출
   (workspace-mcp-workspace-intenet1 → intenet1)
   ↓
5. /api/get-oauth-port API 호출 (accountId: "intenet1")
   ↓
6. 서버: client_secret_intenet1/client_secret.json 읽기
   ↓
7. 서버: client_id 추출
   ↓
8. 서버: oauth_port_map.json에서 포트 조회
   ↓
9. 성공 시: { success: true, port: 8766, source: "oauth_port_map" }
   ↓
10. 프론트엔드: WORKSPACE_MCP_PORT = "8766" 추가
    ↓
11. Claude Config 저장
    ↓
12. ✅ 완료: 이메일과 포트가 모두 설정됨
```

---

## 📁 관련 파일 경로

### 프론트엔드
- `/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter/public/index.html`
  - 라인 2478-2538: `addEmailAndAuth` 함수 (커스텀 모달)
  - 라인 2540-2621: `processEmailAuth` 함수 (포트 자동 감지)

### 백엔드
- `/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter/server.js`
  - 라인 447-541: `/api/get-oauth-port` 엔드포인트

### 데이터 파일
- `~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_{accountId}/client_secret.json`
  - 저장된 OAuth client_secret 파일
  - client_id와 redirect_uris 포함

- `~/.mcp-workspace/oauth_port_map.json`
  - client_id → port 매핑
  - 예: `{"785825570589-2u5kd1tukgq6cbdceto8kug0svp44gl6.apps.googleusercontent.com": 8766}`

- `~/.claude.json`
  - Claude Config 파일
  - 이메일과 포트가 저장되는 최종 목적지

---

## 🧪 테스트 시나리오

### 시나리오 1: 정상 케이스 (파일 모두 존재)

**사전 조건**:
- ✅ client_secret_intenet1/client_secret.json 존재
- ✅ oauth_port_map.json 존재
- ✅ client_id가 매핑되어 있음

**실행**:
1. "이메일 추가 & 인증" 버튼 클릭
2. intenet1@gmail.com 입력
3. 확인 클릭

**예상 결과**:
```javascript
// Claude Config에 추가됨:
{
  "env": {
    "USER_GOOGLE_EMAIL": "intenet1@gmail.com",
    "WORKSPACE_MCP_PORT": "8766",  // ← 자동 추가됨!
    "WORKSPACE_MCP_BASE_URI": "http://localhost",
    "OAUTHLIB_INSECURE_TRANSPORT": "true"
  }
}
```

**콘솔 로그**:
```
🔵 포트 자동 감지 시도 중...
🔵 accountId 추출: intenet1
🔍 Checking OAuth port for account: intenet1
📁 Looking for client_secret at: .../client_secret_intenet1/client_secret.json
✓ Found client_id: 785825570589-2u5kd1tukgq6cbdceto8kug0svp44gl6.apps.googleusercontent.com
✓ Found port 8766 for client_id 785825570589-...
🔵 포트 자동 감지 성공: 8766
```

---

### 시나리오 2: oauth_port_map.json 없음 (Fallback)

**사전 조건**:
- ✅ client_secret_intenet1/client_secret.json 존재
- ❌ oauth_port_map.json 없음 또는 client_id 없음

**실행**: 동일

**예상 결과**:
- redirect_uri에서 포트 추출: `http://localhost:8766/oauth2callback` → 8766
- 여전히 `WORKSPACE_MCP_PORT: "8766"` 추가됨

**콘솔 로그**:
```
✓ Extracted port 8766 from redirect_uri: http://localhost:8766/oauth2callback
🔵 포트 자동 감지 성공: 8766
```

---

### 시나리오 3: client_secret 파일 없음 (실패)

**사전 조건**:
- ❌ client_secret_intenet1/client_secret.json 없음

**실행**: 동일

**예상 결과**:
- `WORKSPACE_MCP_PORT`가 추가되지 않음
- 하지만 `USER_GOOGLE_EMAIL`은 정상 추가됨
- 포트 경고 메시지는 여전히 표시됨

**콘솔 로그**:
```
🔵 포트 자동 감지 시도 중...
🔵 accountId 추출: intenet1
🔍 Checking OAuth port for account: intenet1
📁 Looking for client_secret at: .../client_secret_intenet1/client_secret.json
❌ Client secret file not found for intenet1
🔵 포트 자동 감지 실패, 기본값 사용
```

**참고**: 이 경우 사용자는 Extensions 탭에서 client_secret을 먼저 업로드해야 함

---

## 🎨 UI 변화

### Before (포트 미설정)
```
┌─────────────────────────────────────────────────┐
│ workspace-mcp-workspace-intenet1                │
│ ⚠️ 이메일 미설정                                │
│ ℹ️ 포트 미설정: WORKSPACE_MCP_PORT 환경변수를  │
│    추가하세요 (권장 포트: 8766)                 │
│                                                  │
│ [📧 이메일 추가 & 인증]                         │
└─────────────────────────────────────────────────┘
```

### After (자동 설정 완료)
```
┌─────────────────────────────────────────────────┐
│ workspace-mcp-workspace-intenet1                │
│ ✓ 인증됨: intenet1@gmail.com                   │
│ 🟢 정상                                          │
│ 포트: 8766                                       │
│                                                  │
│ [🔄 재인증] [🔓 인증 해제]                       │
└─────────────────────────────────────────────────┘
```

**변화**:
- ✅ 이메일 설정됨
- ✅ 포트 설정됨
- ✅ 경고 메시지 사라짐
- ✅ 인증 상태 정상 표시

---

## 🔑 핵심 기술

### 1. **정규식 패턴 매칭**
```javascript
// 서버 이름에서 accountId 추출
const accountIdMatch = serverName.match(/workspace-mcp-workspace-(.+)$/);

// redirect_uri에서 포트 추출
const portMatch = redirectUri.match(/:(\d+)\//);
```

### 2. **우선순위 기반 Fallback**
```javascript
// PRIORITY 1: oauth_port_map.json
if (fs.existsSync(portMapPath)) {
  const portMap = JSON.parse(fs.readFileSync(portMapPath, 'utf8'));
  if (portMap[clientId]) {
    return port; // ✓ 가장 신뢰할 수 있는 소스
  }
}

// PRIORITY 2: redirect_uri
if (clientConfig.redirect_uris) {
  const portMatch = redirectUri.match(/:(\d+)\//);
  if (portMatch) {
    return parseInt(portMatch[1]); // ✓ Fallback
  }
}
```

### 3. **에러 허용 설계**
```javascript
try {
  // 포트 감지 시도
  const portData = await fetch('/api/get-oauth-port', {...});
  if (portData.success) {
    // 성공 시 포트 추가
  }
} catch (portError) {
  console.log('🔵 포트 자동 감지 오류 (무시):', portError.message);
  // Continue even if port detection fails
}
```

**중요**: 포트 감지 실패해도 이메일 추가는 계속 진행됨!

---

## ✅ 장점

### 1. **사용자 경험 개선**
- ✅ 수동 포트 설정 불필요
- ✅ 한 번의 버튼 클릭으로 이메일 + 포트 모두 설정
- ✅ 경고 메시지 자동 제거

### 2. **안정성**
- ✅ Fallback 메커니즘으로 높은 성공률
- ✅ 실패해도 이메일 추가는 정상 진행
- ✅ 명확한 에러 메시지 제공

### 3. **유지보수성**
- ✅ 단일 API 엔드포인트로 집중화
- ✅ 디버깅 로그로 추적 가능
- ✅ 확장 가능한 구조

---

## 📊 변경 사항 요약

| 파일 | 라인 | 변경 내용 |
|-----|------|----------|
| `public/index.html` | 2586-2621 | 포트 자동 감지 로직 추가 |
| `server.js` | 447-541 | `/api/get-oauth-port` 엔드포인트 생성 |

---

## 🔄 관련 문서

- **버튼 클릭 문제 해결**: `PROMPT_TO_MODAL_FIX.md`
- **디버깅 가이드**: `BUTTON_DEBUG_STATUS.md`
- **테스트 가이드**: `BUTTON_TESTING_GUIDE.md`

---

**상태**: ✅ 구현 완료
**테스트**: Electron 앱 재시작 후 버튼 작동 확인 필요
**다음 단계**: 사용자가 앱을 재시작하고 "이메일 추가 & 인증" 버튼 테스트
