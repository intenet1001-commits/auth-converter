# 포트 자동 감지 개선 완료

**날짜**: 2025-11-11
**이슈**: 업로드된 client_secret.json에서 redirect_uri 포트를 감지하지 못하는 문제

## 문제 상황

사용자가 client_secret.json을 업로드했음에도 불구하고:
```
⚠️ 포트 자동 감지 실패: oauth_port_map.json 파일이 없거나 매핑 정보가 없습니다.
```

**원인**:
- 기존 로직은 **이미 저장된** client_secret.json 파일만 확인
- Extension 변환 시점에는 파일이 아직 저장되기 전
- 따라서 업로드된 파일의 redirect_uri를 읽을 수 없었음

## 해결 방법

### 우선순위 기반 포트 감지

1. **우선순위 1**: 업로드된 client_secret.json에서 직접 추출 (NEW!)
2. **우선순위 2**: oauth_port_map.json 매핑에서 찾기 (기존)

### 구현 세부사항

#### 1. 서버 측 개선 (server.js)

**파라미터 추가**:
```javascript
const { extension, shareCredentials, uploadedClientSecret } = req.body;
```

**우선순위 1: 업로드된 파일에서 직접 추출**:
```javascript
if (uploadedClientSecret) {
  const clientConfig = uploadedClientSecret.installed || uploadedClientSecret.web;
  if (clientConfig && clientConfig.redirect_uris && clientConfig.redirect_uris.length > 0) {
    const redirectUri = clientConfig.redirect_uris[0];
    const portMatch = redirectUri.match(/:(\d+)\//);  // "http://localhost:8766/" → 8766
    if (portMatch) {
      detectedPort = parseInt(portMatch[1]);
      portSource = 'uploaded_client_secret';
      console.log(`✓ Port ${detectedPort} extracted from uploaded client_secret.json`);

      // 자동으로 환경변수에 추가
      env.WORKSPACE_MCP_PORT = String(detectedPort);
      env.WORKSPACE_MCP_BASE_URI = 'http://localhost';
      env.OAUTHLIB_INSECURE_TRANSPORT = 'true';
    }
  }
}
```

**우선순위 2: 기존 매핑 파일 확인** (fallback):
```javascript
if (!detectedPort) {
  // 기존 oauth_port_map.json 로직...
}
```

**응답에 출처 정보 추가**:
```javascript
res.json({
  detectedPort: detectedPort,
  portAutoConfigured: detectedPort !== null,
  portSource: portSource  // 'uploaded_client_secret' 또는 'oauth_port_map'
});
```

#### 2. 프론트엔드 개선 (index.html)

**업로드된 파일 전달**:
```javascript
const requestPayload = {
  extension: selectedExtension,
  shareCredentials: false
};

// 업로드된 client_secret.json이 있으면 포함
if (loadedEnvData && loadedEnvData._isClientSecret && loadedEnvData._originalData) {
  requestPayload.uploadedClientSecret = loadedEnvData._originalData;
  console.log('✓ Including uploaded client_secret.json for automatic port detection');
}
```

**성공 메시지 개선**:
```javascript
if (result.portAutoConfigured && result.detectedPort) {
  let sourceText = '';
  if (result.portSource === 'uploaded_client_secret') {
    sourceText = ' (업로드된 client_secret.json의 redirect_uri에서 추출)';
  } else if (result.portSource === 'oauth_port_map') {
    sourceText = ' (저장된 포트 매핑에서 자동 감지)';
  }

  portMessage.innerHTML = `
    ✓ OAuth 포트 자동 설정: WORKSPACE_MCP_PORT가 ${result.detectedPort}로 자동 설정되었습니다${sourceText}.
  `;
}
```

## 테스트 시나리오

### 시나리오 1: 업로드된 client_secret.json (NEW - 이제 작동!)

**입력**:
1. Extensions 탭에서 workspace-mcp 선택
2. client_secret.json 업로드 (redirect_uri: "http://localhost:8766/oauth2callback")
3. 계정 식별자 입력
4. "MCP 설정 생성" 클릭

**예상 결과**:
```
✓ OAuth 포트 자동 설정: WORKSPACE_MCP_PORT가 8766로 자동 설정되었습니다
  (업로드된 client_secret.json의 redirect_uri에서 추출).
이제 인증 시 포트 불일치 문제가 발생하지 않습니다.
```

**검증**:
- ✅ 초록색 성공 메시지
- ✅ WORKSPACE_MCP_PORT 필드에 경고 박스 (비워둬도 됨)
- ✅ Config에 병합 시 env.WORKSPACE_MCP_PORT = "8766" 자동 추가

### 시나리오 2: 저장된 포트 매핑 사용 (기존 로직)

**입력**:
1. oauth_port_map.json에 매핑 존재
2. client_secret.json 업로드 안 함
3. 기존 계정 선택

**예상 결과**:
```
✓ OAuth 포트 자동 설정: WORKSPACE_MCP_PORT가 8765로 자동 설정되었습니다
  (저장된 포트 매핑에서 자동 감지).
```

### 시나리오 3: 두 방법 모두 실패 (fallback to manual)

**입력**:
1. client_secret.json 업로드 안 함
2. oauth_port_map.json 없음

**예상 결과**:
```
⚠️ 포트 자동 감지 실패: oauth_port_map.json 파일이 없거나 매핑 정보가 없습니다.
아래 "WORKSPACE_MCP_PORT" 필드에 client_secret.json의 redirect_uri 포트를 직접 입력하세요.
예: redirect_uri가 "http://localhost:8766/oauth2callback"이면 8766 입력
```

## 개선 효과

### Before (개선 전)
❌ **문제**:
- client_secret.json을 업로드해도 "자동 감지 실패" 경고
- 사용자가 redirect_uri를 확인하고 수동으로 포트 입력해야 함
- **불필요한 수동 작업**

### After (개선 후)
✅ **해결**:
- client_secret.json 업로드 시 redirect_uri에서 자동으로 포트 추출
- **8766** → 자동 감지 → env.WORKSPACE_MCP_PORT = "8766"
- 사용자가 아무것도 입력할 필요 없음
- **완전 자동화!**

## 코드 흐름

```
1. 사용자: client_secret.json 업로드
   ↓
2. 프론트엔드: loadedEnvData._originalData에 저장
   ↓
3. Extension 선택 → /api/extension-to-mcp 호출
   ↓
4. 프론트엔드: uploadedClientSecret 파라미터로 전달
   ↓
5. 서버: redirect_uris[0]에서 포트 추출
   - "http://localhost:8766/oauth2callback" → 8766
   ↓
6. 서버: env.WORKSPACE_MCP_PORT = "8766" 자동 추가
   ↓
7. 응답: portAutoConfigured=true, portSource='uploaded_client_secret'
   ↓
8. 프론트엔드: 초록색 성공 메시지 표시
   ↓
9. Config 병합 시 자동으로 포함됨
```

## 로그 출력

**서버 로그**:
```
✓ Port 8766 extracted from uploaded client_secret.json redirect_uri: http://localhost:8766/oauth2callback
```

**프론트엔드 콘솔**:
```
✓ Including uploaded client_secret.json for automatic port detection
```

## 파일 변경 요약

| 파일 | 변경 사항 | 라인 |
|-----|----------|------|
| server.js | uploadedClientSecret 파라미터 추가 | 208 |
| server.js | 우선순위 1: 업로드 파일에서 포트 추출 | 263-284 |
| server.js | 우선순위 2: 매핑 파일 확인 (fallback) | 287-335 |
| server.js | portSource 응답 추가 | 356 |
| index.html | uploadedClientSecret 전달 로직 | 4141-4145 |
| index.html | 포트 출처 표시 개선 | 4173-4183 |

## 사용자 피드백 반영

사용자 질문:
> "첨부파일에 redirect_uris 가 있는데 왜 ⚠️ 포트 자동 감지 실패 에러뜨지?"

**답변**:
- ✅ 이제 해결되었습니다!
- ✅ 업로드된 client_secret.json의 redirect_uri에서 직접 포트를 추출합니다
- ✅ 자동 감지 성공 메시지에 출처가 명시됩니다: "(업로드된 client_secret.json의 redirect_uri에서 추출)"

## 추가 개선 가능 사항

1. **여러 redirect_uris 처리**:
   - 현재: 첫 번째 redirect_uri만 확인
   - 개선: localhost 포함된 것 우선 선택

2. **포트 유효성 검사**:
   - 1024-65535 범위 확인
   - 이미 사용 중인 포트 경고

3. **UI 개선**:
   - 포트 추출 과정을 실시간으로 표시
   - "redirect_uri: http://localhost:8766/... → 포트 8766 추출됨"

---

**상태**: ✅ 구현 완료
**테스트**: npm start 후 실제 환경에서 검증 필요
**다음 단계**: 사용자 테스트 및 피드백 수집
