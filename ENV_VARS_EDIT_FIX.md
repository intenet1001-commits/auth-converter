# 환경 변수 편집 개선 완료

**날짜**: 2025-11-11
**이슈**: 환경 변수 편집 시 user_config에 정의된 필수 필드가 표시되지 않음

## 문제 상황

사용자가 **환경 변수 편집** 버튼을 클릭했을 때:

**표시되는 것** (Before):
- USER_GOOGLE_EMAIL
- WORKSPACE_MCP_BASE_URI
- OAUTHLIB_INSECURE_TRANSPORT

**표시되지 않는 것** (Missing):
- GOOGLE_OAUTH_CLIENT_ID ❌
- GOOGLE_OAUTH_CLIENT_SECRET ❌
- 기타 user_config에 정의된 필드들 ❌

**문제**: Extension의 `manifest.json`에 정의된 **필수 환경 변수**가 표시되지 않음!

## 근본 원인

```javascript
// 기존 코드 (Before)
const currentEnv = (ext.server && ext.server.mcp_config && ext.server.mcp_config.env) || {};

Object.keys(currentEnv).forEach(key => {
  // currentEnv에 있는 것만 표시
});
```

**문제점**:
- `currentEnv`에는 **이미 설정된** 환경 변수만 포함
- `manifest.json`의 `user_config`에 정의된 필드는 값이 없으면 `currentEnv`에 없음
- 따라서 `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` 같은 **필수 필드**가 표시되지 않음

## 해결 방법

### 1. user_config와 currentEnv 병합

```javascript
// Get current environment variables
const currentEnv = (ext.server && ext.server.mcp_config && ext.server.mcp_config.env) || {};

// Get user_config fields from extension manifest
const userConfig = ext.userConfig || {};

// Merge: All user_config fields + any additional env vars not in user_config
const allEnvKeys = new Set([...Object.keys(userConfig), ...Object.keys(currentEnv)]);
```

### 2. 우선순위 기반 표시

**우선순위 1: user_config 필드** (필수 및 선택 항목)
```javascript
Object.keys(userConfig).forEach(key => {
  const field = userConfig[key];
  const currentValue = currentEnv[key] || '';  // 현재 값 또는 빈 문자열
  const isRequired = field.required ? ' <span style="color: red;">*</span>' : '';
  const description = field.description ? `<div style="font-size: 11px; color: #666; margin-top: 3px;">${escapeHtml(field.description)}</div>` : '';

  envFieldsHtml += `
    <div style="margin-bottom: 12px;">
      <label style="display: block; margin-bottom: 5px; font-weight: bold; color: #667eea;">
        ${escapeHtml(field.title || key)}${isRequired}
      </label>
      ${description}
      <input type="${field.type === 'number' ? 'number' : 'text'}"
             id="edit_env_${escapeHtml(key)}"
             value="${escapeHtml(String(currentValue))}"
             placeholder="${escapeHtml(field.description || '')}"
             style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: monospace;">
    </div>
  `;
});
```

**우선순위 2: 추가 환경 변수** (user_config에 없는 것)
```javascript
Object.keys(currentEnv).forEach(key => {
  if (!userConfig[key]) {
    const value = currentEnv[key];
    envFieldsHtml += `
      <div style="margin-bottom: 12px;">
        <label style="display: block; margin-bottom: 5px; font-weight: bold; color: #888;">
          ${escapeHtml(key)} <span style="font-size: 11px; color: #999;">(추가 변수)</span>
        </label>
        <input type="text" id="edit_env_${escapeHtml(key)}" value="${escapeHtml(String(value))}"
               style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: monospace;">
      </div>
    `;
  }
});
```

## 개선 사항

### 1. 모든 필수 필드 표시
- ✅ GOOGLE_OAUTH_CLIENT_ID
- ✅ GOOGLE_OAUTH_CLIENT_SECRET
- ✅ USER_GOOGLE_EMAIL
- ✅ WORKSPACE_MCP_PORT
- ✅ WORKSPACE_MCP_BASE_URI
- ✅ OAUTHLIB_INSECURE_TRANSPORT
- ✅ 기타 모든 user_config 필드

### 2. 필드 정보 표시
- ✅ **타이틀**: `field.title` 사용 (예: "Google OAuth Client ID")
- ✅ **필수 표시**: 빨간색 별표 `*` (field.required)
- ✅ **설명**: `field.description` 표시 (회색 작은 글씨)
- ✅ **플레이스홀더**: 입력 힌트
- ✅ **입력 타입**: number 필드는 `type="number"`

### 3. 구분된 섹션
- **user_config 필드**: 파란색 라벨 (#667eea)
- **추가 변수**: 회색 라벨 (#888) + "(추가 변수)" 태그

## 사용자 경험 개선

### Before (개선 전)
```
환경 변수 편집
─────────────────
USER_GOOGLE_EMAIL: intenet1@gmail.com
WORKSPACE_MCP_BASE_URI: http://localhost
OAUTHLIB_INSECURE_TRANSPORT: true

❌ GOOGLE_OAUTH_CLIENT_ID가 없음!
❌ GOOGLE_OAUTH_CLIENT_SECRET가 없음!
```

### After (개선 후)
```
환경 변수 편집
─────────────────
Google OAuth Client ID *
⚠️ 빈칸으로 두세요 - 프로그램이 업로드된 client_secret.json에서 자동으로 읽습니다.
[선택 입력]

Google OAuth Client Secret *
⚠️ 빈칸으로 두세요 - 프로그램이 업로드된 client_secret.json에서 자동으로 읽습니다.
[선택 입력]

USER_GOOGLE_EMAIL *
[intenet1@gmail.com]

Workspace MCP Port (Optional)
⚠️ 빈칸으로 두세요 - 프로그램 시작 시 업로드된 client_secret.json의 redirect_uris에서 자동으로 포트를 감지합니다...
[        ]

WORKSPACE_MCP_BASE_URI
[http://localhost]

OAUTHLIB_INSECURE_TRANSPORT
[true]
```

## 기술적 세부사항

### manifest.json 구조
```json
{
  "user_config": {
    "GOOGLE_OAUTH_CLIENT_ID": {
      "type": "string",
      "title": "Google OAuth Client ID",
      "description": "⚠️ 빈칸으로 두세요 - 프로그램이 업로드된 client_secret.json에서 자동으로 읽습니다.",
      "required": true
    },
    "GOOGLE_OAUTH_CLIENT_SECRET": {
      "type": "string",
      "title": "Google OAuth Client Secret",
      "description": "⚠️ 빈칸으로 두세요 - 프로그램이 업로드된 client_secret.json에서 자동으로 읽습니다.",
      "required": true
    },
    "USER_GOOGLE_EMAIL": {
      "type": "string",
      "title": "User Google Email",
      "required": true
    },
    "WORKSPACE_MCP_PORT": {
      "type": "number",
      "title": "Workspace MCP Port (Optional)",
      "description": "⚠️ 빈칸으로 두세요 - 자동 포트 감지",
      "required": false
    }
  }
}
```

### 필드 렌더링 로직

```javascript
// 1. user_config 필드 우선 표시
Object.keys(userConfig).forEach(key => {
  const field = userConfig[key];
  const currentValue = currentEnv[key] || '';  // 빈 값도 표시!

  // 필수 필드 표시
  const isRequired = field.required ? ' *' : '';

  // 설명 표시
  const description = field.description || '';

  // 입력 타입 (number vs text)
  const inputType = field.type === 'number' ? 'number' : 'text';
});

// 2. 추가 환경 변수 표시 (user_config에 없는 것)
Object.keys(currentEnv).forEach(key => {
  if (!userConfig[key]) {
    // "(추가 변수)" 태그 표시
  }
});
```

## 테스트 시나리오

### 시나리오 1: 새로운 workspace-mcp 서버

**입력**:
1. Extensions 탭에서 workspace-mcp 선택
2. "✏️ 편집" 버튼 클릭

**예상 결과**:
```
✅ GOOGLE_OAUTH_CLIENT_ID 필드 표시 (빈 값)
✅ GOOGLE_OAUTH_CLIENT_SECRET 필드 표시 (빈 값)
✅ USER_GOOGLE_EMAIL 필드 표시 (현재 값)
✅ WORKSPACE_MCP_PORT 필드 표시 (빈 값)
✅ WORKSPACE_MCP_BASE_URI 필드 표시 (현재 값)
✅ OAUTHLIB_INSECURE_TRANSPORT 필드 표시 (현재 값)
```

### 시나리오 2: 일부 필드만 설정된 서버

**입력**:
- currentEnv: `{ USER_GOOGLE_EMAIL: "test@gmail.com" }`
- userConfig: 6개 필드 정의

**예상 결과**:
```
✅ 6개 모든 user_config 필드 표시
✅ USER_GOOGLE_EMAIL에만 값 표시
✅ 나머지 5개는 빈 입력 필드
```

### 시나리오 3: 추가 환경 변수 포함

**입력**:
- currentEnv: `{ ..., CUSTOM_VAR: "custom_value" }`
- userConfig: CUSTOM_VAR 정의 없음

**예상 결과**:
```
✅ user_config 필드 먼저 표시 (파란색)
✅ CUSTOM_VAR 마지막에 표시 (회색 + "추가 변수" 태그)
```

## 사용자 워크플로우

```
1. Extensions 탭 선택
   ↓
2. workspace-mcp extension 찾기
   ↓
3. "▼ 환경 변수 보기" 클릭
   ↓
4. "✏️ 편집" 버튼 클릭
   ↓
5. 모달 열림:
   - ✅ GOOGLE_OAUTH_CLIENT_ID (빈 값)
   - ✅ GOOGLE_OAUTH_CLIENT_SECRET (빈 값)
   - ✅ USER_GOOGLE_EMAIL (현재 값)
   - ✅ WORKSPACE_MCP_PORT (빈 값)
   - ✅ 기타 필드들...
   ↓
6. 필요한 필드 입력
   ↓
7. "저장" 클릭
   ↓
8. ✅ Claude Desktop config 업데이트
   ↓
9. Extension 목록 새로고침
```

## 추가 개선 사항

### 구현됨
- ✅ user_config 모든 필드 표시
- ✅ 필수 필드 별표 표시
- ✅ 필드 설명 표시
- ✅ 입력 타입 자동 설정
- ✅ 추가 변수 구분 표시

### 향후 개선 가능
- [ ] 필드 유효성 검사
- [ ] boolean 타입 체크박스 지원
- [ ] select 타입 드롭다운 지원
- [ ] 필드 순서 커스터마이징
- [ ] 필드 그룹화

## 파일 변경 요약

| 파일 | 변경 사항 | 라인 |
|-----|----------|------|
| index.html | userConfig 병합 로직 추가 | 3988-3992 |
| index.html | user_config 필드 우선 표시 | 4000-4018 |
| index.html | 추가 환경 변수 구분 표시 | 4020-4032 |

## 결론

✅ **완전히 해결됨!**

**개선 효과**:
1. ✅ 모든 필수 환경 변수가 표시됨
2. ✅ 빈 필드도 입력 가능
3. ✅ 필드 정보 (타이틀, 설명, 필수 여부) 표시
4. ✅ 사용자가 모든 필드를 한눈에 볼 수 있음
5. ✅ 추가 변수도 구분하여 표시

**사용자 피드백 반영**:
> "편집항목 기본입력시 항목이 모두 있어야지"
→ ✅ 이제 user_config에 정의된 모든 항목이 표시됩니다!

---

**상태**: ✅ 구현 완료
**테스트**: npm start 후 Extensions 탭에서 "환경 변수 편집" 확인
**다음 단계**: 사용자 테스트 및 피드백
