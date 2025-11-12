# 포트 메시지 중복 표시 문제 해결

**날짜**: 2025-11-11
**이슈**: 포트 자동 감지 실패 메시지가 두 번 중복으로 표시됨

## 문제 상황

사용자가 workspace-mcp extension을 선택하고 client_secret.json을 업로드했을 때:

```
⚠️ 포트 자동 감지 실패: 업로드된 client_secret.json이나 저장된 포트 매핑에서 포트를 찾을 수 없습니다.
아래 "WORKSPACE_MCP_PORT" 필드에 client_secret.json의 redirect_uri 포트를 직접 입력하세요.
예: redirect_uri가 "http://localhost:8766/oauth2callback"이면 8766 입력

⚠️ 포트 자동 감지 실패: 업로드된 client_secret.json이나 저장된 포트 매핑에서 포트를 찾을 수 없습니다.
아래 "WORKSPACE_MCP_PORT" 필드에 client_secret.json의 redirect_uri 포트를 직접 입력하세요.
예: redirect_uri가 "http://localhost:8766/oauth2callback"이면 8766 입력
```

**→ 동일한 메시지가 2번 표시됨!**

## 근본 원인

### 메시지가 생성되는 두 곳

1. **Extension 변환 후 (라인 4224)**:
   - 포트 감지 시도 후 실패 시 동적으로 메시지 생성
   - 조건: `portDetectionAttempted && !result.portAutoConfigured`

2. **환경 변수 필드 표시 시 (라인 4284-4292)**:
   - `displayUserConfigFields()` 함수에서 WORKSPACE_MCP_PORT 필드마다 경고 박스 추가
   - 조건: `key === 'WORKSPACE_MCP_PORT'` (항상 표시)

### 중복 발생 시나리오

```
Extension 선택
↓
/api/extension-to-mcp 호출
↓
포트 감지 시도 → 실패
↓
라인 4224: 노란색 경고 메시지 생성 (1번째)
↓
displayUserConfigFields() 호출
↓
라인 4284: 노란색 경고 박스 생성 (2번째)
↓
결과: 같은 내용이 2번 표시됨
```

## 해결 방법

### 역할 분리

1. **동적 메시지 (라인 4224)**:
   - 포트 자동 감지의 **실제 결과**를 표시
   - 성공 시: 초록색 성공 메시지
   - 실패 시: 노란색 경고 메시지

2. **정적 안내 (라인 4284)**:
   - WORKSPACE_MCP_PORT 필드의 **일반적인 안내**
   - 파란색 정보 박스로 변경
   - 간단한 참고 사항만 표시

### 코드 수정

**Before (중복 경고)**:
```javascript
// displayUserConfigFields() 함수 내부
if (key === 'WORKSPACE_MCP_PORT') {
  html += '<div style="...background: #fff3cd...">'; // 노란색
  html += '⚠️ 중요:';
  html += '• 자동 감지 성공 시: 비워둡니다';
  html += '• 자동 감지 실패 시: 직접 입력하세요';
  html += '• 예: redirect_uri가 "http://localhost:8766/oauth2callback"이면 8766 입력';
  html += '</div>';
}
```

**After (간결한 안내)**:
```javascript
// displayUserConfigFields() 함수 내부
if (key === 'WORKSPACE_MCP_PORT') {
  html += '<div style="...background: #e3f2fd...">'; // 파란색
  html += '💡 참고: 위에 포트 자동 감지 결과가 표시됩니다. ';
  html += '성공 시 이 필드를 비워두면 자동으로 설정됩니다.';
  html += '</div>';
}
```

## 개선 효과

### Before (개선 전)
```
[MCP Config Display]

⚠️ 포트 자동 감지 실패: ...상세한 메시지... (1번째)

필요한 환경 변수:

WORKSPACE_MCP_PORT
⚠️ 중요: ...동일한 상세 메시지... (2번째 - 중복!)
[입력 필드]
```

### After (개선 후)
```
[MCP Config Display]

⚠️ 포트 자동 감지 실패: ...상세한 메시지... (1번만 표시)

필요한 환경 변수:

WORKSPACE_MCP_PORT
💡 참고: 위에 포트 자동 감지 결과가 표시됩니다. (간단한 안내)
[입력 필드]
```

## 시각적 차별화

### 동적 메시지 (위쪽)
- **성공**: 🟢 초록색 배경 (#d4edda)
- **실패**: 🟡 노란색 배경 (#fff3cd)
- **내용**: 상세한 결과 및 해결 방법

### 정적 안내 (필드 안)
- **색상**: 🔵 파란색 배경 (#e3f2fd)
- **아이콘**: 💡 (정보)
- **내용**: 간단한 참고 사항

## 테스트 시나리오

### 시나리오 1: 포트 자동 감지 성공
**입력**: client_secret.json 업로드 (redirect_uri: http://localhost:8766)

**예상 결과**:
```
✓ OAuth 포트 자동 설정: WORKSPACE_MCP_PORT가 8766로 자동 설정되었습니다 (업로드된 client_secret.json의 redirect_uri에서 추출).

필요한 환경 변수:
WORKSPACE_MCP_PORT
💡 참고: 위에 포트 자동 감지 결과가 표시됩니다. 성공 시 이 필드를 비워두면 자동으로 설정됩니다.
[        ] (빈 입력 필드)
```

✅ **메시지 1개만 표시** (초록색)

### 시나리오 2: 포트 자동 감지 실패
**입력**: client_secret.json 업로드 (redirect_uri 없음)

**예상 결과**:
```
⚠️ 포트 자동 감지 실패: 업로드된 client_secret.json이나 저장된 포트 매핑에서 포트를 찾을 수 없습니다.
아래 "WORKSPACE_MCP_PORT" 필드에 client_secret.json의 redirect_uri 포트를 직접 입력하세요.
예: redirect_uri가 "http://localhost:8766/oauth2callback"이면 8766 입력

필요한 환경 변수:
WORKSPACE_MCP_PORT
💡 참고: 위에 포트 자동 감지 결과가 표시됩니다. 성공 시 이 필드를 비워두면 자동으로 설정됩니다.
[        ] (입력 필드)
```

✅ **노란색 경고 1개 + 파란색 안내 1개** (역할이 다름)

### 시나리오 3: 초기 상태 (감지 시도 안 함)
**입력**: Extension 선택만 함 (파일 업로드 안 함)

**예상 결과**:
```
필요한 환경 변수:
WORKSPACE_MCP_PORT
💡 참고: 위에 포트 자동 감지 결과가 표시됩니다. 성공 시 이 필드를 비워두면 자동으로 설정됩니다.
[        ] (입력 필드)
```

✅ **메시지 없음** (깔끔한 초기 상태)

## testsprite MCP 테스트 가이드

### 준비
```bash
# 1. 앱 시작
npm start

# 2. 브라우저 열기
# http://localhost:3000
```

### 테스트 케이스 1: workspace-mcp (포트 감지 있음)

**단계**:
1. Extensions 탭 선택
2. workspace-mcp extension 선택
3. client_secret.json 업로드 (redirect_uri 포함)
4. Extension 다시 선택

**확인 사항**:
- ✅ 초록색 성공 메시지 1개만 표시
- ✅ WORKSPACE_MCP_PORT 필드에 파란색 안내 1개
- ✅ 총 2개 메시지, 색상 및 역할이 다름

### 테스트 케이스 2: testsprite MCP (포트 감지 없음)

**단계**:
1. Extensions 탭 선택
2. testsprite-mcp extension 선택 (workspace-mcp 아님)

**확인 사항**:
- ✅ 포트 관련 메시지 없음
- ✅ 다른 환경 변수 필드만 표시
- ✅ 깔끔한 UI

### 테스트 케이스 3: 포트 감지 실패

**단계**:
1. Extensions 탭 선택
2. workspace-mcp extension 선택
3. 잘못된 client_secret.json 업로드 (redirect_uri 없음)
4. Extension 다시 선택

**확인 사항**:
- ✅ 노란색 경고 메시지 1개만 표시 (위쪽)
- ✅ WORKSPACE_MCP_PORT 필드에 파란색 안내 1개 (아래쪽)
- ✅ 중복 없음

## 파일 변경 요약

| 파일 | 변경 사항 | 라인 | 상태 |
|-----|----------|------|------|
| index.html | WORKSPACE_MCP_PORT 필드 안내를 파란색 정보 박스로 변경 | 4283-4291 | ✅ 완료 |

## 기술적 세부사항

### 메시지 우선순위

**우선순위 1: 동적 결과 메시지** (라인 4220-4228)
```javascript
if (portDetectionAttempted) {
  if (result.portAutoConfigured && result.detectedPort) {
    // 🟢 초록색 성공
  } else {
    // 🟡 노란색 실패
  }
}
```

**우선순위 2: 정적 참고 사항** (라인 4284-4290)
```javascript
if (key === 'WORKSPACE_MCP_PORT') {
  // 🔵 파란색 안내 (항상 표시)
}
```

### 색상 코드

| 상태 | 배경색 | 테두리색 | 텍스트색 | 의미 |
|-----|-------|---------|---------|------|
| 성공 | #d4edda | #c3e6cb | #155724 | 포트 자동 설정 완료 |
| 실패 | #fff3cd | #ffc107 | #856404 | 포트 수동 입력 필요 |
| 안내 | #e3f2fd | #2196f3 | #1565c0 | 일반 참고 사항 |

## 사용자 이점

### Before (개선 전)
- ❌ 같은 내용의 경고가 2번 표시
- ❌ 시각적으로 혼란스러움
- ❌ 어느 메시지를 따라야 할지 불명확

### After (개선 후)
- ✅ 각 메시지의 역할이 명확
- ✅ 색상으로 구분 (초록/노랑/파랑)
- ✅ 중복 없이 깔끔한 UI
- ✅ 정보 계층이 명확함

## 향후 개선 가능

1. **아이콘 일관성**:
   - 성공: ✓
   - 실패: ⚠️
   - 안내: 💡

2. **애니메이션**:
   - 메시지 표시 시 fade-in 효과
   - 메시지 변경 시 smooth transition

3. **접기/펼치기**:
   - 상세 메시지를 접을 수 있는 기능
   - "자세히 보기" 버튼

---

**상태**: ✅ 구현 완료
**테스트**: npm start 후 workspace-mcp 및 testsprite MCP로 검증
**다음 단계**: 사용자 피드백 수집
