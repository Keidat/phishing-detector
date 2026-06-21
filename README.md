# PhishGuard — 실시간 피싱 문자 탐지 웹 서비스

> **SDGs 16번 — 평화, 정의, 강력한 제도** 연계 프로젝트
> 하이브리드 AI(규칙 기반 + ML + LLM)로 한국어 스미싱 문자를 실시간 탐지합니다.

---

## 프로젝트 소개

스미싱(SMS + Phishing)은 문자 메시지로 피해자를 속여 개인정보나 금융정보를 탈취하는 사이버 범죄입니다.
KISA(한국인터넷진흥원) 통계에 따르면 스미싱 신고 건수는 매년 증가하고 있으며,
피해자 대부분은 문자를 받는 순간 진짜인지 가짜인지 판단할 수 없습니다.

**PhishGuard**는 의심스러운 문자를 붙여넣으면 즉시:
- 위험도 점수(0~100)와 레벨(안전 / 주의 / 위험)을 알려주고
- **왜** 위험한지 AI가 한국어로 설명하며
- 구체적인 대처법을 안내합니다.

### SDGs 16번 연계

| SDGs 세부 목표 | PhishGuard의 기여 |
|---------------|------------------|
| 16.4 불법 금융 흐름 감소 | 스미싱으로 인한 금융 피해 예방 |
| 16.6 효과적·투명한 제도 | 사이버 범죄 탐지 기술의 시민 접근성 확대 |
| 16.10 정보 접근 보장 | 누구나 무료로 쓸 수 있는 오픈 탐지 도구 |

---

## 하이브리드 탐지 구조

```
문자 입력
│
├─── [규칙 기반 30%] ──────────────────────────────────
│      · 정규식 URL 추출
│      · 단축 URL 도메인 대조 (bit.ly, tinyurl 등 20종)
│      · 긴급성 키워드 탐지 (즉시, 지금 바로, 계좌정지 등)
│      · 개인정보 요구 패턴 (주민번호, 카드번호, OTP 등)
│      · VirusTotal API 악성 URL 조회
│
├─── [ML 모델 40%] ────────────────────────────────────
│      · 전처리: URL→토큰, 단축URL→SHORT_URL_TOKEN
│      · TF-IDF (문자 n-gram 2~4, 3만 특징)
│      · Logistic Regression (class_weight=balanced)
│      · 출력: 피싱 확률 0.0~1.0
│
├─── 중간 점수 계산 (규칙 30% + ML 40% 재정규화)
│
│    ┌─ 중간 점수 < 40  → LLM 호출 생략 (안전 확실)
│    ├─ 40 ≤ 점수 ≤ 70 → LLM 호출 (애매한 구간)
│    └─ 중간 점수 > 70  → LLM 호출 생략 (위험 확실)
│
└─── [LLM 30%] ────────────────────────────────────────
       · Claude claude-sonnet-4-6 API
       · 프롬프트 인젝션 방어 (XML 태그 격리)
       · "왜 피싱인지" 한국어 자연어 설명 생성
       · JSON 파싱 3단계 fallback

최종 점수 → 레벨 판정 → 대처법 생성

0~39점:   안전 🟢
40~69점:  주의 🟡
70~100점: 위험 🔴
```

---

## 보안 설계 요소

| 계층 | 보안 기능 | 이유 |
|------|-----------|------|
| 네트워크 | CORS (허가된 출처만) | CSRF 방어 |
| 미들웨어 | Rate Limiting (IP당 분당 10회) | 무차별 대입·남용 방어 |
| 미들웨어 | 요청 크기 제한 (4,200바이트) | 메모리 고갈 공격 방어 |
| 미들웨어 | Content-Type 강제 검증 | 스니핑 공격 방어 |
| 미들웨어 | 보안 HTTP 헤더 자동 주입 | XSS, 클릭재킹, MIME 스니핑 방어 |
| 입력 | Pydantic 타입 검증 | 잘못된 입력 API 계층 차단 |
| 입력 | Null Byte 제거 | 인젝션 방어 |
| 입력 | 공백 전용 입력 차단 | min_length 우회 방어 |
| 탐지 | 정규식 길이 제한 (2000자) | ReDoS 방어 |
| LLM | XML 태그 입력 격리 | 프롬프트 인젝션 방어 |
| 로그 | IP 마스킹 (마지막 2옥텟) | 개인정보 보호 |
| 로그 | 문자 내용 비저장 | 개인정보 최소화 원칙 |
| 환경 | .env 파일 API 키 관리 | 하드코딩 및 GitHub 유출 방지 |
| 프론트 | textContent 사용 | DOM XSS 방어 |
| 프론트 | escapeHtml() 이스케이프 | innerHTML 사용 시 XSS 방어 |

---

## 폴더 구조

```
phishing-detector/
├── backend/
│   ├── main.py                    # FastAPI 앱 진입점, 미들웨어 등록
│   ├── config.py                  # 환경변수, 가중치 설정
│   ├── database/
│   │   ├── init_db.py             # DB 초기화 스크립트 (최초 1회 실행)
│   │   ├── db_loader.py           # DB 로드 및 메모리 캐싱 모듈
│   │   └── phishguard.db          # SQLite DB 파일 (init_db.py 실행 후 생성)
│   ├── models/
│   │   └── schemas.py             # Pydantic 요청/응답 스키마
│   ├── detectors/
│   │   ├── rule_engine.py         # 규칙 기반 탐지 (URL·키워드·VirusTotal)
│   │   ├── ml_model.py            # ML 모델 로드 및 예측
│   │   └── llm_analyzer.py        # Claude API 연동
│   ├── api/
│   │   └── analyze.py             # POST /analyze 통합 엔드포인트
│   ├── security/
│   │   └── middleware.py          # 로깅·헤더·크기제한·Content-Type
│   └── ml_training/
│       ├── build_dataset.py       # 시드 데이터셋 생성
│       ├── preprocess.py          # 텍스트 전처리
│       ├── train.py               # 모델 학습 (1회 실행)
│       └── model.pkl              # 학습된 모델 (train.py 실행 후 생성)
├── frontend/
│   ├── index.html                 # 메인 페이지
│   ├── style.css                  # 다크 테마 스타일
│   └── app.js                     # API 호출 및 결과 렌더링
├── samples.py                     # 시연용 샘플 문자 7개
├── requirements.txt               # Python 의존성
├── .env.example                   # 환경변수 템플릿
├── .gitignore                     # Git 제외 목록
└── README.md
```

---

## 설치 및 실행 방법

### 0. 사전 요구사항

- Python 3.11 이상
- pip

### 1. 저장소 클론 및 의존성 설치

```bash
git clone https://github.com/your-username/phishing-detector.git
cd phishing-detector
pip install -r requirements.txt
```

### 2. 환경변수 설정

```bash
cp .env.example .env
```

`.env` 파일을 열어 API 키를 입력합니다:

```env
ANTHROPIC_API_KEY=sk-ant-api03-...   # https://console.anthropic.com
VIRUSTOTAL_API_KEY=...               # https://www.virustotal.com (무료)
```

> ⚠️ `.env` 파일은 절대 Git에 커밋하지 마세요.

### 3. DB 초기화 (최초 1회 실행)

서버를 처음 실행하기 전에 SQLite DB를 초기화합니다.
이 스크립트는 `backend/database/phishguard.db` 파일을 생성하고
탐지 규칙 데이터(키워드, 단축 URL 도메인, 개인정보 패턴)를 삽입합니다.

```bash
cd backend
python database/init_db.py
```

> **주의:** DB 파일이 이미 존재하면 덮어쓰지 않고 안내 메시지를 출력합니다.
> 재초기화가 필요한 경우 `phishguard.db` 파일을 삭제 후 다시 실행하세요.

### 4. ML 모델 학습 (최초 1회)

```bash
cd backend
python ml_training/train.py
```

출력 예시:
```
✅ 데이터셋 생성 완료: dataset/smishing_ko.csv (142건)
🏋️  모델 학습 중...
정확도: 0.9310 | AUC-ROC: 0.9714 | F1: 0.923
✅ 모델 저장 완료: ml_training/model.pkl
```

> AI Hub(aihub.or.kr)에서 "스미싱" 데이터셋을 내려받아
> `backend/ml_training/dataset/`에 넣고 `train.py`를 재실행하면 성능이 향상됩니다.

### 5. 서버 실행 (백엔드 + 프론트엔드 통합)

FastAPI 서버가 백엔드 API와 프론트엔드 정적 파일을 함께 제공합니다.
서버 시작 시 ML 모델 로드와 DB 규칙 캐싱이 자동으로 수행됩니다.

```bash
cd backend
uvicorn main:app --reload --port 8000
```

브라우저에서 http://localhost:8000 으로 접속하면 바로 PhishGuard 화면이 나타납니다.
API 문서는 http://localhost:8000/docs 에서 확인할 수 있습니다.

### 6. 외부 공개 (발표/시연용, 선택사항)

같은 네트워크가 아닌 외부에서도 접속 가능하게 하려면 ngrok을 사용합니다.

```bash
ngrok http 8000
```

발급된 `https://....ngrok-free.dev` 주소를 공유하면 누구나 접속할 수 있습니다.
첫 접속 시 ngrok 보안 경고 화면이 한 번 표시되며, `Visit Site`를 누르면 됩니다.

### 7. 시연

```bash
python samples.py   # 샘플 문자 목록 출력
```

또는 프론트엔드의 **스미싱 예시 / 정상 예시** 버튼을 클릭합니다.

---

## 시스템 설계 — 데이터베이스 설계

PhishGuard는 규칙 기반 탐지에 사용되는 키워드·도메인·패턴 데이터를
SQLite 데이터베이스(`phishguard.db`)로 관리합니다.
서버 시작 시 전체 데이터를 메모리에 캐싱하여, 요청마다 DB를 재조회하지 않습니다.

### 테이블 구조

#### urgency_keywords — 긴급성 유도 키워드

| 필드명   | 타입    | 제약                      | 설명 |
|----------|---------|---------------------------|------|
| id       | INTEGER | PRIMARY KEY AUTOINCREMENT | 기본키 (자동증가) |
| keyword  | TEXT    | NOT NULL                  | 키워드 텍스트 (예: `"긴급"`, `"계좌 정지"`) |
| category | TEXT    |                           | 분류: `urgency` / `financial_fear` / `identity_check` / `click_lure` / `reward_lure` / `agency_impersonation` / `legal_threat` |
| weight   | INTEGER | NOT NULL DEFAULT 10       | 가중치 점수 (탐지 시 rule_score에 합산) |

#### short_url_domains — 단축 URL 도메인

| 필드명 | 타입    | 제약                      | 설명 |
|--------|---------|---------------------------|------|
| id     | INTEGER | PRIMARY KEY AUTOINCREMENT | 기본키 |
| domain | TEXT    | NOT NULL UNIQUE           | 단축 URL 도메인 (예: `"bit.ly"`) |

#### personal_info_patterns — 개인정보 요구 패턴

| 필드명  | 타입    | 제약                      | 설명 |
|---------|---------|---------------------------|------|
| id      | INTEGER | PRIMARY KEY AUTOINCREMENT | 기본키 |
| pattern | TEXT    | NOT NULL                  | 정규식 패턴 문자열 (서버 로드 시 `re.compile` 적용) |
| reason  | TEXT    | NOT NULL                  | 탐지 시 표시할 사유 (예: `"카드번호 요구"`) |

### ERD

```
┌───────────────────────────┐  ┌─────────────────────────┐  ┌──────────────────────────────┐
│     urgency_keywords      │  │   short_url_domains     │  │   personal_info_patterns     │
├───────────────────────────┤  ├─────────────────────────┤  ├──────────────────────────────┤
│ id       INTEGER PK AUTO  │  │ id     INTEGER PK AUTO  │  │ id       INTEGER PK AUTO     │
│ keyword  TEXT NOT NULL    │  │ domain TEXT NOT NULL    │  │ pattern  TEXT NOT NULL       │
│ category TEXT             │  │        UNIQUE           │  │ reason   TEXT NOT NULL       │
│ weight   INTEGER NOT NULL │  └─────────────────────────┘  └──────────────────────────────┘
└───────────────────────────┘

※ 세 테이블은 독립적이며 외래키 관계 없음.
  서버 시작 시 세 테이블을 모두 메모리에 로드하여 분석 요청에 사용.
```

### 데이터 흐름

```
서버 시작
  └─► lifespan()                         (main.py)
        ├─► load_model()                 ML 모델 로드
        └─► load_rules_from_db()         (db_loader.py)
              ├─► urgency_keywords       → list[dict] 캐싱
              ├─► short_url_domains      → set[str] 캐싱
              └─► personal_info_patterns → list[(Pattern, str)] 캐싱

분석 요청 수신
  └─► analyze_rules(text)                (rule_engine.py)
        └─► get_cached_rules()           DB 재조회 없이 메모리 캐시 반환
```

---

## API 명세

### `POST /analyze`

**요청**
```json
{ "text": "[국민은행] 계좌가 정지되었습니다. 즉시 확인: http://bit.ly/abc" }
```

**응답**
```json
{
  "score": 85,
  "level": "위험",
  "rule_score": 80,
  "ml_score": 86,
  "ml_probability": 0.856,
  "llm_score": null,
  "llm_reason": null,
  "llm_used": false,
  "detected": [
    { "type": "short_url", "value": "http://bit.ly/abc", "reason": "단축 URL 사용" },
    { "type": "keyword",   "value": "즉시",              "reason": "긴급성 유도 표현" }
  ],
  "advice": "⛔ 이 문자는 스미싱으로 의심됩니다..."
}
```

**에러 코드**

| 코드 | 원인 |
|------|------|
| 422 | 빈 문자열, 1000자 초과, 공백 전용 입력 |
| 413 | 요청 크기 4,200바이트 초과 |
| 415 | Content-Type이 application/json 아님 |
| 429 | Rate Limit 초과 (분당 10회) |

---

## 테스트 실행

```bash
cd backend

python detectors/test_rule_engine.py   # 규칙 기반 탐지
python detectors/test_llm_analyzer.py  # LLM 모듈 (API 키 없이도 가능)
python api/test_analyze.py             # 통합 엔드포인트
python security/test_security.py       # 보안 미들웨어
```

전체 43개 테스트 통과 기준으로 작성되었습니다.

---

## 참고 자료

- [KISA 한국인터넷진흥원](https://www.kisa.or.kr)
- [금융보안원](https://www.fsec.or.kr)
- [VirusTotal API v3 문서](https://developers.virustotal.com/reference)
- [Anthropic Claude API 문서](https://docs.anthropic.com)
- [UN SDGs 16번 목표](https://sdgs.un.org/goals/goal16)

---

*스미싱 피해 신고: KISA 불법스팸대응센터 **118***