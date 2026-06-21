"""
init_db.py
PhishGuard SQLite 데이터베이스 초기화 스크립트

실행 방법:
    python backend/database/init_db.py

동작:
  - phishguard.db 파일 생성
  - 3개 테이블 생성 (urgency_keywords, short_url_domains, personal_info_patterns)
  - 기존 rule_engine.py의 하드코딩 데이터를 시드 데이터로 삽입
  - DB 파일이 이미 존재하면 덮어쓰지 않고 안내 메시지 출력 후 종료
"""

import sqlite3
import os
import sys

# ── DB 파일 경로 설정 ──────────────────────────────────────────────
# 이 스크립트 위치(backend/database/)를 기준으로 동일 디렉터리에 생성
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "phishguard.db")


# ─────────────────────────────────────────────
# 시드 데이터 정의
# (기존 rule_engine.py 하드코딩 값을 그대로 이전)
# ─────────────────────────────────────────────

# urgency_keywords 시드 데이터: (keyword, category, weight)
SEED_URGENCY_KEYWORDS = [
    # 즉각 행동 유도
    ("즉시",            "urgency",               10),
    ("지금 바로",       "urgency",               10),
    ("빨리",            "urgency",               10),
    ("당장",            "urgency",               10),
    ("긴급",            "urgency",               10),
    # 계좌/금융 관련 공포 자극
    ("계좌 정지",       "financial_fear",        10),
    ("계좌정지",        "financial_fear",        10),
    ("출금 정지",       "financial_fear",        10),
    ("카드 정지",       "financial_fear",        10),
    ("이용 정지",       "financial_fear",        10),
    ("거래 중단",       "financial_fear",        10),
    ("대출 승인",       "financial_fear",        10),
    ("대출승인",        "financial_fear",        10),
    ("정지되었습니다",  "financial_fear",        10),
    ("제한되었습니다",  "financial_fear",        10),
    ("동결되었습니다",  "financial_fear",        10),
    ("정책에 의해",     "financial_fear",        10),
    ("이용 제한",       "financial_fear",        10),
    ("서비스 중단",     "financial_fear",        10),
    # 본인 확인 사칭
    ("본인 확인",       "identity_check",        10),
    ("본인확인",        "identity_check",        10),
    ("인증 필요",       "identity_check",        10),
    ("인증번호",        "identity_check",        10),
    ("ARS 인증",        "identity_check",        10),
    # 클릭/접속 유도
    ("클릭",            "click_lure",            10),
    ("접속 요망",       "click_lure",            10),
    ("지금 확인",       "click_lure",            10),
    ("바로 확인",       "click_lure",            10),
    ("즉각 확인",       "click_lure",            10),
    # 수령/당첨 미끼
    ("수령하세요",      "reward_lure",           10),
    ("당첨되었습니다",  "reward_lure",           10),
    ("지급 예정",       "reward_lure",           10),
    ("환급금",          "reward_lure",           10),
    ("미수령",          "reward_lure",           10),
    ("택배 미수령",     "reward_lure",           10),
    ("반송 예정",       "reward_lure",           10),
    # 기관 사칭
    ("건강보험",        "agency_impersonation",  10),
    ("국세청",          "agency_impersonation",  10),
    ("경찰청",          "agency_impersonation",  10),
    ("검찰청",          "agency_impersonation",  10),
    ("금융감독원",      "agency_impersonation",  10),
    ("우체국",          "agency_impersonation",  10),
    ("카카오페이",      "agency_impersonation",  10),
    ("네이버페이",      "agency_impersonation",  10),
    # 법적 위협
    ("법적 조치",       "legal_threat",          10),
    ("고소",            "legal_threat",          10),
    ("벌금",            "legal_threat",          10),
    ("과태료",          "legal_threat",          10),
]

# short_url_domains 시드 데이터: (domain,)
SEED_SHORT_URL_DOMAINS = [
    ("bit.ly",),
    ("tinyurl.com",),
    ("t.co",),
    ("goo.gl",),
    ("ow.ly",),
    ("is.gd",),
    ("buff.ly",),
    ("adf.ly",),
    ("tiny.cc",),
    ("lnkd.in",),
    ("db.tt",),
    ("qr.ae",),
    ("po.st",),
    ("bc.vc",),
    ("s.id",),
    ("cutt.ly",),
    ("rebrand.ly",),
    ("short.io",),
    ("han.gl",),
    ("me2.do",),
]

# personal_info_patterns 시드 데이터: (pattern, reason)
# 정규식 패턴을 문자열 그대로 저장 (로드 시 re.compile 적용)
SEED_PERSONAL_INFO_PATTERNS = [
    (r'주민\s*등록\s*번호|주민번호|생년월일',  "주민등록번호 요구"),
    (r'카드\s*번호|신용카드|체크카드\s*번호',  "카드번호 요구"),
    (r'비밀\s*번호|패스워드|password',         "비밀번호 요구"),
    (r'계좌\s*번호|통장\s*번호',               "계좌번호 요구"),
    (r'공인인증서|금융\s*인증서|OTP',          "금융 인증 정보 요구"),
    (r'CVC|CVV|카드\s*뒷\s*3자리',            "카드 보안코드 요구"),
]


# ─────────────────────────────────────────────
# DDL: 테이블 생성 SQL
# ─────────────────────────────────────────────

SQL_CREATE_URGENCY_KEYWORDS = """
CREATE TABLE IF NOT EXISTS urgency_keywords (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,  -- 기본키 (자동증가)
    keyword  TEXT    NOT NULL,                   -- 키워드 텍스트
    category TEXT,                               -- 분류 카테고리
    weight   INTEGER NOT NULL DEFAULT 10         -- 가중치 점수
);
"""

SQL_CREATE_SHORT_URL_DOMAINS = """
CREATE TABLE IF NOT EXISTS short_url_domains (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,  -- 기본키
    domain TEXT    NOT NULL UNIQUE             -- 단축 URL 도메인 (중복 불허)
);
"""

SQL_CREATE_PERSONAL_INFO_PATTERNS = """
CREATE TABLE IF NOT EXISTS personal_info_patterns (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,  -- 기본키
    pattern TEXT    NOT NULL,                   -- 정규식 패턴 문자열
    reason  TEXT    NOT NULL                    -- 탐지 시 표시할 사유 설명
);
"""


# ─────────────────────────────────────────────
# 메인 초기화 함수
# ─────────────────────────────────────────────

def init_db() -> None:
    """
    DB 파일을 생성하고 테이블과 시드 데이터를 삽입한다.
    DB 파일이 이미 존재하면 작업을 중단하고 안내 메시지를 출력한다.
    """
    # ── DB 파일 존재 여부 확인 ─────────────────
    if os.path.exists(DB_PATH):
        print(f"[PhishGuard DB] 이미 DB 파일이 존재합니다: {DB_PATH}")
        print("[PhishGuard DB] 초기화를 건너뜁니다. 재생성이 필요하면 파일을 삭제 후 다시 실행하세요.")
        sys.exit(0)

    print(f"[PhishGuard DB] DB 파일 생성 중: {DB_PATH}")

    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # ── 테이블 생성 ────────────────────────
        print("[PhishGuard DB] 테이블 생성 중...")
        cursor.execute(SQL_CREATE_URGENCY_KEYWORDS)
        cursor.execute(SQL_CREATE_SHORT_URL_DOMAINS)
        cursor.execute(SQL_CREATE_PERSONAL_INFO_PATTERNS)

        # ── 시드 데이터 삽입 ───────────────────
        print("[PhishGuard DB] 시드 데이터 삽입 중...")

        cursor.executemany(
            "INSERT INTO urgency_keywords (keyword, category, weight) VALUES (?, ?, ?)",
            SEED_URGENCY_KEYWORDS,
        )
        cursor.executemany(
            "INSERT INTO short_url_domains (domain) VALUES (?)",
            SEED_SHORT_URL_DOMAINS,
        )
        cursor.executemany(
            "INSERT INTO personal_info_patterns (pattern, reason) VALUES (?, ?)",
            SEED_PERSONAL_INFO_PATTERNS,
        )

        conn.commit()
        print("[PhishGuard DB] 초기화 완료!")
        print(f"  - urgency_keywords      : {len(SEED_URGENCY_KEYWORDS)}개")
        print(f"  - short_url_domains     : {len(SEED_SHORT_URL_DOMAINS)}개")
        print(f"  - personal_info_patterns: {len(SEED_PERSONAL_INFO_PATTERNS)}개")

    except sqlite3.Error as e:
        print(f"[PhishGuard DB] DB 초기화 실패: {e}")
        # 실패 시 불완전한 DB 파일 제거
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
            print("[PhishGuard DB] 불완전한 DB 파일을 삭제했습니다.")
        sys.exit(1)

    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    init_db()