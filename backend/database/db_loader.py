"""
db_loader.py
PhishGuard DB 로드 및 캐싱 모듈

역할:
  - 서버 시작 시 한 번만 DB에서 규칙 데이터를 읽어 메모리에 캐싱
  - 이후 요청마다 캐시된 자료구조를 반환 (DB 재조회 없음)
  - DB 연결 실패 시 빈 자료구조로 graceful degradation
    (서비스 전체가 죽지 않고 최소한 동작 유지)

반환 자료구조:
  urgency_keywords       → list[dict]   예: [{"keyword": "긴급", "weight": 10}, ...]
  short_url_domains      → set[str]     예: {"bit.ly", "tinyurl.com", ...}
  personal_info_patterns → list[tuple]  예: [(re.Pattern, "사유"), ...]
"""

import sqlite3
import re
import os
from typing import TypedDict

# ── DB 파일 경로 ──────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "phishguard.db")


# ─────────────────────────────────────────────
# 타입 정의
# ─────────────────────────────────────────────

class RulesCache(TypedDict):
    urgency_keywords:       list   # [{"keyword": str, "category": str, "weight": int}, ...]
    short_url_domains:      set    # {str, ...}
    personal_info_patterns: list   # [(re.Pattern, str), ...]


# ─────────────────────────────────────────────
# 모듈 레벨 캐시 (서버 프로세스 수명 동안 유지)
# ─────────────────────────────────────────────
_cache: RulesCache | None = None


def _empty_cache() -> RulesCache:
    """DB 연결 실패 시 반환할 빈 캐시 자료구조"""
    return {
        "urgency_keywords":       [],
        "short_url_domains":      set(),
        "personal_info_patterns": [],
    }


# ─────────────────────────────────────────────
# DB 로드 함수
# ─────────────────────────────────────────────

def load_rules_from_db() -> RulesCache:
    """
    phishguard.db에서 규칙 데이터를 읽어 Python 자료구조로 반환한다.
    최초 호출 시 DB를 읽어 모듈 전역 캐시에 저장하고,
    이후 호출부터는 캐시된 데이터를 즉시 반환한다.

    Returns:
        RulesCache: 3종 규칙 데이터를 담은 딕셔너리

    Note:
        예외를 밖으로 전파하지 않음 — DB 오류 시 빈 캐시로 대체
    """
    global _cache

    # ── 캐시 히트: 이미 로드된 경우 즉시 반환 ──
    if _cache is not None:
        return _cache

    # ── DB 파일 존재 여부 사전 확인 ────────────
    if not os.path.exists(DB_PATH):
        print(
            f"[DB Loader] 경고: DB 파일을 찾을 수 없습니다 ({DB_PATH}). "
            "init_db.py를 먼저 실행해 DB를 초기화하세요. "
            "빈 규칙으로 서비스를 시작합니다."
        )
        _cache = _empty_cache()
        return _cache

    # ── DB 연결 및 데이터 로드 ─────────────────
    conn = None
    try:
        # check_same_thread=False: FastAPI의 비동기 환경에서 멀티스레드 접근 허용
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row  # 컬럼명으로 접근 가능하게
        cursor = conn.cursor()

        # 1) urgency_keywords 로드 → list of dict
        cursor.execute("SELECT keyword, category, weight FROM urgency_keywords")
        urgency_keywords = [
            {
                "keyword":  row["keyword"],
                "category": row["category"],
                "weight":   row["weight"],
            }
            for row in cursor.fetchall()
        ]

        # 2) short_url_domains 로드 → set of str
        cursor.execute("SELECT domain FROM short_url_domains")
        short_url_domains = {row["domain"] for row in cursor.fetchall()}

        # 3) personal_info_patterns 로드 → list of (compiled re.Pattern, reason)
        #    패턴 문자열을 re.compile로 컴파일하여 저장
        #    원본 rule_engine.py의 password 패턴에 IGNORECASE가 붙어 있었으므로
        #    일관성을 위해 전체에 IGNORECASE 적용 (한국어 패턴에는 영향 없음)
        cursor.execute("SELECT pattern, reason FROM personal_info_patterns")
        personal_info_patterns = []
        for row in cursor.fetchall():
            try:
                compiled = re.compile(row["pattern"], re.IGNORECASE)
                personal_info_patterns.append((compiled, row["reason"]))
            except re.error as e:
                # 잘못된 정규식 패턴은 건너뜀 (서비스 중단 방지)
                print(f"[DB Loader] 경고: 잘못된 정규식 패턴 무시 — '{row['pattern']}': {e}")

        # ── 캐시에 저장 ────────────────────────
        _cache = {
            "urgency_keywords":       urgency_keywords,
            "short_url_domains":      short_url_domains,
            "personal_info_patterns": personal_info_patterns,
        }

        print(
            f"[DB Loader] 규칙 데이터 로드 완료 — "
            f"키워드 {len(urgency_keywords)}개 / "
            f"단축도메인 {len(short_url_domains)}개 / "
            f"패턴 {len(personal_info_patterns)}개"
        )
        return _cache

    except sqlite3.Error as e:
        print(
            f"[DB Loader] DB 연결 또는 조회 실패: {e}. "
            "빈 규칙으로 서비스를 시작합니다."
        )
        _cache = _empty_cache()
        return _cache

    finally:
        if conn:
            conn.close()


def get_cached_rules() -> RulesCache:
    """
    이미 로드된 캐시를 반환한다.
    load_rules_from_db()가 먼저 호출되지 않았으면 그것을 호출해 반환한다.
    analyze_rules() 같은 요청 핸들러에서 매 요청마다 호출해도 안전하다.
    """
    if _cache is None:
        return load_rules_from_db()
    return _cache