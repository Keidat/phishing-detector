"""
test_all_samples.py
samples.py의 모든 샘플을 서버에 자동으로 테스트하는 스크립트

사용 전: uvicorn 서버가 실행 중이어야 함 (localhost:8000)
실행: python test_all_samples.py
"""

import httpx
from samples import SAMPLES

API_URL = "http://localhost:8000/analyze"

print("=" * 70)
print("PhishGuard 전체 샘플 자동 테스트")
print("=" * 70)

success_count = 0
fail_count = 0

with httpx.Client(timeout=30.0) as client:
    for s in SAMPLES:
        try:
            resp = client.post(API_URL, json={"text": s["text"]})
            data = resp.json()

            actual_level = data.get("level", "?")
            expected_level = s["expected_level"]
            is_match = actual_level == expected_level
            mark = "✅" if is_match else "❌"

            if is_match:
                success_count += 1
            else:
                fail_count += 1

            print(f"\n{mark} 샘플 {s['id']} — {s['type']} [{s['label']}]")
            print(f"   기대: {expected_level} | 실제: {actual_level} (점수: {data.get('score')})")
            print(f"   규칙: {data.get('rule_score')} | ML: {data.get('ml_score')} | "
                  f"LLM: {data.get('llm_score')} (호출됨: {data.get('llm_used')})")

        except Exception as e:
            fail_count += 1
            print(f"\n❌ 샘플 {s['id']} — 오류 발생: {e}")

print(f"\n{'=' * 70}")
print(f"결과: {success_count}개 성공 / {fail_count}개 실패 (전체 {len(SAMPLES)}개)")
print("=" * 70)