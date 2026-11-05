from collections import Counter

from app.crud import backfill_risk_scores, get_findings
from app.database import SessionLocal, init_db
from app.regression import calculate_scan_regression

init_db()
db = SessionLocal()
try:
    updated = backfill_risk_scores(db)
    print("backfilled", updated)
    findings, total = get_findings(db, skip=0, limit=5)
    print("findings_total", total)
    counts = Counter(f.priority for f in db.query(__import__("app.models", fromlist=["Finding"]).Finding).all())
    print("priority_counts", dict(counts))
    print("top", [(f.finding_id, f.priority, f.risk_score) for f in findings])
    for scan_id in (5, 6, 7):
        result = calculate_scan_regression(db, scan_id)
        print(
            "regression",
            scan_id,
            result.get("status"),
            "new",
            result.get("new_count"),
            "fixed",
            result.get("fixed_count"),
            "delta",
            result.get("score_delta"),
        )
finally:
    db.close()
