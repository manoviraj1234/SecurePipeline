import sqlite3

c = sqlite3.connect("securepipeline.db")
print("TABLES", c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall())
for t in ["scans", "findings", "scanner_executions"]:
    cols = c.execute(f"PRAGMA table_info({t})").fetchall()
    print("---", t)
    for col in cols:
        print(col)
print("scan count", c.execute("select count(*) from scans").fetchone())
print("finding count", c.execute("select count(*) from findings").fetchone())
print("decisions")
for row in c.execute(
    "select id, gate_decision, security_score, total_findings from scans order by id"
):
    print(row)
try:
    print("priorities", c.execute("select priority, count(*) from findings group by priority").fetchall())
except Exception as exc:
    print("priority query failed", exc)
