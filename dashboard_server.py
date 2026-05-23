"""
Phishing Platform Dashboard Backend
Run: python dashboard_server.py
Then open: http://localhost:8000
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import json, os, base64
from pathlib import Path
from datetime import datetime

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── paths ── point to YOUR project folder
BASE = Path(r"C:\Users\sahil\OneDrive\Desktop\phishing-platform\data")

def read_jsonl(path):
    items = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try: items.append(json.loads(line))
                    except: pass
    except FileNotFoundError:
        pass
    return items

@app.get("/api/stats")
def stats():
    scored   = read_jsonl(BASE / "scored_results.jsonl")
    suspects = read_jsonl(BASE / "suspects.jsonl")
    takedown = read_jsonl(BASE / "takedown_log.jsonl")
    crawled  = read_jsonl(BASE / "crawl_results.jsonl")

    phishing  = [s for s in scored if s.get("decision") == "PHISHING"]
    review    = [s for s in scored if s.get("decision") == "NEEDS REVIEW"]
    safe      = [s for s in scored if s.get("decision") == "PROBABLY SAFE"]
    sent      = [t for t in takedown if t.get("sent") and not t.get("dry_run")]
    cf_blocked = [s for s in scored if s.get("cf_blocked")]

    return {
        "total_suspects":   len(suspects),
        "total_crawled":    len([c for c in crawled if c.get("success")]),
        "total_scored":     len(scored),
        "phishing_count":   len(phishing),
        "review_count":     len(review),
        "safe_count":       len(safe),
        "takedowns_sent":   len(sent),
        "cf_blocked":       len(cf_blocked),
        "avg_risk_score":   round(sum(s.get("risk_score",0) for s in scored)/len(scored), 1) if scored else 0,
    }

@app.get("/api/threats")
def threats():
    scored = read_jsonl(BASE / "scored_results.jsonl")
    takedown = read_jsonl(BASE / "takedown_log.jsonl")
    sent_urls = {t["url"] for t in takedown if t.get("sent") and not t.get("dry_run")}
    result = []
    for s in scored:
        result.append({
            "url":              s.get("url",""),
            "domain":           s.get("domain",""),
            "risk_score":       s.get("risk_score", 0),
            "decision":         s.get("decision",""),
            "url_signals":      s.get("url_signals", []),
            "cf_blocked":       s.get("cf_blocked", False),
            "malware_url":      s.get("malware_url", False),
            "has_login":        s.get("has_login", False),
            "has_password":     s.get("has_password", False),
            "page_title":       s.get("page_title",""),
            "visual_note":      s.get("visual_note",""),
            "looks_like":       s.get("looks_like",""),
            "visual_similarity":s.get("visual_similarity", 0),
            "url_suspicion":    s.get("url_suspicion", 0),
            "screenshot":       s.get("screenshot",""),
            "takedown_sent":    s.get("url","") in sent_urls,
        })
    result.sort(key=lambda x: x["risk_score"], reverse=True)
    return result

@app.get("/api/takedown_log")
def takedown_log():
    items = read_jsonl(BASE / "takedown_log.jsonl")
    # deduplicate — keep latest entry per URL
    seen = {}
    for item in items:
        seen[item.get("url","")] = item
    result = list(seen.values())
    result.sort(key=lambda x: x.get("timestamp",""), reverse=True)
    return result[:50]

@app.get("/api/screenshot/{domain}")
def screenshot(domain: str):
    path = BASE / "screenshots" / f"{domain}.png"
    if path.exists():
        return FileResponse(str(path), media_type="image/png")
    return {"error": "not found"}

@app.get("/api/pipeline_status")
def pipeline_status():
    files = {
        "suspects.jsonl":        BASE / "suspects.jsonl",
        "crawl_results.jsonl":   BASE / "crawl_results.jsonl",
        "scored_results.jsonl":  BASE / "scored_results.jsonl",
        "takedown_log.jsonl":    BASE / "takedown_log.jsonl",
    }
    result = []
    for name, path in files.items():
        if path.exists():
            stat = path.stat()
            lines = sum(1 for _ in open(path, encoding="utf-8") if _.strip())
            result.append({
                "file": name,
                "exists": True,
                "records": lines,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                "size_kb": round(stat.st_size / 1024, 1),
            })
        else:
            result.append({"file": name, "exists": False, "records": 0})
    return result

@app.get("/", response_class=HTMLResponse)
def index():
    with open("dashboard.html", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*55)
    print("  Phishing Platform Dashboard")
    print("  Open: http://localhost:8000")
    print("="*55 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
