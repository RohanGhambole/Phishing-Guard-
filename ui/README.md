# Phishing UI Dashboard

## Quick Start (Development)
```bash
cd ui
pip install -r requirements.txt
streamlit run dashboard.py
```
Open http://localhost:8501

## Docker (Production)
```bash
docker-compose up ui
```
Port 8501

## Features
- Live dashboard from `data/scored_results.jsonl`
- Metrics, charts, interactive table w/ screenshot gallery
- Filter high-risk, export CSV for reviewers
- Responsive, auto-refreshes data

Run pipeline first: ingest → crawl → score → enjoy! 🕷️

