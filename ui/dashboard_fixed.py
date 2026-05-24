import streamlit as st
import pandas as pd
import json
import os
from PIL import Image
import plotly.express as px
import matplotlib.pyplot as plt
from wordcloud import WordCloud
from datetime import datetime

# Page config
st.set_page_config(page_title="Phishing Dashboard 🕷️", layout="wide")

# Fixed paths from ui/ dir
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
SCREENSHOTS_DIR = os.path.join(DATA_DIR, "screenshots")

@st.cache_data
def load_data():
    data_file = os.path.join(DATA_DIR, "scored_results.jsonl")
    if not os.path.exists(data_file):
        st.error("❌ Run scoring: services/classifier/scorer.py")
        st.stop()
    
    records = []
    with open(data_file, 'r') as f:
        for line in f:
            records.append(json.loads(line.strip()))
    
    df = pd.DataFrame(records)
    df['risk_score'] = pd.to_numeric(df['risk_score'], errors='coerce').fillna(0)
    df['phishing'] = df['decision'] == 'PHISHING'
    df['cf_blocked'] = df['cf_blocked'].astype(bool)
    df['screenshot_rel'] = df['screenshot'].str.replace(r'^.*phishing-platform\\\\', '', regex=True).str.replace(r'^.*phishing-platform/', '', regex=True)
    return df

def get_screenshot_img(rel_path):
    full_path = os.path.join(SCREENSHOTS_DIR, rel_path)
    if os.path.exists(full_path):
        return Image.open(full_path)
    return Image.new('RGB', (100, 100), color='gray')

st.title("🕷️ Phishing Detection Dashboard")

df = load_data()

# Metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Sites", len(df))
col2.metric("Phishing", df['phishing'].sum(), f"{df['phishing'].mean():.1%}")
col3.metric("Avg Score", f"{df['risk_score'].mean():.1f}/100")
col4.metric("Cloudflare Blocks", df['cf_blocked'].sum())

# Sidebar
st.sidebar.header("Filters")
score_filter = st.sidebar.slider("Min Score", 0, 100, 0)
df_filtered = df[df['risk_score'] >= score_filter]

# Charts
col1, col2 = st.columns(2)
with col1:
    fig = px.histogram(df_filtered, x='risk_score', title="Risk Distribution", nbins=20)
    st.plotly_chart(fig, use_container_width=True)
with col2:
    fig = px.pie(df_filtered, names='decision', title="Decisions")
    st.plotly_chart(fig, use_container_width=True)

# Table
st.subheader(f"📊 {len(df_filtered)} Sites")
st.dataframe(
    df_filtered[['domain', 'risk_score', 'decision', 'url_signals', 'screenshot_rel']],
    column_config={
        'risk_score': st.column_config.ProgressColumn("Score", format="%.0f%%"),
        'screenshot_rel': st.column_config.ImageColumn("Screenshot", width="small")
    },
    use_container_width=True
)

# Gallery
high_risk = df_filtered[df_filtered['risk_score'] >= 30]
if not high_risk.empty:
    st.subheader("🖼️ High Risk Gallery")
    for _, row in high_risk.head(9).iterrows():
        img = get_screenshot_img(row['screenshot_rel'])
        st.image(img, caption=row['domain'] + f" (Score: {row['risk_score']})", width=200)

# Export
csv = df_filtered.to_csv(index=False).encode('utf-8')
st.download_button("📥 Export CSV", csv, "phishing_sites.csv")

st.success("✅ Dashboard ready! Refresh after new scoring.")
