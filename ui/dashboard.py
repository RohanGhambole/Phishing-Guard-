import streamlit as st
import pandas as pd
import json
import os
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image
import matplotlib.pyplot as plt
import seaborn as sns
from wordcloud import WordCloud
from datetime import datetime
import base64

# Page config
st.set_page_config(
    page_title="Phishing Platform Dashboard",
    page_icon="🕷️",
    layout="wide",
    initial_sidebar_state="expanded"
)


def load_data():

    data_file = "data/scored_results.jsonl"
    if not os.path.exists(data_file):
        st.error(f"❌ {data_file} not found. Run scoring first!")
        st.stop()
    
    records = []
    with open(data_file, 'r') as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line.strip()))
    
    df = pd.DataFrame(records)
    
    # Process data
    df['risk_score'] = pd.to_numeric(df['risk_score'], errors='coerce').fillna(0)
    df['phishing'] = df['decision'] == 'PHISHING'
    df['cf_blocked'] = df['cf_blocked'].astype(bool)
    df['visited_at'] = pd.to_datetime(df.get('visited_at', datetime.now()), errors='coerce')
    
    # Screenshot paths (make relative for display)
    df['screenshot_rel'] = df['screenshot'].str.replace(r'^C:\\Users\\sahil\\Desktop\\phishing-platform\\', '', regex=True)
    
    return df



def main():
    st.title("🕷️ Phishing Detection Dashboard")
    st.markdown("---")
    
    df = load_data()
    total_sites = len(df)
    phishing_count = df['phishing'].sum()
    avg_score = df['risk_score'].mean()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Sites", total_sites)
    with col2:
        st.metric("Phishing Detected", phishing_count, f"{phishing_count/total_sites*100:.1f}%")
    with col3:
        st.metric("Avg Risk Score", f"{avg_score:.1f}/100")
    with col4:
        st.metric("CF Blocked", df['cf_blocked'].sum())
    
    st.markdown("---")
    
    # Sidebar filters
    st.sidebar.header("🔍 Filters")
    min_score = st.sidebar.slider("Min Risk Score", 0, 100, 20)
    show_phishing = st.sidebar.checkbox("High Risk Only", True)
    
    filtered_df = df[df['risk_score'] >= min_score].copy()
    if show_phishing:
        filtered_df = filtered_df[filtered_df['phishing']]
    
    # Charts row 1
    col1, col2 = st.columns(2)
    with col1:
        # Risk score histogram
        fig_hist = px.histogram(filtered_df, x='risk_score', nbins=20, 
                               title="Risk Score Distribution",
                               labels={'risk_score': 'Risk Score'})
        st.plotly_chart(fig_hist, use_container_width=True)
    
    with col2:
        # Decision pie
        decision_counts = filtered_df['decision'].value_counts()
        fig_pie = px.pie(values=decision_counts.values, names=decision_counts.index,
                        title="Detection Decisions")
        st.plotly_chart(fig_pie, use_container_width=True)
    
    # Charts row 2
    col1, col2 = st.columns(2)
    with col1:
        # Top signals
        all_signals = []
        for signals in filtered_df['url_signals']:
            if signals:
                all_signals.extend(signals)
        signal_df = pd.Series(all_signals).value_counts().head(10)
        fig_bar = px.bar(x=signal_df.index, y=signal_df.values,
                        title="Top Phishing Signals")
        st.plotly_chart(fig_bar, use_container_width=True)
    
    with col2:
        # Wordcloud for signals
        if all_signals:
            wc = WordCloud(width=400, height=300, background_color='white').generate(' '.join(all_signals))
            fig, ax = plt.subplots()
            ax.imshow(wc, interpolation='bilinear')
            ax.axis('off')
            st.pyplot(fig)
    
    st.markdown("---")
    
    # Main table
    st.subheader(f"📊 Sites ({len(filtered_df)} filtered)")
    
    # Add screenshot column
    def screenshot_cell(row):
        img = display_screenshot(row['screenshot_rel'])
        if img:
            return img
        return "❌ No screenshot"
    
    st.dataframe(
        filtered_df[[
            'url', 'domain', 'risk_score', 'decision', 'url_signals', 
            'page_title', 'cf_blocked', 'screenshot_rel'
        ]].rename(columns={'screenshot_rel': 'Screenshot'}),
        use_container_width=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn("Risk Score", width="medium", format="%.1f%%"),
            "decision": st.column_config.SelectboxColumn("Decision", options=df['decision'].unique()),
            "url_signals": st.column_config.ListColumn("Signals"),
            "Screenshot": st.column_config.ImageColumn("Screenshot", width="small")
        },
        hide_index=True
    )
    
    # Gallery for high risk
    high_risk = filtered_df[filtered_df['risk_score'] >= 30]
    if not high_risk.empty:
        st.subheader("🖼️ High-Risk Screenshots Gallery")
        cols = st.columns(3)
        for idx, row in high_risk.iterrows():
            with cols[idx % 3]:
                img = display_screenshot(row['screenshot_rel'])
                if img:
                    st.image(img, caption=f"{row['domain']} (Score: {row['risk_score']})", use_column_width=True)
    
    # Download
    csv = filtered_df.to_csv(index=False).encode('utf-8')
    st.download_button("💾 Download Filtered CSV", csv, "phishing_report.csv", "text/csv")

if __name__ == "__main__":
    main()

