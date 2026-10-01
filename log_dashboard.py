import pandas as pd
import streamlit as st
import plotly.express as px
import re

# PAGE CONFIG

st.set_page_config(
    page_title="Security Log Dashboard",
    layout="wide"
)

st.title("Security Log Analysis Dashboard")

# FILE UPLOAD

uploaded_file = st.file_uploader(
    "Upload Log File",
    type=["txt", "log"]
)

data = []

if uploaded_file is not None:

    lines = uploaded_file.getvalue().decode().splitlines()

else:

    with open("sample_log2.txt", "r") as file:
        lines = file.readlines()

# PARSE LOGS

for line in lines:

    line = line.strip()

    if not line:
        continue

    parts = line.split()

    if len(parts) < 4:
        continue

    data.append({
        "Date": parts[0],
        "Time": parts[1],
        "Level": parts[2],
        "Message": " ".join(parts[3:])
    })

df = pd.DataFrame(data)

df["Timestamp"] = pd.to_datetime(
    df["Date"] + " " + df["Time"]
)

# IP ADDRESS EXTRACTION

ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"

df["IP"] = df["Message"].str.extract(
    f"({ip_pattern})"
)

ip_events = df.dropna(subset=["IP"])

top_ips = ip_events["IP"].value_counts().head(10)

# METRICS

info_count = len(df[df["Level"] == "INFO"])
warning_count = len(df[df["Level"] == "WARNING"])
error_count = len(df[df["Level"] == "ERROR"])

col1, col2, col3 = st.columns(3)

col1.metric("INFO", info_count)
col2.metric("WARNING", warning_count)
col3.metric("ERROR", error_count)

# THREAT DETECTION

critical_keywords = [
    "attack",
    "breach",
    "malware",
    "unauthorized",
    "compromise"
]

critical_events = df[
    df["Message"].str.contains(
        "|".join(critical_keywords),
        case=False,
        na=False
    )
]

if len(critical_events) > 0:
    st.error(
        f"Critical Security Events Detected: {len(critical_events)}"
    )

st.header("Threat Detection")

failed_logins = df[
    df["Message"].str.contains(
        "Failed login",
        case=False,
        na=False
    )
]

lockouts = df[
    df["Message"].str.contains(
        "locked",
        case=False,
        na=False
    )
]

high_errors = df[
    df["Level"] == "ERROR"
]

if len(failed_logins) >= 5:

    st.error(
        f"Security Alert: {len(failed_logins)} failed login attempts detected."
    )

if len(lockouts) > 0:

    st.warning(
        f"Account Lockouts Detected: {len(lockouts)}"
    )

if len(high_errors) >= 2:

    st.warning(
        f"High Error Volume Detected: {len(high_errors)} errors found."
    )

# FILTERS

st.header("Log Filters")

level_filter = st.selectbox(
    "Log Level",
    ["ALL", "INFO", "WARNING", "ERROR"]
)

search_term = st.text_input(
    "Search Messages"
)

filtered_df = df.copy()

if level_filter != "ALL":

    filtered_df = filtered_df[
        filtered_df["Level"] == level_filter
    ]

if search_term:

    filtered_df = filtered_df[
        filtered_df["Message"].str.contains(
            search_term,
            case=False,
            na=False
        )
    ]

# CHART

st.header("Log Event Distribution")

counts = df["Level"].value_counts()

fig = px.bar(
    x=counts.index,
    y=counts.values,
    color=counts.index,
    title="Security Events by Type",
    labels={
        "x": "Event Type",
        "y": "Count"
    }
)

st.plotly_chart(
    fig,
    use_container_width=True
)

pie_fig = px.pie(
    values=counts.values,
    names=counts.index,
    title="Security Event Breakdown"
)

st.plotly_chart(
    pie_fig,
    use_container_width=True
)

timeline_fig = px.line(
    df,
    x="Timestamp",
    y=df.index,
    title="Security Event Timeline"
)

st.plotly_chart(
    timeline_fig,
    use_container_width=True
)

# IP ANALYSIS

st.header("IP Address Analysis")

if len(ip_events) > 0:

    st.subheader("Top Source IP Addresses")

    st.dataframe(
        top_ips.reset_index().rename(
            columns={
                "index": "IP Address",
                "IP": "Event Count"
            }
        ),
        use_container_width=True
    )

    ip_chart = px.bar(
        x=top_ips.index,
        y=top_ips.values,
        title="Top Source IP Addresses",
        labels={
            "x": "IP Address",
            "y": "Number of Events"
        }
    )

    st.plotly_chart(
        ip_chart,
        use_container_width=True
    )

    most_active_ip = top_ips.index[0]

    st.metric(
        "Most Active IP",
        most_active_ip
    )

else:

    st.info(
        "No IP addresses detected in current log data."
    )

# LOG TABLE

st.header("Log Events")

st.dataframe(
    filtered_df,
    use_container_width=True
)

# DOWNLOAD REPORT

csv = filtered_df.to_csv(index=False)

st.download_button(
    label="Download CSV Report",
    data=csv,
    file_name="security_report.csv",
    mime="text/csv"
)

# THREAT SCORE

threat_score = (
    len(failed_logins) * 5 +
    len(lockouts) * 10 +
    len(high_errors) * 2
)

st.header("Threat Score")

st.metric(
    "Current Risk Score",
    threat_score
)

if threat_score >= 150:
    threat_level = "CRITICAL"

elif threat_score >= 100:
    threat_level = "HIGH"

elif threat_score >= 50:
    threat_level = "MEDIUM"

else:
    threat_level = "LOW"

st.metric(
    "Threat Level",
    threat_level
)

# DASHBOARD SUMMARY

st.header("Dashboard Summary")

st.subheader("Security Statistics")

st.write(f"Total Events Analyzed: {len(df)}")
st.write(f"Failed Login Attempts: {len(failed_logins)}")
st.write(f"Account Lockout Events: {len(lockouts)}")
st.write(f"Error Events: {len(high_errors)}")