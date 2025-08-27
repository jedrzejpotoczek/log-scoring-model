# logs scoring model

import pandas as pd
import numpy as np
from datetime import datetime
import pytz

# 📁 Load Excel file
df = pd.read_excel("dataset.xlsx")

# 🧼 Step 1: Parse datetime
df['datetime'] = pd.to_datetime(df['epoch'], unit='ms', errors='coerce')
df['hour_utc'] = df['datetime'].dt.hour

# 🌍 Country to Timezone Mapping (only single-timezone countries + sensitive)
country_timezones = {
    'PL': 'Europe/Warsaw',
    'DE': 'Europe/Berlin',
    'FR': 'Europe/Paris',
    'NL': 'Europe/Amsterdam',
    'IT': 'Europe/Rome',
    'ES': 'Europe/Madrid',
    'UA': 'Europe/Kyiv',
    'GR': 'Europe/Athens',
    'PT': 'Europe/Lisbon',
    'RO': 'Europe/Bucharest',
    'HU': 'Europe/Budapest',
    'NO': 'Europe/Oslo',
    'SE': 'Europe/Stockholm',
    'FI': 'Europe/Helsinki',
    'DK': 'Europe/Copenhagen',
    'JP': 'Asia/Tokyo',
    'KR': 'Asia/Seoul',
    'SG': 'Asia/Singapore',
    'IL': 'Asia/Jerusalem',
    'NZ': 'Pacific/Auckland',
    'AE': 'Asia/Dubai',
    'EG': 'Africa/Cairo',
    'NG': 'Africa/Lagos',
    'TZ': 'Africa/Dar_es_Salaam',
    'KE': 'Africa/Nairobi',
    'GH': 'Africa/Accra',
    'SC': 'Indian/Mahe',         # Seychelles
    'ER': 'Africa/Asmara',       # Sensitive
    'KP': 'Asia/Pyongyang',      # Sensitive
    'TV': 'Pacific/Funafuti',    # Sensitive
    'UM': 'Pacific/Wake',        # US Minor Outlying Islands
}

# ⏰ Calculate local hour where possible
def get_local_hour(row):
    country = row['country']
    utc_time = row['datetime']
    if pd.isna(utc_time) or country not in country_timezones:
        return np.nan
    try:
        tz = pytz.timezone(country_timezones[country])
        return utc_time.tz_localize('UTC').astimezone(tz).hour
    except:
        return np.nan

df['local_hour'] = df.apply(get_local_hour, axis=1)

# 📊 Step 2: Risk Indicator - Off-Hour Login (based on LOCAL time)
def off_hour_score(hour):
    if pd.isna(hour):
        return 0
    if 2 <= hour < 5:
        return 3
    elif hour in [0, 1, 5]:
        return 2
    elif hour in [23, 6]:
        return 1
    return 0
df['risk_offhour'] = df['local_hour'].apply(off_hour_score)

# 🌐 Step 3: Risk Indicator - Network Type
def network_score(network):
    if pd.isna(network):
        return 2
    net = str(network).strip().lower()
    if net in ['hosted', 'reserved']:
        return 3
    elif net in ['mobile', '']:
        return 2
    return 1
df['risk_network'] = df['network_type'].apply(network_score)

# 📌 Step 4: Risk by IP Frequency
ip_counts = df['hashed_ip'].value_counts()
df['ip_login_count'] = df['hashed_ip'].map(ip_counts)
df['risk_ip'] = pd.cut(df['ip_login_count'], bins=[0, 6, 8, 10, float('inf')], labels=[0, 1, 2, 3]).astype(int)

# 📌 Step 5: Risk by Email Frequency
email_counts = df['email_hash'].value_counts()
df['email_login_count'] = df['email_hash'].map(email_counts)
df['risk_email'] = pd.cut(df['email_login_count'], bins=[0, 3, 5, 7, float('inf')], labels=[0, 1, 2, 3]).astype(int)

# 🔧 Step 6: Tool Popularity
tool_counts = df['tool_id'].value_counts(normalize=True)
df['tool_freq'] = df['tool_id'].map(tool_counts)
df['risk_tool'] = pd.cut(df['tool_freq'], bins=[0, 0.0001, 0.001, 1], labels=[3, 2, 0]).astype(int)

# 🛡️ Step 7: Risk Indication Field
df['risk_flag'] = df['risk_indication'].apply(lambda x: 3 if x is True else 0)

# ✔️ Step 8: Status Code Logic
df['risk_status_bonus'] = np.where(
    (df['status_code'] == 200) & (
        df['risk_flag'] +
        df['risk_offhour'] +
        df['risk_network'] +
        df['risk_ip'] +
        df['risk_email'] +
        df['risk_tool']
    ) >= 6, 2, 0
)

# 🌍 Step 9: Risk by Country (sensitive or blank/reserved)
high_risk_countries = ['SC', 'ZZ', 'AN', 'AQ', 'UM', 'TV', 'ER', 'KP']
df['risk_country'] = df['country'].apply(
    lambda c: 3 if pd.isna(c) or c in high_risk_countries or str(c).lower() in ['reserved', 'blank', ''] else 1
)

# 🧮 Final Risk Score
df['final_risk_score'] = (
    df['risk_offhour'] +
    df['risk_network'] +
    df['risk_ip'] +
    df['risk_email'] +
    df['risk_tool'] +
    df['risk_flag'] +
    df['risk_status_bonus'] +
    df['risk_country']
)

# 🏷️ Label: Malicious if score ≥ 8
df['label'] = np.where(df['final_risk_score'] >= 8, 'malicious', 'benign')

# 🧾 Reorder to make final_risk_score the last column
cols = [col for col in df.columns if col != 'final_risk_score'] + ['final_risk_score']
df = df[cols]

# 💾 Save outputs to Excel
with pd.ExcelWriter("labeled_logins.xlsx", engine='xlsxwriter') as writer:
    df.to_excel(writer, index=False)

# 📋 Save malicious-only summary
summary_cols = [
    'email_hash', 'datetime', 'country', 'network_type',
    'tool_id', 'status_code', 'risk_indication',
    'final_risk_score', 'label'
]
with pd.ExcelWriter("malicious_summary.xlsx", engine='xlsxwriter') as writer:
    df[df['label'] == 'malicious'][summary_cols].to_excel(writer, index=False)

# 📊 Save stats summary
malicious_df = df[df['label'] == 'malicious']
stats = {
    'total_logins': len(df),
    'total_malicious': len(malicious_df),
    'malicious_percentage': round(100 * len(malicious_df) / len(df), 2),
    'unique_compromised_credentials': malicious_df['email_hash'].nunique(),
    'top_5_countries': ', '.join(malicious_df['country'].value_counts().head(5).index),
    'top_5_tools': ', '.join(malicious_df['tool_id'].value_counts().head(5).index.astype(str)),
    'average_risk_score_malicious': malicious_df['final_risk_score'].mean(),
    'min_risk_score_malicious': malicious_df['final_risk_score'].min(),
    'max_risk_score_malicious': malicious_df['final_risk_score'].max()
}
pd.DataFrame([stats]).to_excel("malicious_stats.xlsx", index=False)

# 🔐 Save compromised credentials (malicious + status 200)
compromised_emails = df[(df['label'] == 'malicious') & (df['status_code'] == 200)]['email_hash'].unique()
pd.Series(compromised_emails).to_frame(name='compromised_email_hash').to_excel("compromised_credentials.xlsx", index=False)

print("✅ All Excel files saved:")
print("• labeled_logins.xlsx")
print("• malicious_summary.xlsx")
print("• malicious_stats.xlsx")
print("• compromised_credentials.xlsx")