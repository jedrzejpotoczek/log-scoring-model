# Log Scoring Model

This Python script was created to analyze login logs with a focus on detecting **credential stuffing attacks**.

## Features
The script processes login records and applies multiple risk indicators, including:
- ⏰ Off-hour logins  
- 🌐 Suspicious network types  
- 🔑 IP / Email frequency anomalies  
- 🌍 Country sensitivity  
- 🛠️ Tool usage distribution  

## Outputs
The analysis produces:
- 📊 **Labeled dataset** with risk scores  
- 🚨 **Summary of malicious logins**  
- 📈 **Statistical reports**  
- 🔐 **List of compromised credentials**  

All results are exported as structured **Excel reports** for further investigation.

## Usage
1. Place your dataset as `dataset.xlsx` in the same folder.  
2. Run the script:
   ```bash
   python log_scoring_model.py
3. Generated reports:

labeled_logins.xlsx

malicious_summary.xlsx

malicious_stats.xlsx

compromised_credentials.xlsx
