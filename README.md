# log-scoring-model

This Python script was created for the purpose of analyzing login logs, with a focus on detecting patterns related to credential stuffing attacks.

It processes login records, applies multiple risk indicators (such as off-hour logins, suspicious networks, IP/email frequency, country sensitivity, and tool usage), and produces:

A labeled dataset with risk scores

Summaries of malicious logins

Statistical reports

A list of compromised credentials

The output is saved as structured Excel reports for further investigation.
