# Vulnerability Analysis & Automated Remediation Agent POC

This POC implements an autonomous cyber security vulnerability remediation pipeline for vulnerabilities synced from **Qualys** into **ServiceNow** (`sn_vul_m2m_vul_group_item`).

---

## 🌟 Key Features

1. **ServiceNow Ingest**:
   - Directly connects to ServiceNow REST Table API (`/api/now/table/sn_vul_m2m_vul_group_item`).
   - If live credentials are not set, it uses a local synchronized dataset matching the user's ServiceNow report screenshot.
2. **AI Risk Analysis & Prioritization**:
   - Uses **Gemini LLM** to analyze vulnerabilities, severity, CVE impact, and server environment.
   - Automatically calculates ranking and sorts the queue so **Critical (Score 95–99)** items are processed first.
3. **Simulated Server Team Approval Workflow**:
   - Identifies responsible assignment groups (e.g., `S-TCS-DC-WINTEL`) and affected servers (Configuration Items).
   - Generates automated change request notifications and provides interactive **Review & Approve** controls.
4. **Targeted Remediation Execution & Patch Simulation**:
   - **Microsoft Edge**: Silent Chromium Enterprise MSI update (`/silent /install`).
   - **Microsoft Office / Outlook**: Office Click-to-Run background security patch (e.g., CVE-2023-23397).
   - **Microsoft Windows DLL / Kernel**: Microsoft Update Catalog standalone package (`wusa.exe`).
   - **7-Zip**: Silent upgrade via MSI package to resolve Mark-of-the-Web bypass.
   - **Adobe Acrobat Reader**: Quarterly security update MSP installation (`msiexec.exe /p`).
5. **ServiceNow Status Update**:
   - Automatically marks the remediation task item state to `Closed` with audit work notes.

---

## 🚀 How to Run the POC

### 1. Start the FastAPI Server
The server is currently running on port 8000. You can also start it manually:
```bash
python main.py
```

### 2. Access the Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:8000
```

### 3. Connect Live ServiceNow (Optional)
Navigate to the **Settings** tab in the dashboard or configure `.env`:
```env
SERVICENOW_INSTANCE_URL=https://your-instance.service-now.com
SERVICENOW_USERNAME=your_username
SERVICENOW_PASSWORD=your_password
GEMINI_API_KEY=your_gemini_api_key
```
