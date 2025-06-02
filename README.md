# 🛠️ GWS Enumeration Tool

A Python-based tool to enumerate Google Workspace data using OAuth2 authorization. It collects data from Google Drive, Gmail, Contacts, Calendar, Tasks, and GCP Projects.

---

## ⚠️ Warning

Use only on accounts and domains you have permission to test. This tool is for **educational and authorized auditing purposes only**.

---

## 🚀 Features

- 🔐 OAuth2 Authorization with multiple scopes
- 📁 Extracts and downloads:
  - Google Docs, Sheets, and Slides
- 📧 Extracts Gmail labels, message snippets, and raw emails
- 📇 Downloads Google Contacts
- 📅 Lists upcoming Calendar events
- 📋 Lists Google Tasks
- ☁️ Enumerates GCP projects

---

## 📦 Requirements

- Python 3.10+
- `pip install -r requirements.txt`

### Required Packages

```
rich
requests
google-auth
google-auth-oauthlib
google-api-python-client
```

Install using:

```bash
pip install rich requests google-auth google-auth-oauthlib google-api-python-client
```

---

## 🔧 Setup

1. **Enable APIs** in your Google Cloud Console:
   - [Google Drive API](https://console.cloud.google.com/apis/library/drive.googleapis.com)
   - [Gmail API](https://console.cloud.google.com/apis/library/gmail.googleapis.com)
   - [People API](https://console.cloud.google.com/apis/library/people.googleapis.com)
   - [Google Calendar API](https://console.cloud.google.com/apis/library/calendar.googleapis.com)
   - [Google Tasks API](https://console.cloud.google.com/apis/library/tasks.googleapis.com)
   - [Google Keep API](https://console.cloud.google.com/apis/library/keep.googleapis.com)
   - [Cloud Resource Manager API](https://console.cloud.google.com/apis/library/cloudresourcemanager.googleapis.com)

2. **Create OAuth 2.0 Client ID:**

Go to [Credentials Page](https://console.cloud.google.com/apis/credentials):

- Create OAuth Client ID (Desktop App)
- Download `client_secrets.json`

3. **Place `client_secrets.json` in the same directory as your script**

---

## 🔑 Scopes Used

```python
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/drive',  # Kept drive for broader functionality including download
    'https://www.googleapis.com/auth/drive.metadata.readonly',
    'https://www.googleapis.com/auth/contacts.readonly',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/tasks.readonly',
    'https://www.googleapis.com/auth/spreadsheets.readonly',
    'https://www.googleapis.com/auth/presentations.readonly',
    'https://www.googleapis.com/auth/documents.readonly',
    'https://www.googleapis.com/auth/cloud-platform.read-only',
    'https://www.googleapis.com/auth/cloud-platform', # This is a broad scope, consider narrowing if not needed
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/devstorage.read_only' # Added for Cloud Storage
]

```

---

## ▶️ Usage

```bash
python3 gws_enum.py
```

This will:

- Launch a local browser for OAuth login
- Start enumeration and save data in the `loot/` folder:
  - `loot/drive/`
  - `loot/gsheet/`
  - `loot/gmail/`
  - `loot/contacts/`
  - `loot/keep/`

---

## 📁 Output Files

| Folder         | Description                           |
|----------------|---------------------------------------|
| `loot/drive/`  | Downloaded Google Docs & Slides       |
| `loot/gsheet/` | Exported Google Sheets (CSV)          |
| `loot/gmail/`  | Email snippets and raw `.eml` files   |
| `loot/contacts/` | Email addresses & display names     |
| `loot/keep/`   | JSON dump of Keep notes               |

---


## 📄 License

MIT License
