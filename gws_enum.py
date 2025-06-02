from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.table import Table
from rich.progress import track
import os
import json
import base64
import datetime
import requests
from pathlib import Path
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload
import io

console = Console()
now = datetime.datetime.now().isoformat()

# --- Configuration ---
# Enhanced loot directory structure
loot_base = Path("loot")
directories = [
    loot_base / "drive",
    loot_base / "gsheet",
    loot_base / "gmail",
    loot_base / "contacts",
    loot_base / "keep",
    loot_base / "calendar",
    loot_base / "tasks",
    loot_base / "groups",
    loot_base / "gcp",
    loot_base / "sites",
    loot_base / "shared_drives",
    loot_base / "drive_permissions",
    loot_base / "documents", # For Google Docs exports
    loot_base / "spreadsheets", # For Google Sheets exports
    loot_base / "presentations" # For Google Slides exports
]

# Create loot directories
for path in directories:
    path.mkdir(parents=True, exist_ok=True)

# Define specific loot paths for clarity
loot_drive = loot_base / "drive"
loot_gmail = loot_base / "gmail"
loot_gcp = loot_base / "gcp"
loot_sites = loot_base / "sites"
loot_shared_drives = loot_base / "shared_drives"
loot_contacts = loot_base / "contacts" # Added for contacts analysis


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

console.print(Panel(f"[bold green]🚀 Enhanced Google Workspace + GCP Enumeration[/] @ [cyan]{now}[/]", box=box.DOUBLE))

# --- Authentication ---
creds = None
try:
    flow = InstalledAppFlow.from_client_secrets_file('client_secrets.json', SCOPES)
    flow.oauth2session._state = None # This might be needed for older versions or specific setups
    creds = flow.run_local_server(port=0, include_client_id=True)
    authed_session = requests.Session()
    authed_session.headers.update({'Authorization': f'Bearer {creds.token}'})
except Exception as e:
    console.print(f"[red][!][/red] Authentication failed: {e}")
    exit(1)

# --- User Information ---
console.print("\n[bold cyan]👤 User Information[/]")
try:
    userinfo = authed_session.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
    email = userinfo.get("email", "unknown")
    name = userinfo.get("name", "unknown")
    picture = userinfo.get("picture", "")

    with open(loot_base / "user_info.json", "w") as f:
        json.dump(userinfo, f, indent=2)

    console.print(f"[green][+][/green] Logged in as: [bold yellow]{name}[/bold yellow] <[cyan]{email}[/cyan]>")
    if picture:
        console.print(f"[green][+][/green] Profile picture: [underline]{picture}[/underline]")

    # Get directory API info if available
    try:
        directory = build('admin', 'directory_v1', credentials=creds)
        # For 'directory_v1', you usually need domain-wide delegation for a service account,
        # or specific admin roles for an authenticated user.
        # This will likely fail for a regular user unless they are a super admin.
        user = directory.users().get(userKey=email).execute()
        with open(loot_base / "directory_info.json", "w") as f:
            json.dump(user, f, indent=2)
        console.print(f"[green][+][/green] Organization: [bold]{user.get('orgUnitPath', 'N/A')}[/bold]")
    except HttpError as e:
        console.print(f"[yellow][-][/yellow] No Directory API access or user not found via Directory API: {e}")
except Exception as e:
    console.print(f"[red][!][/red] User info error: {e}")

# --- Helper function for MIME type to file extension mapping ---
def get_file_extension(mime_type):
    extensions = {
        'application/vnd.google-apps.document': '.docx',
        'application/vnd.google-apps.spreadsheet': '.xlsx',
        'application/vnd.google-apps.presentation': '.pptx',
        'application/vnd.google-apps.drawing': '.png',
        'application/vnd.google-apps.script': '.gs',
        'application/vnd.google-apps.form': '.zip', # Forms can sometimes be exported as zip
        'application/pdf': '.pdf',
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'text/plain': '.txt',
        'application/json': '.json',
        'application/xml': '.xml',
        'text/html': '.html',
        'application/zip': '.zip',
        'application/x-rar-compressed': '.rar',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
    }
    return extensions.get(mime_type, '')

# --- Google Drive Analysis ---
def analyze_drive():
    console.print("\n[bold cyan]📁 Enhanced Google Drive Analysis[/]")
    drive_service = build('drive', 'v3', credentials=creds)

    # Get storage quota
    try:
        about = drive_service.about().get(fields="storageQuota").execute()
        used = int(about['storageQuota']['usage']) / (1024**3)
        limit = int(about['storageQuota']['limit']) / (1024**3)
        console.print(f"[green][+][/green] Storage: [bold]{used:.2f}GB[/bold] used of [bold]{limit:.2f}GB[/bold]")
    except Exception as e:
        console.print(f"[red][!][/red] Storage quota error: {e}")

    # Get all file types with counts
    try:
        results = []
        page_token = None
        while True:
            response = drive_service.files().list(
                fields="nextPageToken, files(id, name, mimeType, shared, owners, webViewLink, permissions, modifiedTime)",
                pageSize=1000,
                q="'me' in owners", # Only files owned by the authenticated user
                pageToken=page_token
            ).execute()
            results.extend(response.get('files', []))
            page_token = response.get('nextPageToken', None)
            if not page_token:
                break

        file_types = {}
        shared_files = []
        for file in results:
            mime = file['mimeType']
            file_types[mime] = file_types.get(mime, 0) + 1
            if file.get('shared'):
                shared_files.append(file)

        # Save shared files analysis
        with open(loot_drive / "shared_files.json", "w") as f:
            json.dump(shared_files, f, indent=2)

        # Print file type summary
        table = Table(title="File Type Summary (My Drive)", box=box.ROUNDED)
        table.add_column("MIME Type", style="cyan")
        table.add_column("Count", style="green")
        for mime, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True):
            table.add_row(mime, str(count))
        console.print(table)

        console.print(f"[green][+][/green] Found [bold]{len(shared_files)}[/bold] shared files in My Drive")

        # Permission analysis (for a subset of shared files to avoid rate limits)
        permission_analysis = {}
        for file in track(shared_files[:100], description="Analyzing permissions for shared files..."):
            try:
                perms = drive_service.permissions().list(fileId=file['id'], fields="permissions(type, role, emailAddress, displayName)").execute()
                permission_analysis[file['id']] = {
                    'name': file['name'],
                    'webViewLink': file.get('webViewLink'),
                    'permissions': perms.get('permissions', [])
                }
            except HttpError as e:
                console.print(f"[yellow][-][/yellow] Could not retrieve permissions for '{file['name']}': {e}")

        with open(loot_base / "drive_permissions" / "my_drive_permission_analysis.json", "w") as f:
            json.dump(permission_analysis, f, indent=2)

    except Exception as e:
        console.print(f"[red][!][/red] Drive analysis error: {e}")

# --- Enhanced Gmail Analysis ---
def analyze_gmail():
    console.print("\n[bold cyan]📧 Enhanced Gmail Analysis[/]")
    gmail = build('gmail', 'v1', credentials=creds)

    try:
        # Get mailbox profile
        profile = gmail.users().getProfile(userId='me').execute()
        with open(loot_gmail / "profile.json", "w") as f:
            json.dump(profile, f, indent=2)

        console.print(f"[green][+][/green] Total messages: [bold]{profile.get('messagesTotal', 0)}[/bold]")
        console.print(f"[green][+][/green] Total threads: [bold]{profile.get('threadsTotal', 0)}[/bold]")

        # Get filters
        filters = gmail.users().settings().filters().list(userId='me').execute().get('filter', [])
        with open(loot_gmail / "filters.json", "w") as f:
            json.dump(filters, f, indent=2)
        console.print(f"[green][+][/green] Found [bold]{len(filters)}[/bold] email filters")

        # Get forwarding addresses
        forwarding = gmail.users().settings().forwardingAddresses().list(userId='me').execute().get('forwardingAddresses', [])
        with open(loot_gmail / "forwarding.json", "w") as f:
            json.dump(forwarding, f, indent=2)
        if forwarding:
            console.print("[yellow][!][/yellow] Forwarding addresses configured:")
            for addr in forwarding:
                console.print(f"    • [bold]{addr['forwardingEmail']}[/bold] (verification: {addr.get('verificationStatus', 'unknown')})")

    except Exception as e:
        console.print(f"[red][!][/red] Gmail analysis error: {e}")

# --- Google Groups Analysis ---
def analyze_groups():
    console.print("\n[bold cyan]👥 Google Groups Analysis[/]")
    try:

        # If the authenticated user is a domain administrator, then the following might work:
        directory_service = build('admin', 'directory_v1', credentials=creds)

        console.print("[yellow]Note:[/yellow] Listing all Google Groups usually requires Google Workspace admin privileges or specific Cloud Identity API permissions. This might fail for regular users.")
        groups = []
        page_token = None
        while True:
            # Using directory_v1 for groups; requires admin scope.
            response = directory_service.groups().list(
                customer='my_customer', # Replace with actual customer ID or 'my_customer' for domain associated with user
                fields='nextPageToken, groups(id, name, email, description, adminCreated, directMembersCount)',
                maxResults=200,
                pageToken=page_token
            ).execute()
            groups.extend(response.get('groups', []))
            page_token = response.get('nextPageToken', None)
            if not page_token:
                break

        if groups:
            group_loot_path = loot_base / "groups"
            group_loot_path.mkdir(exist_ok=True) # Ensure the groups directory exists

            with open(group_loot_path / "all_groups.json", "w") as f:
                json.dump(groups, f, indent=2)

            table = Table(title="Google Groups", box=box.ROUNDED)
            table.add_column("Group Name", style="cyan")
            table.add_column("Email", style="green")
            table.add_column("Members (Estimate)", style="yellow") # directMembersCount is approximate

            for group in groups:
                table.add_row(
                    group.get('name', 'N/A'),
                    group.get('email', 'N/A'),
                    str(group.get('directMembersCount', 'N/A'))
                )

                # Save members for each group (this requires specific admin scope and direct API calls for each group)
                # This part is highly likely to fail for non-admin users.
                # It's also very chatty on the API.
                # Disabling for a normal user flow.
                # try:
                #     members = directory_service.members().list(groupKey=group['id']).execute().get('members', [])
                #     group_dir = group_loot_path / group['id']
                #     group_dir.mkdir(exist_ok=True)
                #     with open(group_dir / "members.json", "w") as f:
                #         json.dump(members, f, indent=2)
                # except HttpError as e:
                #     console.print(f"[yellow][-][/yellow] Failed to get members for group '{group.get('name', 'N/A')}': {e}")

            console.print(table)
        else:
            console.print("[red][-][/red] No groups found or insufficient access to list groups.")
    except HttpError as e:
        console.print(f"[red][!][/red] Google Groups API (Admin SDK) access error: {e}. Ensure you have necessary admin roles or domain-wide delegation configured.")
    except Exception as e:
        console.print(f"[red][!][/red] Groups analysis error: {e}")

# --- Google Sites Analysis ---
def analyze_sites():
    console.print("\n[bold cyan]🌐 Google Sites Analysis[/]")
    try:
        sites_service = build('sites', 'v1', credentials=creds)
        sites = []
        page_token = None
        while True:
            response = sites_service.sites().list(
                fields='nextPageToken, sites(name, title, siteUrl, createdTime, lastPublishedTime)', # More fields for better info
                pageToken=page_token
            ).execute()
            sites.extend(response.get('sites', []))
            page_token = response.get('nextPageToken', None)
            if not page_token:
                break

        if sites:
            with open(loot_sites / "sites.json", "w") as f:
                json.dump(sites, f, indent=2)

            table = Table(title="Google Sites", box=box.ROUNDED)
            table.add_column("Site Name", style="cyan")
            table.add_column("URL", style="green")
            table.add_column("Created", style="yellow")
            table.add_column("Last Published", style="magenta")

            for site in sites:
                table.add_row(
                    site.get('title', site.get('name', 'N/A')), # Prefer title over name if available
                    site.get('siteUrl', 'N/A'),
                    site.get('createdTime', 'N/A'),
                    site.get('lastPublishedTime', 'N/A')
                )

            console.print(table)
        else:
            console.print("[red][-][/red] No Google Sites found")
    except HttpError as e:
        console.print(f"[red][!][/red] Google Sites API access error: {e}")
    except Exception as e:
        console.print(f"[red][!][/red] Sites error: {e}")

# --- Shared Drives Analysis and Download ---
def download_drive_content(drive_service, file_id, file_name, mime_type, download_path):
    """
    Downloads a single file from Google Drive, handling native Google Workspace formats.
    """
    file_extension = get_file_extension(mime_type)

    # Sanitize file name for path
    safe_file_name = "".join([c for c in file_name if c.isalpha() or c.isdigit() or c in (' ', '.', '_', '-')]).rstrip()
    if not safe_file_name: # Fallback if sanitization results in empty string
        safe_file_name = file_id

    final_file_name = f"{safe_file_name}{file_extension}" if file_extension else safe_file_name
    output_filepath = download_path / final_file_name

    try:
        # Check if it's a Google Workspace native file
        if 'application/vnd.google-apps' in mime_type:
            # Export Google Docs, Sheets, Slides etc. to standard formats
            if mime_type == 'application/vnd.google-apps.document':
                request = drive_service.files().export_media(fileId=file_id, mimeType='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
            elif mime_type == 'application/vnd.google-apps.spreadsheet':
                request = drive_service.files().export_media(fileId=file_id, mimeType='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
            elif mime_type == 'application/vnd.google-apps.presentation':
                request = drive_service.files().export_media(fileId=file_id, mimeType='application/vnd.openxmlformats-officedocument.presentationml.presentation')
            elif mime_type == 'application/vnd.google-apps.drawing':
                request = drive_service.files().export_media(fileId=file_id, mimeType='image/png')
            elif mime_type == 'application/vnd.google-apps.script':
                request = drive_service.files().export_media(fileId=file_id, mimeType='application/vnd.google-apps.script+json')
                # For script, might need to change extension to .json or .gs
                output_filepath = download_path / f"{safe_file_name}.json"
            else:
                console.print(f"[yellow][-][/yellow] Skipping export for unsupported Google Workspace MIME type: {mime_type}")
                return False # Indicate that download was skipped

        else:
            # For other file types, use get_media
            request = drive_service.files().get_media(fileId=file_id)

        fh = io.FileIO(output_filepath, 'wb')
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while done is False:
            status, done = downloader.next_chunk()
            # console.print(f"Downloading {file_name}: {int(status.progress() * 100)}%")
        console.print(f"[green][+][/green] Downloaded '{final_file_name}' to '{output_filepath}'")
        return True # Indicate successful download
    except HttpError as e:
        if e.resp.status == 403:
            console.print(f"[red][!][/red] Permission denied to download '{file_name}' ({file_id}): {e}")
        else:
            console.print(f"[red][!][/red] HTTP Error downloading '{file_name}' ({file_id}): {e}")
    except Exception as e:
        console.print(f"[red][!][/red] Error downloading '{file_name}' ({file_id}): {e}")
    return False # Indicate failed download


def analyze_shared_drives():
    console.print("\n[bold cyan]📂 Shared Drives Analysis[/]")
    drive_service = build('drive', 'v3', credentials=creds)
    shared_drives = []
    page_token_drives = None
    try:
        while True:
            response = drive_service.drives().list(
                fields="nextPageToken, drives(id, name, createdTime, capabilities)",
                useDomainAdminAccess=False, # Set to True if running with domain-wide delegation for full admin view
                pageSize=100,
                pageToken=page_token_drives
            ).execute()
            shared_drives.extend(response.get('drives', []))
            page_token_drives = response.get('nextPageToken', None)
            if not page_token_drives:
                break

        if shared_drives:
            with open(loot_shared_drives / "shared_drives.json", "w") as f:
                json.dump(shared_drives, f, indent=2)

            table = Table(title="Shared Drives", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("ID", style="green")
            table.add_column("Created", style="yellow")
            table.add_column("Can Add Items", style="magenta")

            for sd in shared_drives:
                table.add_row(
                    sd.get('name', 'N/A'),
                    sd.get('id', 'N/A'),
                    sd.get('createdTime', 'N/A'),
                    str(sd.get('capabilities', {}).get('canAddChildren', 'N/A'))
                )

            console.print(table)

            # Get permissions and download content for each shared drive
            for sd in track(shared_drives, description="Processing shared drives..."):
                drive_id = sd['id']
                drive_name = sd['name']
                console.print(f"\n[bold blue]Processing Shared Drive:[/bold blue] [cyan]{drive_name}[/] (ID: {drive_id})")

                # Create a directory for the shared drive's content
                drive_content_dir = loot_shared_drives / drive_name.replace('/', '_').replace(' ', '_')
                drive_content_dir.mkdir(exist_ok=True)

                # Get permissions for the shared drive
                try:
                    permissions = drive_service.permissions().list(
                        fileId=drive_id,
                        supportsAllDrives=True,
                        useDomainAdminAccess=False, # Set to True if domain-wide delegation
                        fields="permissions(id, displayName, emailAddress, role, type)"
                    ).execute().get('permissions', [])

                    with open(drive_content_dir / f"{drive_id}_permissions.json", "w") as f:
                        json.dump(permissions, f, indent=2)
                    console.print(f"[green][+][/green] Saved permissions for '{drive_name}'")
                except HttpError as e:
                    console.print(f"[yellow][-][/yellow] Failed to get permissions for '{drive_name}': {e}")
                except Exception as e:
                    console.print(f"[red][!][/red] Error getting permissions for '{drive_name}': {e}")

                # List and download files from the shared drive
                console.print(f"[bold yellow]Downloading content from '{drive_name}'...[/bold yellow]")
                files_to_download = []
                page_token_files = None
                try:
                    while True:
                        response = drive_service.files().list(
                            corpora="drive",
                            driveId=drive_id,
                            includeItemsFromAllDrives=True,
                            supportsAllDrives=True,
                            fields="nextPageToken, files(id, name, mimeType)",
                            pageSize=1000,
                            pageToken=page_token_files
                        ).execute()

                        files = response.get('files', [])
                        for file in files:
                            # Skip folders for direct download
                            if file['mimeType'] != 'application/vnd.google-apps.folder':
                                files_to_download.append(file)

                        page_token_files = response.get('nextPageToken', None)
                        if not page_token_files:
                            break

                    if files_to_download:
                        console.print(f"[green][+][/green] Found [bold]{len(files_to_download)}[/bold] files to download from '{drive_name}'")
                        for file_item in track(files_to_download, description=f"Downloading files from {drive_name}"):
                            download_drive_content(drive_service, file_item['id'], file_item['name'], file_item['mimeType'], drive_content_dir)
                    else:
                        console.print(f"[yellow][-][/yellow] No files found in '{drive_name}' to download (or only folders).")
                except HttpError as e:
                    console.print(f"[red][!][/red] HTTP Error listing files for '{drive_name}': {e}")
                except Exception as e:
                    console.print(f"[red][!][/red] Error listing files for '{drive_name}': {e}")

        else:
            console.print("[red][-][/red] No shared drives found")
    except HttpError as e:
        console.print(f"[red][!][/red] Shared drives API access error: {e}. Ensure 'drive.drives().list()' is permitted.")
    except Exception as e:
        console.print(f"[red][!][/red] Shared drives analysis error: {e}")


# Enhanced Google Docs/Sheets/Slides Analysis
def analyze_workspace_docs():
    console.print("\n[bold cyan]📝 Enhanced Google Workspace Docs Analysis[/]")
    drive = build('drive', 'v3', credentials=creds)

    # Query for all Google Workspace file types
    query = """
    mimeType='application/vnd.google-apps.document' or
    mimeType='application/vnd.google-apps.spreadsheet' or
    mimeType='application/vnd.google-apps.presentation'
    """

    try:
        results = []
        page_token = None
        while True:
            response = drive.files().list(
                q=query,
                fields="nextPageToken, files(id, name, mimeType, owners, modifiedTime, viewedByMeTime, shared, permissions)",
                pageSize=1000,
                supportsAllDrives=True,
                includeItemsFromAllDrives=True,
                pageToken=page_token
            ).execute()
            results.extend(response.get('files', []))
            page_token = response.get('nextPageToken')
            if not page_token:
                break

        # Categorize files
        docs = [f for f in results if f['mimeType'] == 'application/vnd.google-apps.document']
        sheets = [f for f in results if f['mimeType'] == 'application/vnd.google-apps.spreadsheet']
        slides = [f for f in results if f['mimeType'] == 'application/vnd.google-apps.presentation']

        # Export and analyze each type
        def process_files(files, file_type, export_mime):
            console.print(f"\n[bold]🔹 Processing {len(files)} {file_type} files[/]")
            loot_dir = loot_base / f"{file_type.lower()}s"
            loot_dir.mkdir(exist_ok=True) # Ensure the specific document type directory exists
            metadata_dir = loot_dir / "metadata"
            metadata_dir.mkdir(exist_ok=True)

            for file in track(files[:50], description=f"Analyzing {file_type}..."):  # Limit to 50 for demo
                try:
                    # Export file
                    # MIME types for export
                    if file_type == "Document":
                        export_mime_actual = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                        ext = "docx"
                    elif file_type == "Spreadsheet":
                        export_mime_actual = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                        ext = "xlsx"
                    elif file_type == "Presentation":
                        export_mime_actual = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
                        ext = "pptx" # Using pptx as a standard export, or pdf if preferred
                    else:
                        console.print(f"[yellow][-][/yellow] Skipping export for unsupported Google Workspace file type: {file_type}")
                        continue

                    request = drive.files().export_media(
                        fileId=file['id'],
                        mimeType=export_mime_actual
                    )
                    fh = io.BytesIO()
                    downloader = MediaIoBaseDownload(fh, request)
                    done = False
                    while not done:
                        status, done = downloader.next_chunk()

                    # Sanitize filename
                    safe_file_name = "".join([c for c in file['name'] if c.isalpha() or c.isdigit() or c in (' ', '.', '_', '-')]).rstrip()
                    if not safe_file_name:
                        safe_file_name = file['id']

                    # Save content
                    file_path = loot_dir / f"{safe_file_name}.{ext}"
                    with open(file_path, 'wb') as f_out:
                        f_out.write(fh.getvalue())
                    console.print(f"[green][+][/green] Exported '{safe_file_name}.{ext}'")

                    # Save metadata
                    meta_path = metadata_dir / f"{file['id']}.json"
                    with open(meta_path, 'w') as f_meta:
                        json.dump({
                            'name': file['name'],
                            'id': file['id'],
                            'mimeType': file['mimeType'],
                            'modifiedTime': file.get('modifiedTime'),
                            'viewedByMeTime': file.get('viewedByMeTime'),
                            'shared': file.get('shared', False),
                            'permissions': file.get('permissions', [])
                        }, f_meta, indent=2)

                except HttpError as e:
                    console.print(f"[yellow][-][/yellow] HTTP Error processing {file_type} '{file['name']}': {e}")
                except Exception as e:
                    console.print(f"[red][!][/red] Error processing {file_type} '{file['name']}': {e}")

        # Process each file type
        if docs:
            process_files(docs, "Document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        if sheets:
            process_files(sheets, "Spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        if slides:
            process_files(slides, "Presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation") # Change to pptx for consistency, or pdf if desired

        # Create summary table
        table = Table(title="Google Workspace Docs Summary", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Last Modified", style="yellow")
        table.add_column("Shared %", style="magenta")

        for category, files in [("Documents", docs), ("Sheets", sheets), ("Slides", slides)]:
            if files:
                last_modified_times = [f.get('modifiedTime', '1970-01-01T00:00:00Z') for f in files]
                last_modified = max(last_modified_times)
                shared_count = sum(1 for f in files if f.get('shared', False))
                shared_pct = (shared_count / len(files)) * 100 if files else 0
                table.add_row(
                    category,
                    str(len(files)),
                    last_modified[:10] if last_modified else 'N/A',
                    f"{shared_pct:.1f}%"
                )

        console.print(table)

    except Exception as e:
        console.print(f"[red][!][/red] Workspace docs analysis error: {e}")


# Enhanced Google Contacts Analysis
def analyze_contacts():
    console.print("\n[bold cyan]📇 Enhanced Google Contacts Analysis[/]")
    try:
        people_service = build('people', 'v1', credentials=creds)

        # Get all connections with detailed fields
        connections = []
        page_token = None
        while True:
            results = people_service.people().connections().list(
                resourceName='people/me',
                pageSize=1000,
                personFields='names,emailAddresses,phoneNumbers,organizations,addresses,biographies',
                pageToken=page_token
            ).execute()
            connections.extend(results.get('connections', []))
            page_token = results.get('nextPageToken')
            if not page_token:
                break

        if connections:
            # Save full contacts data
            with open(loot_contacts / "full_contacts.json", "w") as f:
                json.dump(connections, f, indent=2)

            # Create detailed table
            table = Table(title="Contacts Summary", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("Email", style="green")
            table.add_column("Phone", style="yellow")
            table.add_column("Organization", style="magenta")

            contact_count = 0
            org_counter = {}

            for person in connections[:100]:  # Show first 100 for brevity
                name = person.get('names', [{}])[0].get('displayName', 'Unknown')
                email = person.get('emailAddresses', [{}])[0].get('value', 'None')
                phone = person.get('phoneNumbers', [{}])[0].get('value', 'None')
                org = person.get('organizations', [{}])[0].get('name', 'None')

                # Count organizations
                if org != 'None':
                    org_counter[org] = org_counter.get(org, 0) + 1

                table.add_row(name, email, phone, org)
                contact_count += 1

            console.print(table)
            console.print(f"[green][+][/green] Processed {contact_count} contacts (showing first 100)")

            # Organization statistics
            if org_counter:
                org_table = Table(title="Top Organizations", box=box.SIMPLE)
                org_table.add_column("Organization", style="cyan")
                org_table.add_column("Count", style="green")
                for org, count in sorted(org_counter.items(), key=lambda x: x[1], reverse=True)[:10]:
                    org_table.add_row(org, str(count))
                console.print(org_table)

            # Export to vCard format
            try:
                vcard_data = []
                for person in connections:
                    vcard = ["BEGIN:VCARD", "VERSION:3.0"]
                    if 'names' in person:
                        name = person['names'][0]
                        vcard.append(f"N:{name.get('familyName','')};{name.get('givenName','')};;;")
                        vcard.append(f"FN:{name.get('displayName','')}")
                    if 'emailAddresses' in person:
                        for email in person['emailAddresses']:
                            vcard.append(f"EMAIL:{email.get('value','')}")
                    if 'phoneNumbers' in person:
                        for phone in person['phoneNumbers']:
                            vcard.append(f"TEL:{phone.get('value','')}")
                    vcard.append("END:VCARD")
                    vcard_data.append("\n".join(vcard))

                with open(loot_contacts / "contacts.vcf", "w") as f:
                    f.write("\n".join(vcard_data))
                console.print("[green][+][/green] Exported contacts to vCard format")

            except Exception as e:
                console.print(f"[yellow][-][/yellow] Failed to export vCard: {e}")

        else:
            console.print("[red][-][/red] No contacts found")

    except Exception as e:
        console.print(f"[red][!][/red] Contacts error: {e}")


# Enhanced GCP Analysis
def enhanced_analyze_gcp():
    console.print("\n[bold cyan]☁️ Enhanced GCP Analysis[/]")
    try:
        # Initialize services
        cloudres = build('cloudresourcemanager', 'v1', credentials=creds)
        serviceusage = build('serviceusage', 'v1', credentials=creds)
        iam = build('iam', 'v1', credentials=creds)
        compute = build('compute', 'v1', credentials=creds)
        storage = build('storage', 'v1', credentials=creds) # Initialize Cloud Storage API

        # Get all projects
        projects = []
        page_token = None
        while True:
            response = cloudres.projects().list(pageToken=page_token).execute()
            projects.extend(response.get('projects', []))
            page_token = response.get('nextPageToken')
            if not page_token:
                break

        if not projects:
            console.print("[red][-][/red] No GCP projects found")
            return

        # Main projects table
        main_table = Table(title="GCP Projects Overview", box=box.ROUNDED)
        main_table.add_column("Project ID", style="cyan")
        main_table.add_column("Name", style="green")
        main_table.add_column("Number", style="yellow")
        main_table.add_column("State", style="magenta")

        for proj in projects:
            main_table.add_row(
                proj['projectId'],
                proj.get('name', 'N/A'),
                str(proj.get('projectNumber', 'N/A')),
                proj.get('lifecycleState', 'N/A')
            )

        console.print(main_table)

        # Detailed analysis for each project
        for project in track(projects, description="Analyzing projects..."):
            project_id = project['projectId']
            project_dir = loot_gcp / project_id
            project_dir.mkdir(exist_ok=True)

            # Save basic project info
            with open(project_dir / "project_info.json", "w") as f:
                json.dump(project, f, indent=2)

            # Get IAM policy
            try:
                policy = cloudres.projects().getIamPolicy(
                    resource=project_id,
                    body={}
                ).execute()
                with open(project_dir / "iam_policy.json", "w") as f:
                    json.dump(policy, f, indent=2)

                # Analyze roles
                roles = set()
                for binding in policy.get('bindings', []):
                    roles.add(binding['role'])

                with open(project_dir / "roles_used.txt", "w") as f:
                    f.write("\n".join(sorted(roles)))

            except HttpError as e:
                console.print(f"[yellow][-][/yellow] Failed to get IAM policy for {project_id}: {e}")
            except Exception as e:
                console.print(f"[red][!][/red] Error getting IAM policy for {project_id}: {e}")

            # Get enabled services
            try:
                services = serviceusage.services().list(
                    parent=f"projects/{project_id}",
                    filter="state:ENABLED"
                ).execute().get('services', [])

                with open(project_dir / "enabled_services.json", "w") as f:
                    json.dump(services, f, indent=2)

                # Check for sensitive services
                sensitive_services = {
                    'compute.googleapis.com': 'Compute Engine',
                    'container.googleapis.com': 'Kubernetes Engine',
                    'cloudkms.googleapis.com': 'Cloud KMS',
                    'iam.googleapis.com': 'IAM',
                    'admin.googleapis.com': 'Admin SDK',
                    'storage.googleapis.com': 'Cloud Storage' # Added Cloud Storage
                }

                enabled_sensitive = []
                for service in services:
                    if service['config']['name'] in sensitive_services:
                        enabled_sensitive.append(sensitive_services[service['config']['name']])

                if enabled_sensitive:
                    console.print(f"[yellow][!][/yellow] Project [bold]{project_id}[/] has sensitive services enabled: {', '.join(enabled_sensitive)}")

            except HttpError as e:
                console.print(f"[yellow][-][/yellow] Failed to get services for {project_id}: {e}")
            except Exception as e:
                console.print(f"[red][!][/red] Error getting services for {project_id}: {e}")

            # Get Compute Engine instances if Compute API is enabled
            try:
                instances_response = compute.instances().aggregatedList(project=project_id).execute()
                instance_count = 0
                all_instances = []
                for zone, items in instances_response.get('items', {}).items():
                    if 'instances' in items:
                        instance_count += len(items['instances'])
                        all_instances.extend(items['instances'])

                if instance_count > 0:
                    with open(project_dir / "compute_instances.json", "w") as f:
                        json.dump(all_instances, f, indent=2) # Save the list of instances
                    console.print(f"[green][+][/green] Project [bold]{project_id}[/] has {instance_count} Compute Engine instances")
            except HttpError as e:
                if e.resp.status != 403 and e.resp.status != 404: # Ignore permission/not found errors for non-enabled APIs
                    console.print(f"[yellow][-][/yellow] Failed to get Compute instances for {project_id}: {e}")
            except Exception as e:
                # pass  # Compute API probably not enabled or other error
                console.print(f"[yellow][-][/yellow] General error getting Compute instances for {project_id}: {e}")


            # Get service accounts
            try:
                accounts_response = iam.projects().serviceAccounts().list(
                    name=f"projects/{project_id}"
                ).execute()
                accounts = accounts_response.get('accounts', [])

                if accounts:
                    with open(project_dir / "service_accounts.json", "w") as f:
                        json.dump(accounts, f, indent=2)

                    # Check for user-managed keys
                    for account in accounts:
                        try:
                            keys_response = iam.projects().serviceAccounts().keys().list(
                                name=account['name'],
                                keyTypes='USER_MANAGED'
                            ).execute()
                            keys = keys_response.get('keys', [])

                            if keys:
                                console.print(f"[yellow][!][/!][/bold] Service account [bold]{account['email']}[/] has {len(keys)} user-managed keys!")
                                with open(project_dir / f"{account['uniqueId']}_keys.json", "w") as f:
                                    json.dump(keys, f, indent=2)
                        except HttpError as e:
                            console.print(f"[yellow][-][/yellow] Failed to list keys for service account {account['email']}: {e}")

            except HttpError as e:
                if e.resp.status != 403: # Ignore permission denied if IAM API not fully accessible
                    console.print(f"[yellow][-][/yellow] Failed to get service accounts for {project_id}: {e}")
            except Exception as e:
                console.print(f"[red][!][/red] Error getting service accounts for {project_id}: {e}")


            # --- Cloud Storage Bucket Analysis ---
            console.print(f"[bold purple]  🔍 Analyzing Cloud Storage Buckets for {project_id}[/bold purple]")
            try:
                buckets = []
                page_token_buckets = None
                while True:
                    bucket_response = storage.buckets().list(
                        project=project_id,
                        pageToken=page_token_buckets
                    ).execute()
                    buckets.extend(bucket_response.get('items', []))
                    page_token_buckets = bucket_response.get('nextPageToken')
                    if not page_token_buckets:
                        break

                if buckets:
                    bucket_data_file = project_dir / "cloud_storage_buckets.json"
                    with open(bucket_data_file, "w") as f:
                        json.dump(buckets, f, indent=2)
                    console.print(f"[green][+][/green] Found [bold]{len(buckets)}[/bold] buckets in project [cyan]{project_id}[/cyan]")

                    for bucket in track(buckets, description=f"Analyzing buckets in {project_id}"):
                        bucket_name = bucket['name']
                        bucket_info_dir = project_dir / "buckets" / bucket_name
                        bucket_info_dir.mkdir(parents=True, exist_ok=True)

                        # Get Bucket IAM Policy
                        try:
                            bucket_policy = storage.buckets().getIamPolicy(bucket=bucket_name).execute()
                            policy_file = bucket_info_dir / "iam_policy.json"
                            with open(policy_file, "w") as f:
                                json.dump(bucket_policy, f, indent=2)

                            # Check for public access
                            is_public = False
                            for binding in bucket_policy.get('bindings', []):
                                if 'allUsers' in binding.get('members', []) or 'allAuthenticatedUsers' in binding.get('members', []):
                                    console.print(f"[red][!][/red] Bucket [bold red]'{bucket_name}'[/bold red] has public access! Role: {binding.get('role')}")
                                    is_public = True
                                    break
                            if not is_public:
                                console.print(f"[green][+][/green] Bucket '{bucket_name}' IAM policy saved. No public access detected.")

                        except HttpError as e:
                            console.print(f"[yellow][-][/yellow] Failed to get IAM policy for bucket '{bucket_name}': {e}")
                        except Exception as e:
                            console.print(f"[red][!][/red] Error getting IAM policy for bucket '{bucket_name}': {e}")

                        # List a few objects from the bucket (can be very verbose, limit to first N)
                        try:
                            objects_response = storage.objects().list(
                                bucket=bucket_name,
                                maxResults=10 # Limit to first 10 objects
                            ).execute()
                            objects = objects_response.get('items', [])
                            if objects:
                                objects_file = bucket_info_dir / "sample_objects.json"
                                with open(objects_file, "w") as f:
                                    json.dump(objects, f, indent=2)
                                console.print(f"[green][+][/green] Saved info for {len(objects)} sample objects from '{bucket_name}'")
                            else:
                                console.print(f"[yellow][-][/yellow] No objects found in bucket '{bucket_name}' (or no access).")
                        except HttpError as e:
                            console.print(f"[yellow][-][/yellow] Failed to list objects in bucket '{bucket_name}': {e}")
                        except Exception as e:
                            console.print(f"[red][!][/red] Error listing objects in bucket '{bucket_name}': {e}")

                else:
                    console.print(f"[yellow][-][/yellow] No Cloud Storage buckets found in project [cyan]{project_id}[/cyan]")
            except HttpError as e:
                console.print(f"[red][!][/red] Failed to list buckets for project {project_id}: {e}")
            except Exception as e:
                console.print(f"[red][!][/red] General error during Cloud Storage analysis for {project_id}: {e}")


        console.print("\n[bold]🔹 GCP Security Findings Summary[/]")
        console.print("[yellow]![yellow] Review the following potential issues:")
        console.print("  - Projects with sensitive services enabled")
        console.print("  - Service accounts with user-managed keys")
        console.print("  - Broad IAM permissions (check iam_policy.json files)")
        console.print("  - [bold red]Publicly accessible Cloud Storage buckets[/bold red] (check bucket IAM policies)")

    except Exception as e:
        console.print(f"[red][!][/red] Enhanced GCP analysis error: {e}")


# --- Execute Analysis Functions ---
analyze_drive()
analyze_gmail()
analyze_groups()
analyze_sites()
analyze_shared_drives()
analyze_workspace_docs() # Call the new workspace docs analysis
analyze_contacts() # Call the contacts analysis
enhanced_analyze_gcp() # Call the enhanced GCP analysis

# --- Final Summary ---
console.print(Panel(
    "[bold green]✅ Enhanced enumeration complete![/]\n"
    "All data saved in [bold yellow]./loot/[/] directory\n"
    "[cyan]Tip:[/] Review the JSON files and downloaded content for detailed information",
    box=box.HEAVY
))
