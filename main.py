from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import re
import os
import base64

# Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# 토큰 import 부분 ( .json 으로 파일 관리 )
creds = None
if os.path.exists('token.json'):
    creds = Credentials.from_authorized_user_file('token.json')

if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        from google_auth_oauthlib.flow import InstalledAppFlow
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
    with open('token.json', 'w') as token:
        token.write(creds.to_json())

# API 빌드
service = build('gmail', 'v1', credentials=creds)

# 이메일 변경 유무 메일 검색
results = service.users().messages().list(userId='me', q='from:account-security-noreply@accountprotection.microsoft.com "primary alias"').execute()
messages = results.get('messages', [])

found_emails = []

for message in messages:
    msg = service.users().messages().get(userId='me', id=message['id']).execute()
    payload = msg['payload']

    # 메일 내용
    if 'parts' in payload:
        parts = payload['parts']
        for part in parts:
            if part['mimeType'] == 'text/plain':
                data = part['body']['data']
                decoded_data = base64.urlsafe_b64decode(data).decode('utf-8')

                # "to" 텍스트 감지, 뒷부분 추출
                match = re.search(r'primary alias.*?to\s+([a-zA-Z0-9._%+-]+@outlook\.com)', decoded_data)
                if match:
                    found_emails.append(match.group(1))

# 중복 제거
unique_emails = list(set(found_emails))

with open("microsoft_email.txt", "w") as f:
    f.write("\n".join(unique_emails))

print("✅ 추출 완료: microsoft_email.txt")
