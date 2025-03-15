from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import re
import os
import base64
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

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

                # "to" 텍스트 감지해서 뒷내용 추출
                match = re.search(r'primary alias.*?to\s+([a-zA-Z0-9._%+-]+@outlook\.com)', decoded_data)
                if match:
                    found_emails.append(match.group(1))


# 중복 이메일 제거
unique_emails = list(set(found_emails))

with open("microsoft_email.txt", "w") as f:
    f.write("\n".join(unique_emails))


# 여기서부터 이메일 유효성 검사
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-gpu")

service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service, options=chrome_options)

valid_emails = []
invalid_emails = []
guardian_emails = []

for email in unique_emails:
    driver.get("https://login.live.com/")
    time.sleep(2)

    driver.find_element(By.NAME, "loginfmt").send_keys(email + Keys.RETURN)
    time.sleep(3)

    try:
        error_message = driver.find_element(By.ID, "usernameError").text
        if "Microsoft 계정이 없습니다." in error_message:
            invalid_emails.append(email)
        else:
            valid_emails.append(email)

            driver.find_element(By.ID, "idSIButton9").click()
            time.sleep(3)

            security_text = driver.find_element(By.CLASS_NAME, "highlighted-text").text
            if "gu****@gmail.com" in security_text:
                guardian_emails.append(email)

    except:
        valid_emails.append(email)

with open("valid_microsoft_email.txt", "w") as f:
    f.write("\n".join(valid_emails))

with open("invalid_microsoft_email.txt", "w") as f:
    f.write("\n".join(invalid_emails))

with open("guardian_microsoft_email.txt", "w") as f:
    f.write("\n".join(guardian_emails))

print("✅ 이메일 검사 완료: valid_microsoft_email.txt, invalid_microsoft_email.txt, guardian_microsoft_email.txt")

driver.quit()
