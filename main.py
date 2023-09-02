import base64
import re
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from datetime import datetime
import time
import requests
import json
from urllib.parse import urlparse
import openai

# Set the credentials path
## When you form your token rename to credentials.json
creds = Credentials.from_authorized_user_file('credentials.json')

# Create a Gmail API client
service = build('gmail', 'v1', credentials=creds)

# Sanitize the sender and recipient addresses
def sanitize_address(address):
    # Replace period with [.]
    return address.replace('.', '[.]')

# Get the subject and sender from user input
subject = input('Enter the subject of the email to search: ')
sender = input('Enter the sender email address to search: ')
print("#" * 50) # Add separator line

# Search for emails matching the given subject and sender
query = f"subject:{subject} from:{sender}"
result = service.users().messages().list(userId='me', q=query).execute()

# Get a list of matching messages
messages = result.get('messages', [])

# Check if any messages were found
if not messages:
    print('No emails found with the given subject and sender.')
else:
    print(f'{len(messages)} emails found with the given subject and sender.')

    # Process each message
    for message in messages:
        # Get the message details
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        subject = next(h['value'] for h in msg['payload']['headers'] if h['name'] == 'Subject')
        sender = next(h['value'] for h in msg['payload']['headers'] if h['name'] == 'From')
        body = None
        attachment_name = None

        # Get the message body and attachment name if present
if 'parts' in msg['payload']:
    for part in msg['payload']['parts']:
        if part['mimeType'] == 'text/plain':
            body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8').strip()
            body = re.sub(r'[\n\r\s]+', ' ', body)  # remove extra white spaces and line breaks
        elif part.get('filename'):
            attachment_name = part['filename']
            break
        elif 'parts' in part:
            for sub_part in part['parts']:
                if sub_part['mimeType'] == 'text/plain':
                    body = base64.urlsafe_b64decode(sub_part['body']['data']).decode('utf-8').strip()
                    body = re.sub(r'[\n\r\s]+', ' ', body)  # remove extra white spaces and line breaks
                    break
                elif sub_part.get('filename'):
                    attachment_name = sub_part['filename']
                    break
        elif 'mimeType' in part and part['mimeType'].startswith('text/'):
            body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8').strip()
            body = re.sub(r'[\n\r\s]+', ' ', body)  # remove extra white spaces and line breaks
        if body:
            break

        if body and attachment_name:
            break

# Sanitize the sender and recipient addresses
sender = sanitize_address(sender)
to = ', '.join([sanitize_address(header['value']) for header in msg['payload']['headers'] if header['name'] == 'To'])
cc = ', '.join([sanitize_address(header['value']) for header in msg['payload']['headers'] if header['name'] == 'Cc'])

# Get the date and time of the message
timestamp = int(msg['internalDate'])/1000
date_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

# Parse and format the date and time
parsed_datetime = datetime.strptime(date_time, '%Y-%m-%d %H:%M:%S')
formatted_date = parsed_datetime.strftime('%B %d, %Y')
formatted_time = parsed_datetime.strftime('%I:%M %p')

# Format and print the email message details
print('-' * 70)
print(f"Sender: {sender}")
print(f"To: {to}")
print(f"Cc: {cc}")
print(f"Subject: {subject}")
print(f"Date: \"{formatted_date}\", Time: \"{formatted_time}\"")
if attachment_name:
    print(f"Attachment Name: {attachment_name}")
else:
    print("No attachment found.")

if body:
    # Replace line breaks with '\n'
    body = body.replace('\r\n', '\n').replace('\r', '\n')

    # Split body into sentences
    sentences = re.split('(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', body)

    # Loop through each sentence and add new lines after URLs, IP addresses, and email addresses
    formatted_body = ""
    urls = []
    ips = []
    for sentence in sentences:
        # Add new lines after URLs, IP addresses, and email addresses
        sentence = re.sub(r'(?P<url>https?://[^\s]+(?:\:\d+)?)(?=\s|$)', r'\g<url>\n', sentence)
        sentence = re.sub(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3}(?:\:\d+)?)(?=\s|$)', r'\g<ip>\n', sentence)
        sentence = re.sub(r'(?P<email>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?=\s|$)', r'\g<email>\n', sentence)
        formatted_body += sentence + "\n"
        
        # Save URLs and IPs
        urls.extend(re.findall(r'https?://[^\s]+(?:\:\d+)?', sentence))
        ips.extend(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}(?:\:\d+)?', sentence))
    
    print(f"Body:\n\n{formatted_body}\n")

    if urls or ips:
        print('-' * 70)
        print("URLs and IPs:")
        if urls:
            for url in urls:
                print(url)
        if ips:
            for ip in ips:
                print(ip)
        print('-' * 70)
else:
    print('-' * 70)
    print("SCRIPT FAILED!")
    print("No IPs or URLs were found. Please ask for more information from the user.")

def display_vendor_results(report):
    scans = report['scans']
    total_vendors = len(scans)

    # Separate the results into two groups: malware/suspicious and unrated/clean
    malware_suspicious_results = []
    unrated_clean_results = []

    for vendor, result in scans.items():
        detection = result['result']
        if 'malware' in detection.lower() or 'malicious' in detection.lower() or 'phishing' in detection.lower():
            malware_suspicious_results.append((vendor, detection))
        elif 'unrated' in detection.lower() or 'clean' in detection.lower():
            unrated_clean_results.append((vendor, detection))

    # Sort each group alphabetically
    malware_suspicious_results = sorted(malware_suspicious_results, key=lambda x: x[0].lower())
    unrated_clean_results = sorted(unrated_clean_results, key=lambda x: x[0].lower())

    # Calculate the positive detection count
    positive_count = sum(1 for _, result in scans.items() if result['detected'])

    # Display the results
    print(f'Positive Detections: {positive_count}/{total_vendors}')
    print('Scan results:')
    for vendor, detection in malware_suspicious_results + unrated_clean_results:
        print(f'Vendor: {vendor}\tDetection: {detection}')

# Upload URLs and IPs to VirusTotal
scan_results = {}
print("Virus Total Results")
for url in urls + ips:
    params = {'apikey': 'YOUR VT API KEY', 'resource': url}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    try:
        json_response = response.json()
    except:
        continue
    if json_response['response_code'] == 1:
        # URL or IP has been scanned before
        scan_results[url] = {'positives': json_response['positives'], 'total': json_response['total']}
        print(f"{url} has {json_response['positives']} positive detections out of {json_response['total']} total scans")
        display_vendor_results(json_response)
    elif json_response['response_code'] == -2:
        # URL or IP is still queued for scanning
        print(f"{url} is still queued for scanning")
    else:
        # URL or IP has not been scanned before
        print(f"{url} has not been scanned before")

        # Upload URL or IP for scanning
        params = {'apikey': 'YOUR VT API KEY', 'url': url}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        json_response = response.json()
        if json_response['response_code'] == 1:
            print(f"{url} has been queued for scanning")
        else:
            print(f"{url} upload failed")

        # Wait for the scan to complete
        scan_id = json_response['scan_id']
        params = {'apikey': 'YOUR VT API KEY', 'resource': scan_id}
        while True:
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
            json_response = response.json()
            if json_response['response_code'] == 1:
                scan_results[url] = {'positives': json_response['positives'], 'total': json_response['total']}
                print(f"{url} has {json_response['positives']} positive detections out of {json_response['total']} total scans")
                display_vendor_results(json_response)
                break
            else:
                time.sleep(10)

# Set up your OpenAI API credentials
print('-' * 70)
print("SecurityBot: How can I help you?")
openai.api_key = 'YOUR OPENAI KEY'

# Define a function to interact with ChatGPT-3
def ask_question(question, chat_log=[]):
    # Append the user's question to the chat log
    chat_log.append({'role': 'system', 'content': question})

    # Generate a response from ChatGPT-3
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=chat_log
    )

    # Extract the reply from the response
    reply = response.choices[0].message.content

    # Append the model's reply to the chat log
    chat_log.append({'role': 'system', 'content': reply})

    return reply

# Obtain the outputted results from the earlier code
positive_count = sum(result['positives'] for result in scan_results.values())
total_scans = sum(result['total'] for result in scan_results.values())
positive_detections = f'Positive Detections: {positive_count}/{total_scans}'

# Prepare the question to ask
question = f"Based on these results, would you deem this phishing URL or phishing email as malicious/suspicious? Yes or No?\n\n{positive_detections}"

# Example usage
chat_log = []  # Initialize an empty chat log

# Show the question
print("Question:", question)

# Ask the question and get a response
response = ask_question(question, chat_log)
print("SecurityBot:", response)

should_move_to_trash = False
if response.lower() == "yes":
    should_move_to_trash = True

# Iterate through all the messages
print('-' * 70)
print("SecurityBot moved the email to the Trash")
for message in messages:
    msg_id = message['id']
    msg = service.users().messages().get(userId='me', id=msg_id).execute()
    subject = next(h['value'] for h in msg['payload']['headers'] if h['name'] == 'Subject')
    timestamp = int(msg['internalDate'])/1000
    date_time = datetime.fromtimestamp(timestamp).strftime('%B %d, %Y %I:%M:%S %p')

    for part in msg['payload'].get('parts', []):
        if 'data' in part['body']:
            body = part['body']['data']
        else:
            continue
        decoded_body = base64.urlsafe_b64decode(body).decode('utf-8')
        for url in urls + ips:
            if url in decoded_body and url in scan_results and scan_results[url]['positives'] > 0:
                should_move_to_trash = True
                break

    if should_move_to_trash:
        service.users().messages().trash(userId='me', id=msg_id).execute()
        print(f'Subject "{subject}", Date: "{datetime.strptime(date_time, "%B %d, %Y %I:%M:%S %p").strftime("%B %d, %Y")}", Time: "{datetime.strptime(date_time, "%B %d, %Y %I:%M:%S %p").strftime("%I:%M %p")}" was moved to trash.')
    else:
        print(f'Subject "{subject}", Date: "{datetime.strptime(date_time, "%B %d, %Y %I:%M:%S %p").strftime("%B %d, %Y")}", Time: "{datetime.strptime(date_time, "%B %d, %Y %I:%M:%S %p").strftime("%I:%M %p")}" was not moved to trash.')

    # Sleep for 1 second to give the script some time to complete the operation
    time.sleep(1)
