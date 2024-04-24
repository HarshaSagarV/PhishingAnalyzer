from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import requests
import re
import whois

# ANSI escape code for changing text color
class Color:
    BLACK = '\033[30m'
    GREEN_BG = '\033[42m'
    END = '\033[0m'  # Reset color

# Function to parse .eml file
def parse_eml_file(file_path):
    with open(file_path, 'rb') as file:
        # Parse the .eml file
        msg = BytesParser(policy=policy.default).parse(file)
        return msg

# Function to extract the top-level domain (TLD) from the 'from_address'
def extract_tld(from_address):
    # Use regular expressions to find the TLD
    match = re.search(r'@([a-zA-Z0-9.-]+)\b', from_address)
    if match:
        tld = match.group(1)  # Return the matched TLD
        # Remove any additional characters after the TLD (e.g., ">")
        tld = re.sub(r'[^\w\s.]', '', tld)
        return tld
    return None  # Return None if no match is found

# Function to perform a WHOIS lookup on the given domain
def perform_whois_lookup(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except whois.parser.PywhoisError as e:
        print(f"WHOIS lookup failed for domain {domain}: {e}")
        return None

# Function to fetch URLs from a website
def get_urls_from_website(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses

        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)

        return [link['href'] for link in links]
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return []

# Function to analyze links in HTML content
def analyze_links(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    links = soup.find_all('a', href=True)

    for link in links:
        url = link['href']
        if url.startswith(('http://', 'https://')):
            if url.startswith('http://'):
                print(f"Found an insecure link: {url}")
                # You can take further action here, such as marking or reporting the link.

            try:
                response = requests.head(url, allow_redirects=True, timeout=5)
                if response.status_code == 200:
                    print(f"{Color.BLACK}{Color.GREEN_BG}Secure link: {url}{Color.END}")
                else:
                    print(f"Insecure link: {url}")
            except requests.RequestException:
                print(f"Unable to verify link: {url}")
        else:
            print(f"Invalid URL: {url}")

# Example usage
eml_file_path = r"C:\Users\naveena\OneDrive\Desktop\“intern”_ Transamerica - Technology Intern (Summer 2024) and more.eml"
parsed_email = parse_eml_file(eml_file_path)

# Displaying email contact information
print("----------------------------")
print(f"\n{Color.BLACK}{Color.GREEN_BG}\nEmail Contact Information:{Color.END}")
print("Subject:", parsed_email.get('subject'))
print("From:", parsed_email.get('from'))
print("To:", parsed_email.get('to'))
print("Date:", parsed_email.get('date'))

# Extract and display the Top-Level Domain (TLD)
from_address = parsed_email.get('from')
tld = extract_tld(from_address)
print(f"{Color.BLACK}{Color.GREEN_BG}Top-Level Domain (TLD): {tld}{Color.END}")
# print(f"\n{Color.BLACK}{Color.GREEN_BG}\nTop-Level Domain (TLD):{Color.END}")

# Perform WHOIS lookup if TLD is extracted
if tld:
    whois_info = perform_whois_lookup(tld)
    if whois_info:
        print(f"\n{Color.BLACK}{Color.GREEN_BG}\nWHOIS Information:{Color.END}")
        print(whois_info)

# Fetch URLs from the specified website
website_url = 'https://openphish.com/'
urls_on_website = get_urls_from_website(website_url)

# Check if TLD is present in the extracted URLs
if tld and any(tld in url for url in urls_on_website):
    print(f"\n{Color.BLACK}{Color.GREEN_BG}ALERT: TLD found in the website URLs!{Color.END}")
else:print(f"\n{Color.BLACK}{Color.GREEN_BG}This TLD is not present in Database !{Color.END}")

print("----------------------------")

# Extracting and analyzing links
html_content = str(parsed_email.get_body(preferencelist=('html')).get_content())
print(f"{Color.BLACK}{Color.GREEN_BG}Link Analysis:{Color.END}")
analyze_links(html_content)
print("----------------------------")
