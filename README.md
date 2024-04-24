# Phishing Analyzer

## how to download eml files

Log in to your Gmail account.
Open the email you want to use as a sample.
Click on the three dots (More options) in the top right corner of the email.
Select "Download message."
Save the downloaded .eml file to a location on your computer.



## Dependencies

Ensure you have Python installed on your system.

## How to Run

1. Clone the project to your local machine.

2. Navigate to the project directory.

3. Install dependencies:

    ```bash
    pip install whois beautifulsoup4 requests
    ```

4. Run the analyzer:

    ```bash
    python anti_phishing_analyzer.py --email_path path/to/your/email.eml
    ```

Replace `path/to/your/email.eml` with the path to the phishing email you want to analyze.

The program will display information about the email contact, Top-Level Domain (TLD) analysis, and WHOIS lookup.
