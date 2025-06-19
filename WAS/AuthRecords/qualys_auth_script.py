import requests
import xml.etree.ElementTree as ET
import csv
import getpass
from urllib.parse import urljoin

# Base URL for Qualys API
BASE_URL = "https://qualysapi.qualys.eu/qps/rest/3.0"

# XML payload for fetching auth record IDs
AUTH_RECORD_XML = """<ServiceRequest>
    <filters>
        <Criteria field="contents" operator="EQUALS">FORM_SELENIUM</Criteria>
    </filters>
</ServiceRequest>"""

def get_credentials():
    """Prompt user for credentials."""
    user_id = input("Enter your Qualys user ID: ")
    password = getpass.getpass("Enter your Qualys password: ")
    return user_id, password

def make_api_request(url, method, auth, headers, data=None):
    """Make an API request and return the response."""
    try:
        if method.lower() == "post":
            response = requests.post(url, auth=auth, headers=headers, data=data)
        elif method.lower() == "get":
            response = requests.get(url, auth=auth, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        print(f"API request failed: {e}")
        return None

def parse_auth_records(response_text):
    """Parse XML response to extract auth record IDs and names."""
    records = []
    try:
        root = ET.fromstring(response_text)
        for record in root.findall(".//WebAppAuthRecord"):
            record_id = record.find("id").text.strip() if record.find("id") is not None else ""
            name_element = record.find("name")
            record_name = name_element.text.strip() if name_element is not None and name_element.text else ""
            records.append({"id": record_id, "name": record_name})
    except ET.ParseError as e:
        print(f"Failed to parse XML: {e}")
    return records

def save_to_csv(data, filename, fieldnames):
    """Save data to a CSV file."""
    try:
        with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"Data saved to {filename}")
    except IOError as e:
        print(f"Failed to write to CSV: {e}")

def parse_auth_record_details(response_text):
    """Parse XML response to extract auth record details."""
    try:
        root = ET.fromstring(response_text)
        record = root.find(".//WebAppAuthRecord")
        if record is None:
            return None
        
        record_id = record.find("id").text.strip() if record.find("id") is not None else ""
        name_element = record.find("name")
        record_name = name_element.text.strip() if name_element is not None and name_element.text else ""
        
        # Type is not explicitly provided in the example; assuming it's related to contents
        record_type = "FORM_SELENIUM"  # Based on the filter used in the first request
        
        selenium_script = record.find(".//seleniumScript/name")
        script_name = selenium_script.text.strip() if selenium_script is not None and selenium_script.text else ""
        
        return {
            "id": record_id,
            "name": record_name,
            "type": record_type,
            "script_name": script_name
        }
    except ET.ParseError as e:
        print(f"Failed to parse XML: {e}")
        return None

def main():
    # Get user credentials
    user_id, password = get_credentials()
    auth = (user_id, password)
    headers = {"Content-Type": "text/xml"}

    # Step 1: Fetch auth record IDs
    search_url = urljoin(BASE_URL, "search/was/webappauthrecord")
    response = make_api_request(search_url, "post", auth, headers, AUTH_RECORD_XML)
    
    if response is None:
        print("Failed to fetch auth records. Exiting.")
        return
    
    # Parse and save auth records to CSV
    auth_records = parse_auth_records(response.text)
    if not auth_records:
        print("No auth records found or parsing failed. Exiting.")
        return
    
    save_to_csv(auth_records, "auth_records.csv", ["id", "name"])
    
    # Step 2: Fetch details for each auth record
    details = []
    for record in auth_records:
        record_id = record["id"]
        details_url = urljoin(BASE_URL, f"get/was/webappauthrecord/{record_id}")
        response = make_api_request(details_url, "get", auth, headers)
        
        if response is None:
            print(f"Failed to fetch details for auth record ID {record_id}")
            continue
        
        detail = parse_auth_record_details(response.text)
        if detail:
            details.append(detail)
    
    # Save auth record details to CSV
    if details:
        save_to_csv(details, "auth_record_details.csv", ["id", "name", "type", "script_name"])
    else:
        print("No auth record details retrieved.")

if __name__ == "__main__":
    main()