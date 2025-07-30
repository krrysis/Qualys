import requests
import xml.etree.ElementTree as ET
import csv

# === Config ===
USERNAME = input("Enter your Qualys username: ")
PASSWORD = input("Enter your Qualys password: ")

BASE_URL = "https://qualysapi.qualys.eu/qps/rest/2.0"
HEADERS = {
    "Content-Type": "application/xml",
    "Accept": "application/xml"
}

# === Functions ===

def get_all_tags():
    """Retrieve all tags with pagination."""
    tags = []
    start_offset = 1
    page_size = 100

    while True:
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<ServiceRequest>
  <preferences>
    <startFromOffset>{start_offset}</startFromOffset>
    <limitResults>{page_size}</limitResults>
  </preferences>
</ServiceRequest>"""

        url = f"{BASE_URL}/search/am/tag"
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=HEADERS, data=payload)
        response.raise_for_status()

        root = ET.fromstring(response.text)
        
        for tag_elem in root.findall(".//Tag"):
            tag_id = tag_elem.findtext("id")
            tag_name = tag_elem.findtext("name")
            tags.append({"id": tag_id, "name": tag_name})

        has_more = root.findtext(".//hasMoreRecords")
        if has_more and has_more.lower() == 'true':
            start_offset += page_size
        else:
            break

    return tags


def get_asset_count_for_tag(tag_id):
    """Get asset count for a given tag ID (POST method with XML filter)."""
    url = f"{BASE_URL}/count/am/asset"
    payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<ServiceRequest>
  <filters>
    <Criteria field="tagId" operator="EQUALS">{tag_id}</Criteria>
  </filters>
</ServiceRequest>"""
    
    response = requests.post(url, auth=(USERNAME, PASSWORD), headers=HEADERS, data=payload)
    response.raise_for_status()

    root = ET.fromstring(response.text)
    count_text = root.findtext(".//count")
    return int(count_text) if count_text and count_text.isdigit() else 0


# === Main Execution ===

def main():
    print("Fetching all tags...")
    tags = get_all_tags()
    print(f"Total tags fetched: {len(tags)}")

    with open("qualys_tags_asset_counts.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Tag ID", "Tag Name", "Asset Count"])
        
        for tag in tags:
            asset_count = get_asset_count_for_tag(tag["id"])
            print(f"Tag: {tag['name']} (ID: {tag['id']}) -> Asset Count: {asset_count}")
            writer.writerow([tag["id"], tag["name"], asset_count])

    print("CSV file 'qualys_tags_asset_counts.csv' created successfully.")

if __name__ == "__main__":
    main()