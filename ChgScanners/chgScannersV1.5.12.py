import requests
import getpass
import logging
import xml.etree.ElementTree as ET
import pandas as pd
import os
import time
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import argparse
from requests.auth import HTTPBasicAuth

# Script version
SCRIPT_VERSION = "1.5.12"

def get_resource_path(filename):
    """Get the correct path for a resource file (handles PyInstaller bundling)."""
    if getattr(sys, 'frozen', False):
        # PyInstaller extracts files to a temporary directory (sys._MEIPASS)
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, filename)

# Configure logging to use the base directory
base_dir = os.path.dirname(os.path.abspath(__file__)) if not getattr(sys, 'frozen', False) else os.path.dirname(sys.executable)
log_file = os.path.join(base_dir, 'qualys_scanner_update.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TextRedirector:
    """Redirect print statements to a Tkinter text widget."""
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)
        self.text_widget.update()

    def flush(self):
        pass

class QualysAPIClient:
    def __init__(self, base_url, username):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = None
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'text/xml'})

    def set_password(self, password):
        """Set password (used by GUI)."""
        self.password = password
        logger.info("Password entered successfully.")

    def prompt_password(self):
        """Prompt for password in CLI mode."""
        self.password = getpass.getpass("Enter Qualys API password: ")
        logger.info("Password entered via CLI.")

    def make_api_call(self, endpoint, method='POST', data=None, retries=1):
        """Generic method to make API calls with retry."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        for attempt in range(retries + 1):
            try:
                response = self.session.request(
                    method,
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    data=data,
                    timeout=30
                )
                response.raise_for_status()
                logger.info(f"API call to {endpoint} successful. Status: {response.status_code}")
                return response.text
            except requests.exceptions.HTTPError as e:
                logger.error(f"Attempt {attempt + 1}/{retries + 1}: HTTP error occurred for {endpoint}: {e}")
                if response.status_code == 429:
                    logger.warning("Rate limit hit. Consider increasing batch delay or reducing batch size.")
                if response.status_code == 401:
                    logger.error("Authentication failed. Verify username and password.")
                elif response.status_code == 400:
                    logger.error(f"Bad request. Check XML payload. Response: {response.text}")
                elif response.status_code == 404:
                    logger.error("Resource not found. Verify endpoint or web app ID.")
                if attempt == retries:
                    raise
            except requests.exceptions.RequestException as e:
                logger.error(f"Attempt {attempt + 1}/{retries + 1}: Request failed for {endpoint}: {e}")
                if attempt == retries:
                    raise
            time.sleep(1)

def get_webapp_id(client, webapp_url):
    """Fetch web app ID using the search endpoint."""
    xml_payload = f"""<ServiceRequest>
        <filters>
            <Criteria field="url" operator="EQUALS">{webapp_url}</Criteria>
        </filters>
    </ServiceRequest>"""
    
    try:
        response_xml = client.make_api_call("/search/was/webapp", method="POST", data=xml_payload)
        root = ET.fromstring(response_xml)
        webapp_id = root.find(".//WebApp/id")
        if webapp_id is not None:
            logger.info(f"Found web app ID: {webapp_id.text} for URL: {webapp_url}")
            return webapp_id.text
        else:
            logger.error(f"No web app ID found for URL: {webapp_url}")
            raise ValueError(f"No web app found for URL: {webapp_url}")
    except ET.ParseError:
        logger.error("Failed to parse XML response from search endpoint.")
        raise
    except Exception as e:
        logger.error(f"Error fetching web app ID for URL {webapp_url}: {e}")
        raise

def get_scanner_details(client, webapp_id):
    """Fetch scanner details for a web app using GET /get/was/webapp/<id>."""
    endpoint = f"/get/was/webapp/{webapp_id}"
    try:
        response_xml = client.make_api_call(endpoint, method="GET", retries=1)
        logger.debug(f"Raw XML response for web app ID {webapp_id}: {response_xml}")
        root = ET.fromstring(response_xml)
        
        scanner_name = "Unknown"
        scanner_type = root.find(".//defaultScanner/type")
        if scanner_type is not None:
            if scanner_type.text == "EXTERNAL":
                scanner_name = "External"
            elif scanner_type.text == "INTERNAL":
                friendly_name = root.find(".//defaultScanner/friendlyName")
                scanner_name = friendly_name.text if friendly_name is not None else "Unknown Internal"
        
        scanner_tag_id = root.find(".//defaultScannerTags/list/Tag/id")
        if scanner_tag_id is not None and scanner_tag_id.text == "49516103":
            scanner_name = "Scanner Pool Tag (Int-Scanners)"
        
        logger.info(f"Retrieved scanner: {scanner_name} for web app ID: {webapp_id}")
        return scanner_name
    except ET.ParseError:
        logger.error(f"Failed to parse XML response for web app ID {webapp_id}")
        return "Unknown"
    except Exception as e:
        logger.error(f"Error fetching scanner details for web app ID {webapp_id}: {e}")
        return "Unknown"

def build_update_payload(selected_scanner):
    """Build XML payload for updating scanner based on user selection."""
    if selected_scanner == "External":
        return """<ServiceRequest>
            <data>
                <WebApp>
                    <defaultScanner>
                        <type>EXTERNAL</type>
                    </defaultScanner>
                </WebApp>
            </data>
        </ServiceRequest>"""
    elif selected_scanner == "Scanner Pool Tag (Int-Scanners)":
        return """<ServiceRequest>
            <data>
                <WebApp>
                    <defaultScannerTags>
                        <set>
                            <Tag>
                                <id>49516103</id>
                            </Tag>
                        </set>
                    </defaultScannerTags>
                </WebApp>
            </data>
        </ServiceRequest>"""
    else:
        return f"""<ServiceRequest>
            <data>
                <WebApp>
                    <defaultScanner>
                        <type>INTERNAL</type>
                        <friendlyName>{selected_scanner}</friendlyName>
                    </defaultScanner>
                </WebApp>
            </data>
        </ServiceRequest>"""

def update_scanner(client, webapp_id, selected_scanner):
    """Update the scanner for the given web app ID."""
    xml_payload = build_update_payload(selected_scanner)
    endpoint = f"/update/was/webapp/{webapp_id}"
    try:
        client.make_api_call(endpoint, method="POST", data=xml_payload, retries=1)
        logger.info(f"Successfully updated scanner to {selected_scanner} for web app ID: {webapp_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to update scanner for web app ID {webapp_id}: {e}")
        return False

def process_url(client, webapp_url, selected_scanner, current_url_index, total_urls):
    """Process a single URL and return result."""
    if not webapp_url:
        logger.warning(f"Skipping empty URL at index {current_url_index}/{total_urls}")
        return {
            'url': webapp_url,
            'existing_scanner': 'N/A',
            'new_assigned_scanner': selected_scanner,
            'queried_scanner': 'N/A'
        }
    
    try:
        logger.info(f"Processing URL {current_url_index}/{total_urls}: {webapp_url}")
        print(f"[INFO] Processing URL {current_url_index}/{total_urls}: {webapp_url}")
        webapp_id = get_webapp_id(client, webapp_url)
        existing_scanner = get_scanner_details(client, webapp_id)
        success = update_scanner(client, webapp_id, selected_scanner)
        time.sleep(2)
        queried_scanner = get_scanner_details(client, webapp_id) if success else "Update Failed"
        if queried_scanner == "Unknown" and success:
            logger.warning(f"Queried scanner is Unknown for {webapp_url}. Retrying after 5 seconds.")
            time.sleep(5)
            queried_scanner = get_scanner_details(client, webapp_id)
        logger.info(f"URL {current_url_index}/{total_urls} processed")
        print(f"[INFO] URL {current_url_index}/{total_urls} processed")
        return {
            'url': webapp_url,
            'existing_scanner': existing_scanner,
            'new_assigned_scanner': selected_scanner,
            'queried_scanner': queried_scanner
        }
    except Exception as e:
        logger.error(f"Error processing URL {current_url_index}/{total_urls} ({webapp_url}): {e}")
        print(f"[ERROR] Error processing URL {current_url_index}/{total_urls} ({webapp_url}): {e}")
        return {
            'url': webapp_url,
            'existing_scanner': 'Unknown',
            'new_assigned_scanner': selected_scanner,
            'queried_scanner': 'Error'
        }

def process_csv(client, selected_scanner, batch_size=10, batch_delay=5):
    """Process URLs from target.csv in batches."""
    base_dir = os.path.dirname(os.path.abspath(__file__)) if not getattr(sys, 'frozen', False) else os.path.dirname(sys.executable)
    csv_file = os.path.join(base_dir, 'target.csv')
    try:
        logger.info(f"Looking for target.csv at: {csv_file}")
        print(f"[INFO] Looking for target.csv at: {csv_file}")
        df = pd.read_csv(csv_file)
        if 'url' not in df.columns:
            raise ValueError("CSV must contain a 'url' column.")
        
        results = []
        urls = [str(url).strip() for url in df['url']]
        total_urls = len(urls)
        logger.info(f"Processing {total_urls} URLs in batches of {batch_size} with {batch_delay}s delay between batches.")
        print(f"[INFO] Processing {total_urls} URLs in batches of {batch_size} with {batch_delay}s delay between batches.")
        
        for i in range(0, total_urls, batch_size):
            batch_urls = urls[i:i + batch_size]
            logger.info(f"Processing batch {i // batch_size + 1} with {len(batch_urls)} URLs")
            print(f"[INFO] Processing batch {i // batch_size + 1} with {len(batch_urls)} URLs")
            
            for j, webapp_url in enumerate(batch_urls, start=i + 1):
                result = process_url(client, webapp_url, selected_scanner, j, total_urls)
                results.append(result)
            
            if i + batch_size < total_urls:
                logger.info(f"Waiting {batch_delay} seconds before next batch...")
                print(f"[INFO] Waiting {batch_delay} seconds before next batch...")
                time.sleep(batch_delay)
        
        output_csv = os.path.join(base_dir, 'scanner_update_results.csv')
        results_df = pd.DataFrame(results, columns=['url', 'existing_scanner', 'new_assigned_scanner', 'queried_scanner'])
        results_df.to_csv(output_csv, index=False)
        logger.info(f"Results written to {output_csv}")
        print(f"[INFO] Results written to {output_csv}")
        
        return results
    except FileNotFoundError:
        logger.error(f"CSV file not found: {csv_file}")
        raise
    except pd.errors.EmptyDataError:
        logger.error("CSV file is empty.")
        raise
    except Exception as e:
        logger.error(f"Error processing CSV: {e}")
        raise

def print_results(results):
    """Print summary of processing results."""
    print("\nProcessing Summary:")
    logger.info("\nProcessing Summary:")
    print("-" * 50)
    logger.info("-" * 50)
    success_count = 0
    for result in results:
        print(f"URL: {result['url']}")
        logger.info(f"URL: {result['url']}")
        print(f"Existing Scanner: {result['existing_scanner']}")
        logger.info(f"Existing Scanner: {result['existing_scanner']}")
        print(f"New Assigned Scanner: {result['new_assigned_scanner']}")
        logger.info(f"New Assigned Scanner: {result['new_assigned_scanner']}")
        print(f"Queried Scanner: {result['queried_scanner']}")
        logger.info(f"Queried Scanner: {result['queried_scanner']}")
        status = 'SUCCESS' if result['new_assigned_scanner'] == result['queried_scanner'] else 'FAILED'
        print(f"Status: {status}")
        logger.info(f"Status: {status}")
        print("-" * 50)
        logger.info("-" * 50)
        if result['new_assigned_scanner'] == result['queried_scanner']:
            success_count += 1
    
    print(f"Total URLs processed: {len(results)}")
    logger.info(f"Total URLs processed: {len(results)}")
    print(f"Successful updates: {success_count}")
    logger.info(f"Successful updates: {success_count}")
    print(f"Failed updates: {len(results) - success_count}")
    logger.info(f"Failed updates: {len(results) - success_count}")
    print(f"Results saved to scanner_update_results.csv")
    logger.info(f"Results saved to scanner_update_results.csv")

def run_processing(username, password, selected_scanner, output_text, status_label):
    """Run the processing logic in a separate thread."""
    try:
        if not username:
            raise ValueError("Username cannot be empty.")
        
        logger.info(f"Username entered: {username}")
        print(f"[INFO] Username entered: {username}")
        
        base_url = "https://qualysapi.qualys.eu/qps/rest/3.0"
        client = QualysAPIClient(base_url, username)
        client.set_password(password)
        
        results = process_csv(client, selected_scanner, batch_size=10, batch_delay=5)
        print_results(results)
        
        logger.info("Script completed successfully.")
        print("[INFO] Script completed successfully.")
        status_label.config(text="Completed", foreground="green")
    except Exception as e:
        logger.error(f"Script failed: {e}")
        print(f"[ERROR] Script failed: {e}")
        status_label.config(text=f"Error: {e}", foreground="red")

def main_gui():
    """Launch the Tkinter GUI."""
    root = tk.Tk()
    root.title(f"Qualys Scanner Update v{SCRIPT_VERSION}")
    root.geometry("600x400")
    
    # Set window icon
    icon_path = get_resource_path('qualys.ico')
    logger.info(f"Attempting to load icon from: {icon_path} (absolute path: {os.path.abspath(icon_path)})")
    print(f"[INFO] Attempting to load icon from: {icon_path} (absolute path: {os.path.abspath(icon_path)})")
    
    # Use iconbitmap with explicit path check
    try:
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
            logger.info("Successfully set iconbitmap")
            print("[INFO] Successfully set iconbitmap")
        else:
            logger.warning(f"Icon file not found: {icon_path}")
            print(f"[WARNING] Icon file not found: {icon_path}")
    except tk.TclError as e:
        logger.error(f"Failed to set iconbitmap: {e}. Using default icon. Ensure qualys.ico is a valid .ico file with 16x16 and 32x32 sizes.")
        print(f"[ERROR] Failed to set iconbitmap: {e}. Using default icon. Ensure qualys.ico is a valid .ico file with 16x16 and 32x32 sizes.")
    
    # Input frame
    input_frame = ttk.Frame(root, padding="10")
    input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    ttk.Label(input_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
    username_entry = ttk.Entry(input_frame)
    username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
    
    ttk.Label(input_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
    password_entry = ttk.Entry(input_frame, show="*")
    password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
    
    ttk.Label(input_frame, text="Scanner:").grid(row=2, column=0, sticky=tk.W, pady=5)
    scanners = [
        "External",
        "Scanner Pool Tag (Int-Scanners)",
        "QualysAzureScannerNA02",
        "ClaranetAppliance1",
        "CAPAppliance4",
        "CAPAppliance5",
        "CAPAppliance6",
        "CAPAppliance7"
    ]
    scanner_combo = ttk.Combobox(input_frame, values=scanners, state="readonly")
    scanner_combo.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
    scanner_combo.set(scanners[0])
    
    # Output frame
    output_frame = ttk.Frame(root, padding="10")
    output_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    output_text = scrolledtext.ScrolledText(output_frame, height=10, wrap=tk.WORD)
    output_text.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    # Redirect print to text widget
    sys.stdout = TextRedirector(output_text)
    
    # Status label
    status_label = ttk.Label(root, text="Ready", foreground="blue")
    status_label.grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
    
    # Start button
    def start_processing():
        username = username_entry.get()
        password = password_entry.get()
        scanner = scanner_combo.get()
        if not username or not password or not scanner:
            status_label.config(text="Please fill all fields", foreground="red")
            return
        status_label.config(text="Processing...", foreground="orange")
        start_button.config(state="disabled")
        threading.Thread(
            target=run_processing,
            args=(username, password, scanner, output_text, status_label),
            daemon=True
        ).start()
    
    start_button = ttk.Button(input_frame, text="Start Processing", command=start_processing)
    start_button.grid(row=3, column=0, columnspan=2, pady=10)
    
    # Configure grid weights
    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)
    input_frame.columnconfigure(1, weight=1)
    output_frame.columnconfigure(0, weight=1)
    
    root.mainloop()

def main_cli():
    """Original CLI main function."""
    logger.info(f"Starting Qualys Scanner Update Script v{SCRIPT_VERSION}")
    print(f"[INFO] Starting Qualys Scanner Update Script v{SCRIPT_VERSION}")
    
    username = input("Enter Qualys API username: ")
    if not username:
        logger.error("Username cannot be empty.")
        print("[ERROR] Username cannot be empty.")
        return
    
    logger.info(f"Username entered: {username}")
    
    base_url = "https://qualysapi.qualys.eu/qps/rest/3.0"
    client = QualysAPIClient(base_url, username)
    
    try:
        client.prompt_password()
        selected_scanner = prompt_scanner_selection()
        results = process_csv(client, selected_scanner, batch_size=10, batch_delay=5)
        print_results(results)
        logger.info("Script completed successfully.")
        print("[INFO] Script completed successfully.")
    except Exception as e:
        logger.error(f"Script failed: {e}")
        print(f"[ERROR] Script failed: {e}")
        raise

def prompt_scanner_selection():
    """Prompt user to select a scanner and return the selection (CLI)."""
    scanners = [
        "External",
        "Scanner Pool Tag (Int-Scanners)",
        "QualysAzureScannerNA02",
        "ClaranetAppliance1",
        "CAPAppliance4",
        "CAPAppliance5",
        "CAPAppliance6",
        "CAPAppliance7"
    ]
    print("\nAvailable scanners:")
    for idx, scanner in enumerate(scanners, 1):
        print(f"{idx}. {scanner}")
    
    while True:
        try:
            choice = int(input("Select a scanner (enter the number): "))
            if 1 <= choice <= len(scanners):
                selected_scanner = scanners[choice - 1]
                logger.info(f"User selected scanner: {selected_scanner}")
                return selected_scanner
            else:
                print(f"Please enter a number between 1 and {len(scanners)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Qualys Scanner Update Script")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    args = parser.parse_args()
    
    if args.cli:
        main_cli()
    else:
        main_gui()