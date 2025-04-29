import requests
import time
import pandas as pd

URL = ""
CLIENT_ID = ""
CLIENT_SECRET = ""

def token_generation():
    try:
        token_url = URL + "auth/oauth/token"
        auth_data = {
            'client_secret': CLIENT_SECRET,
            'grant_type': 'client_credentials',
            'client_id': CLIENT_ID
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        response = requests.post(token_url, data=auth_data, headers=headers, verify=True)

        if response.status_code == 200:
            access_token = response.json().get('access_token')
            if access_token:
                return access_token
            else:
                print("Error: No access token returned in the response.")
        else:
            print(f"Failed to obtain access token: {response.status_code} - {response.text}")
    except Exception as e:
        print("Error during token generation:", str(e))
    return None

def handle_retry(response, retry_count=3):
    retry_attempts = 0
    while retry_attempts < retry_count:
        if response.status_code in [401, 407] or "invalid_token" in response.text.lower():
            print("Attempting token regeneration...")
            new_token = token_generation()
            if new_token:
                return new_token
        retry_attempts += 1
        time.sleep(2)
    return None

def fetch_clients(access_token, partner_id, base_url):
    clients = {}
    page = 1

    while True:
        try:
            headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
            url = f"{base_url}api/v2/tenants/{partner_id}/clients/search?pageNo={page}&pageSize=100"

            response = requests.get(url, headers=headers, verify=True)

            if response.status_code in [401, 407] or "invalid_token" in response.text.lower():
                print("Token invalid or expired. Generating a new token...")
                access_token = handle_retry(response)
                if not access_token:
                    print("Unable to generate new token.")
                    break
                continue

            elif response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                for client in results:
                    client_id = client.get("uniqueId", "NA")
                    client_name = client.get("name", "NA")
                    if client_id != "NA" and client_name != "NA":
                        clients[client_id] = client_name

                total_pages = data.get('totalPages', 1)
                if page >= total_pages:
                    break
                page += 1
            else:
                print(f"Failed to get clients: {response.status_code}")
                break
        except Exception as e:
            print("Error fetching clients:", str(e))
            break

    print(f"Total clients fetched: {len(clients)}")
    return clients

# Function to get NOC Name for a given client
def get_noc_name(access_token, partner_id, client_id, client_name, base_url):
    try:
        auth_header = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
        noc_details_url = base_url + f"api/v2/tenants/{partner_id}/clients/{client_id}"
        response = requests.get(noc_details_url, headers=auth_header, verify=True)

        # Handle retry logic
        if response.status_code in [401, 407]:
            access_token = handle_retry(response)
            if not access_token:
                return "N/A"
            response = requests.get(noc_details_url, headers=auth_header, verify=True)

        response.raise_for_status()
        noc_data = response.json()
        noc_details = noc_data.get('nocDetails', {})
        return noc_details.get('name', 'N/A')
    except requests.exceptions.RequestException as e:
        print(f"Error fetching NOC details for client {client_name}: {e}")
        return "N/A"
    except Exception as e:
        print(f"Unexpected error fetching NOC details for client {client_name}: {e}")
        return "N/A"

def fetch_devices(access_token, client_id, client_name, partner_id, base_url):
    devices = {}

    try:
        auth_header = {'Authorization': 'Bearer ' + access_token, 'Content-Type': 'application/json'}
        devices_url = f"{base_url}/api/v2/tenants/{client_id}/resources/minimal"
        response = requests.get(devices_url, headers=auth_header, verify=True)

        if response.status_code in [401, 407]:
            access_token = handle_retry(response)
            if not access_token:
                return [], False, []
            response = requests.get(devices_url, headers=auth_header, verify=True)

        response.raise_for_status()
        devices_data = response.json()

        if response.status_code == 200 and isinstance(devices_data, list):
            for device in devices_data:
                device_name = device.get("hostName", 'NA')
                device_id = device.get("id", "NA")
                if device_id and device_name:
                    devices[device_name] = device_id
        else:
            print(f"Error: {response.status.code}")
                
    except requests.exceptions.RequestException as e:
        print(f"Error fetching devices for {client_name}: {e}")
    except Exception as e:
        print("Error fetching device IDs:", str(e))

    return devices

def get_device_details(access_token, client_id, client_name, device_id, base_url):
    
    tagvalue_1 = "NA"
    tagvalue_2= "NA"
    auth_header = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    device_url = base_url + f"api/v2/tenants/{client_id}/resources/{device_id}"
    response = requests.get(device_url, headers=auth_header, verify=True)

    try:
        if response.status_code in [401, 407]:
            access_token = handle_retry(response)
            if not access_token:
                return False, None
            response = requests.get(device_url, headers=auth_header, verify=True)

        response.raise_for_status()
        if response.status_code == 200:
            device_data = response.json()
            ip = device_data.get("ipAddress", "NA")
            model = device_data.get("model", "NA")
            status = device_data.get("status", "NA")
            gnrlinfo = device_data.get("generalInfo")
            make = gnrlinfo.get('make', 'No value available') if gnrlinfo else 'No value available'
            resourceType = gnrlinfo.get('resourceType', 'No value available') if gnrlinfo else 'No value available'
            tags = device_data.get('tags', [])

            if tags != 'No Tags' and isinstance(tags, list):
                for tag in tags:
                    tagname = tag.get('name', 'NA')
                    tagvalue = tag.get('value', 'NA')
                    if tagname == "Service - Partner Scope":
                        tagvalue_1 = tagvalue
                    elif tagname == "SKU Device - Partner Scope":
                        tagvalue_2 = tagvalue
            else:
                tagvalue_1 = "No tag assigned"
                tagvalue_2 = "No tag assigned"
            return ip, model, make, tagvalue_1, tagvalue_2, resourceType, status
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching devices for {client_name}: {e}")
    except Exception as e:
        print("Error fetching device IDs:", str(e))
        
def main():
    access_token = token_generation()
    if not access_token:
        print("Failed to generate access token. Exiting.")
        return

    partners = {}

    all_devices_info = []  # List to store all the data

    for partner_id, partner_name in partners.items():
        print(f"\nProcessing Partner: {partner_name}")

        clients = fetch_clients(access_token, partner_id, URL)

        for client_name, client_id in clients.items():
            noc_name = get_noc_name(access_token, partner_id, client_id, client_name, URL)
            if noc_name in [""]:
                print(f"Fetching devices for client: {client_name}")

                devices = fetch_devices(access_token, client_id, client_name, partner_id, URL)

                if not devices:
                    print(f"No devices found for client: {client_name}")
                    continue

                for device_name, device_id in devices.items():
                    device_details = get_device_details(access_token, client_id, client_name, device_id, URL)

                    if device_details:
                        ip, model, make, tagvalue_1, tagvalue_2, resourceType, status = device_details
                        device_info = {
                            "Partner Name": partner_name,
                            "Client Name": client_name,
                            "Resource Name": device_name,
                            "Ip Address": ip,
                            "Service - Partner Scope": tagvalue_1,
                            "SKU Device - Partner Scope": tagvalue_2,
                            "Make": make,
                            "Model": model,
                            "Device State": status,
                            "Type": resourceType
                        }
                        all_devices_info.append(device_info)

    # After all data collected, export to Excel
    if all_devices_info:
        df = pd.DataFrame(all_devices_info)
        df.to_excel("client_devices_report.xlsx", index=False)
        print("\nExcel file 'client_devices_report.xlsx' created successfully.")
    else:
        print("No device data found to export.")

if __name__ == "__main__":
    main()
