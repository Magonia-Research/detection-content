import requests
from typing import List
import os
from github import Github

# Define constants
CANARY_URL = os.getenv('CANARY_URL')
CLOUD_IOCS_URL = os.getenv('CLOUD_IOCS_URL')
REPO_NAME = os.getenv('REPO_NAME')  # Format: "username/repo"
FILE_PATH = os.getenv('FILE_PATH')  # Path to the file in the repository
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')  # GitHub Personal Access Token

def fetch_canary_data() -> List[str]:
    response = requests.get(CANARY_URL)
    response.raise_for_status()
    
    canary_data = response.json()
    source_ips = []
    
    # Iterate over hits and filter out "AWS Internal"
    for hit in canary_data["history"]["hits"]:
        src_ip = hit["src_ip"]
        if src_ip != "AWS Internal":
            source_ips.append(src_ip)
    
    return source_ips

def fetch_cloud_iocs() -> List[str]:
    response = requests.get(CLOUD_IOCS_URL)
    response.raise_for_status()
    return response.text.splitlines()

def update_cloud_iocs(new_ips: List[str]) -> None:
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(REPO_NAME)
    
    contents = repo.get_contents(FILE_PATH)
    existing_ips = contents.decoded_content.decode("utf-8").splitlines()

    ips_to_add = []
    for ip in new_ips:
        if ip not in existing_ips:
            ips_to_add.append(ip)

    if ips_to_add:
        updated_content = "\n".join(existing_ips + ips_to_add)

        repo.update_file(
            path=FILE_PATH,
            message=f"Added {len(ips_to_add)} new IPs from canary tokens",
            content=updated_content,
            sha=contents.sha
        )
        print(f"Successfully added {len(ips_to_add)} new IPs to {FILE_PATH}")
    else:
        print("No new IPs to add.")

def main():
    try:
        canary_ips = fetch_canary_data()
        cloud_iocs = fetch_cloud_iocs()

        update_cloud_iocs(canary_ips)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
