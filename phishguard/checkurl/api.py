import requests
from django.conf import settings

def check_url_with_virustotal(url):
    api_key = settings.VIRUSTOTAL_API_KEY
    headers = {"x-apikey": api_key}
    payload = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=payload)

    if response.status_code == 200:
        json_response = response.json()
        scan_id = json_response["data"]["id"]
        report_url = f"https://www.virustotal.com/gui/url/{scan_id}"
        return {"status": "success", "scan_id": scan_id, "report_url": report_url}
    else:
        return {"status": "error", "message": response.text}
