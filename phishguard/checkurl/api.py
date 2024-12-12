import requests
import base64
from django.conf import settings


def check_url_with_virustotal(url):
    api_key = settings.VIRUSTOTAL_API_KEY
    headers = {
        "x-apikey": api_key
    }

    url = url.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    print(f"Encoded URL: {encoded_url}")

    payload = {"url": encoded_url}

    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, json=payload)

    if response.status_code == 200:
        try:
            json_response = response.json()

            if 'data' in json_response and 'id' in json_response['data']:
                scan_id = json_response["data"]["id"]
                report_url = f"https://www.virustotal.com/gui/url/{scan_id}"

                analysis_response = requests.get(f"https://www.virustotal.com/api/v3/urls/{scan_id}", headers=headers)

                if analysis_response.status_code == 200:
                    analysis_json = analysis_response.json()

                    if 'data' in analysis_json and 'attributes' in analysis_json['data']:
                        last_analysis_stats = analysis_json["data"]["attributes"].get("last_analysis_stats", {})
                        positives = last_analysis_stats.get("malicious", 0)

                        if positives > 0:
                            return {"status": "suspicious", "scan_id": scan_id, "report_url": report_url,
                                    "positives": positives}
                        else:
                            return {"status": "safe", "scan_id": scan_id, "report_url": report_url,
                                    "positives": positives}
                    else:
                        return {"status": "error", "message": "Invalid response format from VirusTotal analysis."}
                else:
                    return {"status": "error", "message": "Failed to retrieve analysis details from VirusTotal."}

            else:
                return {"status": "error", "message": "Invalid response format from VirusTotal."}
        except Exception as e:
            return {"status": "error", "message": f"Error parsing response: {str(e)}"}
    elif response.status_code == 400:
        return {"status": "error", "message": "Unable to process the URL. It might be malformed or unsupported."}
    else:
        return {"status": "error", "message": response.text}
