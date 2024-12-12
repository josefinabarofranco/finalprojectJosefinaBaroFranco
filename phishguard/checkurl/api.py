import requests
import base64
from django.conf import settings


def check_url_with_virustotal(url):
    api_key = settings.VIRUSTOTAL_API_KEY
    headers = {
        "x-apikey": api_key
    }

    # Base64 encode the URL (as required by VirusTotal)
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # Prepare the payload with the encoded URL
    payload = {
        "url": encoded_url
    }

    # Send POST request to VirusTotal API
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=payload)

    # Check the response
    if response.status_code == 200:
        try:
            json_response = response.json()

            # Check if the 'data' and 'attributes' keys exist in the response
            if 'data' in json_response and 'attributes' in json_response['data']:
                scan_id = json_response["data"]["id"]
                report_url = f"https://www.virustotal.com/gui/url/{scan_id}"

                # Check if the 'last_analysis_stats' and 'malicious' keys exist
                last_analysis_stats = json_response["data"]["attributes"].get("last_analysis_stats", {})
                positives = last_analysis_stats.get("malicious", 0)

                if positives > 0:
                    return {"status": "suspicious", "scan_id": scan_id, "report_url": report_url,
                            "positives": positives}
                else:
                    return {"status": "safe", "scan_id": scan_id, "report_url": report_url, "positives": positives}
            else:
                return {"status": "error", "message": "Invalid response format from VirusTotal."}

        except KeyError as e:
            return {"status": "error", "message": f"Missing key in response: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"An unexpected error occurred: {str(e)}"}

    else:
        return {"status": "error", "message": response.text}
