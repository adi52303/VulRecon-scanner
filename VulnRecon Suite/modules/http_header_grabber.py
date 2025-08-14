
import requests

def grab_http_headers(url):
    
    print(f"\n[+] Fetching HTTP headers for {url}...\n")
    
    try:
        # Add default scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # Send HTTP request (allow redirects)
        response = requests.get(url, timeout=5, allow_redirects=True)

        # Display headers
        for header, value in response.headers.items():
            print(f"{header}: {value}")

        return dict(response.headers)

    except requests.exceptions.Timeout:
        print("[!] Connection timed out.")
    except requests.exceptions.ConnectionError:
        print("[!] Failed to connect to target.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")

    return None
