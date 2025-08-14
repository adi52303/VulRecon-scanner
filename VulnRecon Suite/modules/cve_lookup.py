# modules/cve_lookup.py
import os
import time
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _pick_cvss(cve: dict):
    
    metrics = cve.get("metrics", {}) if isinstance(cve, dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or data.get("baseSeverity".lower())
            return (score, severity)
    return (None, None)

def fetch_cves(keyword: str, max_results: int = 8, timeout: int = 12) -> list[dict]:
    """
    Query NVD for CVEs matching a keyword (e.g., 'Apache 2.4.6').
    Returns list of dicts: {cve_id, description, score, severity, published, url}
    """
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key  

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(max_results)
        
    }

    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=timeout)
        
        if r.status_code == 429:
            time.sleep(1.5)
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=timeout)

        r.raise_for_status()
        data = r.json()
    except Exception:
        return []

    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descs = cve.get("descriptions", []) or []
        en_desc = next((d.get("value") for d in descs if d.get("lang") == "en"), None) or (descs[0].get("value") if descs else "")
        score, severity = _pick_cvss(cve)
        published = cve.get("published")
        
        refs = cve.get("references", []) or []
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else (refs[0].get("url") if refs else "")
        out.append({
            "cve_id": cve_id,
            "description": en_desc,
            "score": score,
            "severity": severity,
            "published": published,
            "url": url
        })
    
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}
    out.sort(key=lambda x: (sev_rank.get((x.get("severity") or "").upper(), 0), x.get("score") or 0, x.get("published") or ""), reverse=True)
    return out
