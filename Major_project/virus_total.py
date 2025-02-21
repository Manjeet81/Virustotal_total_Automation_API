import requests

api_key = "dda80dd5df8c5c8e008670e2d525649ae678f310af6e5a6351d1ab5d9a6a357b"  # Replace with your VirusTotal API key


def link_scan():
    url = "https://www.virustotal.com/api/v3/domains/coachuaeoutlet.com"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    extracted_data =response.json()

    if "data" in extracted_data:
        site_result = extracted_data["data"]
        site_name=site_result["id"]
        scaned_result = site_result["attributes"]["last_analysis_stats"]
        malicious = str(scaned_result["malicious"])
        suspicious = str(scaned_result["suspicious"])
        undetected = str(scaned_result["undetected"])
        harmless = str(scaned_result["harmless"])
        return site_name,malicious,suspicious,undetected,harmless
    else:
            raise Exception("data is unable to fetch Try angin")

def main():
    try:
        site_name,malicious,suspicious,undetected,harmless = link_scan()
        print("WebSite Name:", site_name,"\n","malicious:", malicious,"\n","suspicious:", suspicious,"\n","undetected:", undetected,"\n", "harmless:", harmless,)
    except Exception as e:
        print(str(e))
    

if __name__ == "__main__":
    main()