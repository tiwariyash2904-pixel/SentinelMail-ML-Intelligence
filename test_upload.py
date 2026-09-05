import requests

with open("data/sample_phishing.eml", "rb") as f:
    response = requests.post(
        "http://127.0.0.1:8000/analyze-eml",
        files={"file": f}
    )

print(response.status_code)
print(response.json())