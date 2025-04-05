import os
import requests

def ask_openai(question):
    api_key = os.getenv("AZURE_OPENAI_KEY")
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    deployment = os.getenv("DEPLOYMENT_NAME")
    search_endpoint = os.getenv("AZURE_AI_SEARCH_ENDPOINT")
    search_index = os.getenv("AZURE_AI_SEARCH_INDEX")
    search_key = os.getenv("AZURE_AI_SEARCH_KEY")

    # Safety check for environment variables
    if not all([api_key, endpoint, deployment, search_endpoint, search_index, search_key]):
        raise ValueError("Missing one or more required environment variables")

    url = f"{endpoint}/openai/deployments/{deployment}/extensions/chat/completions?api-version=2023-06-01-preview"

    headers = {
        "Content-Type": "application/json",
        "api-key": api_key
    }

    payload = {
        "messages": [
            {
                "role": "user",
                "content": question
            }
        ],
        "temperature": 0.7,
        "dataSources": [
            {
                "type": "AzureCognitiveSearch",
                "parameters": {
                    "endpoint": search_endpoint,
                    "key": search_key,
                    "indexName": search_index,
                    "inScope": True,
                    "topNDocuments": 5,
                    "roleInformation": "You are a helpful Ring Expert for RINGS & I who answers user questions."
                }
            }
        ]
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()

    data = response.json()

    # Debug log to help identify format
    print("OpenAI response:", data)

    try:
        return data["choices"][0]["messages"][0]["content"]
    except KeyError:
        # Fallback if format uses 'message' instead of 'messages'
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Error parsing OpenAI response: {e}\nFull response: {data}"
