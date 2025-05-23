#!/usr/bin/env python3
"""
HuggingFace API Test Script
Verifies that the HuggingFace API key is working correctly
"""

import os
import requests
from dotenv import load_dotenv

def test_huggingface_api():
    """Test the HuggingFace API connection"""
    # Load environment variables from .env file
    load_dotenv()

    # Get HuggingFace API key from environment
    api_key = os.environ.get("HUGGINGFACE_API_KEY")
    if not api_key:
        print("Error: HuggingFace API key not found in environment variables")
        return False

    print(f"Testing HuggingFace API connection...")
    print("-" * 50)

    # API endpoint for checking user information
    url = "https://huggingface.co/api/whoami"

    # Headers with API key
    headers = {
        "Authorization": f"Bearer {api_key}"
    }

    # No payload needed for this endpoint
    payload = None

    try:
        # Make the API request with a timeout
        response = requests.get(url, headers=headers, timeout=10)

        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            print(f"API Response: {data}")
            print("\nHuggingFace API is working correctly!")
            return True
        else:
            print(f"Error: {response.status_code} - {response.text}")

            # Check for common error types
            if response.status_code == 401:
                print("\nAuthentication error: Your API key may be invalid or expired.")
                print("Please check your API key in the .env file.")
            elif response.status_code == 429:
                print("\nRate limit exceeded: You've sent too many requests.")
                print("Try again later or check your usage limits.")
            elif response.status_code == 503:
                print("\nService unavailable: The model might be loading or unavailable.")
                print("Try again later.")

            return False
    except requests.exceptions.Timeout:
        print("Error: Request timed out. HuggingFace servers might be slow or unreachable.")
        return False
    except requests.exceptions.ConnectionError:
        print("Error: Connection error. Please check your internet connection.")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    test_huggingface_api()
