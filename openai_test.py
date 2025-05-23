#!/usr/bin/env python3
"""
OpenAI API Test Script
Verifies that the OpenAI API key is working correctly
"""

import os
import time
import requests
from dotenv import load_dotenv

def test_openai_api():
    """Test the OpenAI API connection"""
    # Load environment variables from .env file
    load_dotenv()
    
    # Get OpenAI API key from environment
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OpenAI API key not found in environment variables")
        return False
    
    print(f"Testing OpenAI API connection...")
    print("-" * 50)
    
    # API endpoint for chat completions
    url = "https://api.openai.com/v1/chat/completions"
    
    # Headers with API key
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    # Simple request payload
    payload = {
        "model": "gpt-3.5-turbo",  # Using a simpler model for testing
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say hello world"}
        ],
        "max_tokens": 50
    }
    
    try:
        # Make the API request with a timeout
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        
        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            message = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            print(f"API Response: {message}")
            print("\nOpenAI API is working correctly!")
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
            elif response.status_code == 500:
                print("\nServer error: OpenAI's servers are experiencing issues.")
                print("Try again later.")
                
            return False
    except requests.exceptions.Timeout:
        print("Error: Request timed out. OpenAI servers might be slow or unreachable.")
        return False
    except requests.exceptions.ConnectionError:
        print("Error: Connection error. Please check your internet connection.")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    test_openai_api()
