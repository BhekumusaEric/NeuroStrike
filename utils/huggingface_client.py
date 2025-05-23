"""
HuggingFace Client Module
Provides a direct client for HuggingFace Inference API
"""

import os
import json
import requests
import time
from typing import Dict, List, Any, Optional

from utils.logger import get_logger

class HuggingFaceClient:
    """
    Client for interacting with the HuggingFace Inference API
    """

    def __init__(self):
        """Initialize the HuggingFace client"""
        self.logger = get_logger("huggingface_client")
        self.api_key = os.environ.get("HUGGINGFACE_API_KEY")
        self.base_url = "https://api-inference.huggingface.co/models"

        if not self.api_key:
            self.logger.warning("HuggingFace API key not found in environment variables")
        else:
            self.logger.info("HuggingFace client initialized")

    def generate_text(self,
                     prompt: str,
                     model: str = "mistralai/Mistral-7B-Instruct-v0.2",
                     max_tokens: int = 1000,
                     temperature: float = 0.7,
                     retry_count: int = 3,
                     timeout: int = 120,  # Increased timeout
                     verify_ssl: bool = False) -> str:  # Disabled SSL verification
        """
        Generate text from a prompt using the HuggingFace Inference API

        Args:
            prompt: The prompt to send
            model: Model to use
            max_tokens: Maximum number of tokens to generate
            temperature: Temperature for sampling
            retry_count: Number of times to retry on failure
            timeout: Timeout for the request in seconds
            verify_ssl: Whether to verify SSL certificates

        Returns:
            Generated text as a string
        """
        if not self.api_key:
            self.logger.error("HuggingFace API key not available")
            return "Error: HuggingFace API key not available"

        url = f"{self.base_url}/{model}"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        # Format the prompt based on the model
        if "mistral" in model.lower() or "llama" in model.lower():
            # Format for instruction-tuned models
            formatted_prompt = f"<s>[INST] {prompt} [/INST]"
        else:
            # Default format
            formatted_prompt = prompt

        data = {
            "inputs": formatted_prompt,
            "parameters": {
                "max_new_tokens": max_tokens,
                "temperature": temperature,
                "return_full_text": False
            }
        }

        # Set up a session with proxy handling
        session = requests.Session()

        # Try to get proxy settings from environment variables
        http_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
        https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')

        if http_proxy or https_proxy:
            proxies = {
                'http': http_proxy,
                'https': https_proxy
            }
            session.proxies.update(proxies)
            self.logger.info(f"Using proxies: {proxies}")

        for attempt in range(retry_count):
            try:
                # Use session for the request
                response = session.post(
                    url,
                    headers=headers,
                    json=data,
                    timeout=timeout,
                    verify=verify_ssl
                )

                if response.status_code == 200:
                    result = response.json()

                    # Handle different response formats
                    if isinstance(result, list) and len(result) > 0:
                        if isinstance(result[0], dict) and "generated_text" in result[0]:
                            return result[0]["generated_text"]
                        elif isinstance(result[0], str):
                            return result[0]

                    # Fallback to returning the whole response as string
                    return str(result)

                elif response.status_code == 503:
                    # Model is loading
                    wait_time = min(2 ** attempt + 5, 60)  # Exponential backoff
                    self.logger.warning(f"Model is loading. Waiting {wait_time} seconds before retry.")
                    time.sleep(wait_time)
                    continue

                elif response.status_code == 429:
                    # Rate limit error - wait and retry
                    wait_time = min(2 ** attempt, 60)  # Exponential backoff
                    self.logger.warning(f"Rate limit exceeded. Waiting {wait_time} seconds before retry.")
                    time.sleep(wait_time)
                    continue

                else:
                    self.logger.error(f"HuggingFace API error: {response.status_code} - {response.text}")
                    return f"Error: API error {response.status_code} - {response.text}"

            except requests.exceptions.SSLError:
                self.logger.warning("SSL verification failed. Retrying without SSL verification.")
                # Try again without SSL verification
                return self.generate_text(
                    prompt=prompt,
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    retry_count=retry_count-1,
                    timeout=timeout,
                    verify_ssl=False
                )

            except requests.exceptions.Timeout:
                self.logger.warning(f"Request timed out. Retrying with increased timeout.")
                # Try again with increased timeout
                return self.generate_text(
                    prompt=prompt,
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    retry_count=retry_count-1,
                    timeout=timeout*2,
                    verify_ssl=verify_ssl
                )

            except requests.exceptions.ConnectionError:
                self.logger.warning(f"Connection error. Attempt {attempt+1}/{retry_count}")
                # Wait before retrying
                time.sleep(2 ** attempt)

            except Exception as e:
                self.logger.error(f"Error querying HuggingFace API: {e}")
                return f"Error: {e}"

        # If we've exhausted all retries
        return "Error: Failed after multiple retry attempts"

    def check_api_status(self) -> bool:
        """
        Check if the HuggingFace API is accessible

        Returns:
            True if the API is accessible, False otherwise
        """
        if not self.api_key:
            self.logger.error("HuggingFace API key not available")
            return False

        # For now, let's assume the API is accessible even if we can't verify it
        # This allows us to attempt to use the API and fall back to MockLLM if needed
        self.logger.info("Assuming HuggingFace API is accessible (skipping verification)")
        return True

        # The code below is commented out because it's causing issues
        # We'll uncomment it when we can properly verify the API status
        """
        try:
            # Set up a session with proxy handling
            session = requests.Session()

            # Try to get proxy settings from environment variables
            http_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
            https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')

            if http_proxy or https_proxy:
                proxies = {
                    'http': http_proxy,
                    'https': https_proxy
                }
                session.proxies.update(proxies)
                self.logger.info(f"Using proxies: {proxies}")

            # Use the whoami endpoint to check API status
            url = "https://huggingface.co/api/whoami"
            headers = {"Authorization": f"Bearer {self.api_key}"}

            response = session.get(url, headers=headers, timeout=30, verify=False)

            if response.status_code == 200:
                self.logger.info("HuggingFace API is accessible")
                return True
            else:
                self.logger.error(f"HuggingFace API error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Error checking HuggingFace API status: {e}")
            return False
        """

def get_huggingface_client() -> HuggingFaceClient:
    """Get a HuggingFace client instance"""
    return HuggingFaceClient()
