"""
OpenAI Client Module
Provides a direct client for OpenAI API without relying on LangChain
"""

import os
import json
import requests
import time
from typing import Dict, List, Any, Optional

from utils.logger import get_logger

class OpenAIClient:
    """
    Client for interacting with the OpenAI API directly
    """

    def __init__(self):
        """Initialize the OpenAI client"""
        self.logger = get_logger("openai_client")
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.base_url = "https://api.openai.com/v1"

        if not self.api_key:
            self.logger.warning("OpenAI API key not found in environment variables")
        else:
            self.logger.info("OpenAI client initialized")

    def chat_completion(self,
                        messages: List[Dict[str, str]],
                        model: str = "gpt-3.5-turbo",
                        temperature: float = 0.7,
                        max_tokens: int = 1000,
                        retry_count: int = 3,
                        timeout: int = 60,  # Increased default timeout
                        verify_ssl: bool = False) -> Dict[str, Any]:  # Default to not verify SSL
        """
        Send a chat completion request to the OpenAI API

        Args:
            messages: List of message objects (role and content)
            model: Model to use
            temperature: Temperature for sampling
            max_tokens: Maximum number of tokens to generate
            retry_count: Number of times to retry on failure
            timeout: Timeout for the request in seconds
            verify_ssl: Whether to verify SSL certificates

        Returns:
            Dictionary containing the API response
        """
        if not self.api_key:
            self.logger.error("OpenAI API key not available")
            return {"error": "API key not available"}

        url = f"{self.base_url}/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        data = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
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
                    return response.json()
                elif response.status_code == 429:
                    # Rate limit error - wait and retry
                    wait_time = min(2 ** attempt, 60)  # Exponential backoff
                    self.logger.warning(f"Rate limit exceeded. Waiting {wait_time} seconds before retry.")
                    time.sleep(wait_time)
                    continue
                else:
                    self.logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
                    return {"error": f"API error: {response.status_code}", "details": response.text}
            except requests.exceptions.SSLError:
                self.logger.warning("SSL verification failed. Retrying without SSL verification.")
                # Try again without SSL verification
                return self.chat_completion(
                    messages=messages,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    retry_count=retry_count-1,
                    timeout=timeout,
                    verify_ssl=False
                )
            except requests.exceptions.Timeout:
                self.logger.warning(f"Request timed out. Retrying with increased timeout.")
                # Try again with increased timeout
                return self.chat_completion(
                    messages=messages,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    retry_count=retry_count-1,
                    timeout=timeout*2,
                    verify_ssl=verify_ssl
                )
            except requests.exceptions.ConnectionError:
                self.logger.warning(f"Connection error. Attempt {attempt+1}/{retry_count}")
                # Wait before retrying
                time.sleep(2 ** attempt)
            except Exception as e:
                self.logger.error(f"Error querying OpenAI API: {e}")
                return {"error": str(e)}

        # If we've exhausted all retries
        return {"error": "Failed after multiple retry attempts"}

    def generate_text(self, prompt: str, **kwargs) -> str:
        """
        Generate text from a prompt

        Args:
            prompt: The prompt to send
            **kwargs: Additional arguments to pass to chat_completion

        Returns:
            Generated text as a string
        """
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]

        response = self.chat_completion(messages, **kwargs)

        if "error" in response:
            return f"Error: {response['error']}"

        try:
            return response["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            return "Error: Unexpected response format"

def get_openai_client() -> OpenAIClient:
    """Get an OpenAI client instance"""
    return OpenAIClient()
