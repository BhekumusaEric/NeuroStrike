"""
Model Loader Module
Handles loading and configuring LLM models
"""

import os
import yaml
import logging
import random
import requests
from typing import Dict, List, Any, Optional

# Import LLM providers
try:
    # Try importing from langchain_openai first (newer versions)
    from langchain_openai import OpenAI
    from langchain_openai import ChatOpenAI
    LANGCHAIN_AVAILABLE = True
    print("Successfully imported from langchain_openai")
except ImportError:
    try:
        # Fall back to older langchain imports
        from langchain.llms import OpenAI
        from langchain.chat_models import ChatOpenAI
        LANGCHAIN_AVAILABLE = True
        print("Successfully imported from langchain")
    except ImportError:
        print("Failed to import LangChain modules")
        LANGCHAIN_AVAILABLE = False

from utils.logger import get_logger
from utils.openai_client import get_openai_client
from utils.huggingface_client import get_huggingface_client

# Custom OpenAI wrapper using our direct client
class CustomOpenAIWrapper:
    """
    Custom wrapper for OpenAI using our direct client implementation
    Provides a consistent interface with other LLM implementations
    """

    def __init__(self, model_name: str, temperature: float = 0.7, max_tokens: int = 2000):
        """
        Initialize the Custom OpenAI wrapper

        Args:
            model_name: Name of the model to use
            temperature: Temperature for sampling
            max_tokens: Maximum number of tokens to generate
        """
        self.logger = get_logger("custom_openai")
        self.client = get_openai_client()
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.logger.info(f"Initialized CustomOpenAIWrapper with model {model_name}")

    def invoke(self, prompt: str) -> str:
        """
        Generate a response from the prompt

        Args:
            prompt: The prompt to send to the model

        Returns:
            The generated response as a string
        """
        self.logger.debug(f"Generating response for prompt: {prompt[:100]}...")

        try:
            return self.client.generate_text(
                prompt=prompt,
                model=self.model_name,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
        except Exception as e:
            self.logger.error(f"Error generating response: {e}")
            self.logger.warning("Falling back to MockLLM due to error.")
            mock_llm = MockLLM()
            return mock_llm.invoke(prompt)

    def predict(self, prompt: str) -> str:
        """Alias for invoke method for compatibility"""
        return self.invoke(prompt)

    def __call__(self, prompt: str) -> str:
        """Callable interface for compatibility"""
        return self.invoke(prompt)

# Custom HuggingFace wrapper using our direct client
class CustomHuggingFaceWrapper:
    """
    Custom wrapper for HuggingFace using our direct client implementation
    Provides a consistent interface with other LLM implementations
    """

    def __init__(self, model_name: str, temperature: float = 0.7, max_tokens: int = 2000):
        """
        Initialize the Custom HuggingFace wrapper

        Args:
            model_name: Name of the model to use
            temperature: Temperature for sampling
            max_tokens: Maximum number of tokens to generate
        """
        self.logger = get_logger("custom_huggingface")
        self.client = get_huggingface_client()
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.logger.info(f"Initialized CustomHuggingFaceWrapper with model {model_name}")

    def invoke(self, prompt: str) -> str:
        """
        Generate a response from the prompt

        Args:
            prompt: The prompt to send to the model

        Returns:
            The generated response as a string
        """
        self.logger.debug(f"Generating response for prompt: {prompt[:100]}...")

        try:
            return self.client.generate_text(
                prompt=prompt,
                model=self.model_name,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
        except Exception as e:
            self.logger.error(f"Error generating response: {e}")
            self.logger.warning("Falling back to MockLLM due to error.")
            mock_llm = MockLLM()
            return mock_llm.invoke(prompt)

    def predict(self, prompt: str) -> str:
        """Alias for invoke method for compatibility"""
        return self.invoke(prompt)

    def __call__(self, prompt: str) -> str:
        """Callable interface for compatibility"""
        return self.invoke(prompt)

# Mock LLM class for testing without real LLM
class MockLLM:
    """
    Mock LLM class for testing without a real LLM
    Returns predefined responses for different types of prompts
    """

    def __init__(self):
        """Initialize the Mock LLM"""
        self.logger = get_logger("mock_llm")
        self.logger.info("Initializing Mock LLM for testing")

    def invoke(self, prompt: str) -> str:
        """
        Generate a response based on the prompt

        Args:
            prompt: The prompt to respond to

        Returns:
            A predefined response based on the prompt content
        """
        self.logger.info("Mock LLM received prompt")

        if "vulnerability" in prompt.lower():
            return random.choice(MOCK_VULNERABILITY_RESPONSES)
        elif "exploit" in prompt.lower():
            return random.choice(MOCK_EXPLOIT_RESPONSES)
        elif "mitigation" in prompt.lower():
            return random.choice(MOCK_MITIGATION_RESPONSES)
        elif "rule" in prompt.lower():
            return random.choice(MOCK_RULE_RESPONSES)
        else:
            return "Mock LLM response: I'm a test response for development purposes."

    def predict(self, prompt: str) -> str:
        """Alias for invoke method for compatibility"""
        return self.invoke(prompt)

    def __call__(self, prompt: str) -> str:
        """Callable interface for compatibility"""
        return self.invoke(prompt)

# Mock responses for testing without LLM
MOCK_VULNERABILITY_RESPONSES = [
    """
    1. SSH Service Misconfiguration
       Severity: Medium
       CVE: N/A
       Exploitation Difficulty: Easy

       The SSH service on port 22 is configured to allow password authentication, which makes it vulnerable to brute force attacks.

    2. Outdated Web Server
       Severity: High
       CVE: CVE-2021-1234
       Exploitation Difficulty: Medium

       The web server is running an outdated version with known vulnerabilities that could allow remote code execution.
    """,
    """
    1. Unpatched Operating System
       Severity: Critical
       CVE: CVE-2022-5678
       Exploitation Difficulty: Medium

       The operating system has not been updated with the latest security patches, leaving it vulnerable to several known exploits.

    2. Weak Firewall Configuration
       Severity: Medium
       CVE: N/A
       Exploitation Difficulty: Medium

       The firewall is configured to allow traffic on unnecessary ports, increasing the attack surface.
    """
]

MOCK_EXPLOIT_RESPONSES = [
    """
    Exploit Plan for SSH Brute Force

    Type: Password Attack

    Steps:
    1. Identify the target SSH service
    2. Gather a list of common usernames
    3. Prepare a dictionary of common passwords
    4. Use a tool like Hydra to perform the brute force attack
    5. Gain access using discovered credentials

    Commands:
    nmap -p 22 -sV [target]
    hydra -L users.txt -P passwords.txt ssh://[target]
    ssh [username]@[target]

    Expected Outcome: Successful login to the SSH service with valid credentials

    Detection Methods:
    1. Failed login attempts in auth logs
    2. Unusual login times or sources
    3. High volume of connection attempts
    """,
    """
    Exploit Plan for Web Server Vulnerability

    Type: Remote Code Execution

    Steps:
    1. Identify the vulnerable web server version
    2. Craft a payload that exploits the vulnerability
    3. Send the payload to the target server
    4. Establish a reverse shell connection
    5. Escalate privileges if possible

    Commands:
    curl -I http://[target]
    python exploit.py --target http://[target] --payload reverse_shell
    nc -lvp 4444

    Expected Outcome: Remote code execution on the target server

    Detection Methods:
    1. Unusual web server logs
    2. Unexpected outbound connections
    3. File system modifications
    """
]

MOCK_MITIGATION_RESPONSES = [
    """
    Verification: Confirmed
    Severity: Medium
    CVSS Score: 6.5

    Immediate Mitigation:
    1. Disable password authentication in SSH and use key-based authentication only
    2. Implement fail2ban to block repeated failed login attempts
    3. Restrict SSH access to specific IP addresses

    Long-term Remediation:
    1. Implement multi-factor authentication
    2. Regular review of SSH configuration
    3. Monitor for unusual login patterns

    Configuration Changes:
    1. Edit /etc/ssh/sshd_config to set "PasswordAuthentication no"
    2. Add "AllowUsers [specific_users]" to restrict access

    Commands:
    sudo nano /etc/ssh/sshd_config
    sudo systemctl restart sshd
    sudo apt install fail2ban
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

    Verification Steps:
    1. Attempt to login with password (should fail)
    2. Verify key-based authentication works
    3. Check logs for blocked attempts after implementing fail2ban
    """,
    """
    Verification: Confirmed
    Severity: High
    CVSS Score: 8.2

    Immediate Mitigation:
    1. Update the web server to the latest version
    2. Apply security patches
    3. Implement a Web Application Firewall

    Long-term Remediation:
    1. Establish regular patching schedule
    2. Implement vulnerability scanning
    3. Consider containerization for better isolation

    Configuration Changes:
    1. Update package repositories
    2. Install security updates

    Commands:
    sudo apt update
    sudo apt upgrade
    sudo systemctl restart apache2

    Verification Steps:
    1. Check server version after update
    2. Run vulnerability scan to verify patch
    3. Test web application functionality
    """
]

MOCK_RULE_RESPONSES = [
    """
    YARA rule:
    rule SSH_Brute_Force {
        meta:
            description = "Detects SSH brute force attempts"
            author = "NeuroStrike"
            severity = "medium"
        strings:
            $s1 = "Failed password for" nocase
            $s2 = "Invalid user" nocase
            $s3 = "authentication failure" nocase
        condition:
            any of them and #s1 > 5
    }

    Snort rule:
    alert tcp any any -> $HOME_NET 22 (msg:"Potential SSH brute force attempt"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)

    Sigma rule:
    title: SSH Brute Force Attempt
    status: experimental
    description: Detects SSH brute force attempts
    author: NeuroStrike
    logsource:
      product: linux
      service: sshd
    detection:
      selection:
        message:
          - 'Failed password for*'
          - 'Invalid user*'
      timeframe: 5m
      condition: selection | count() > 5
    falsepositives:
      - Legitimate failed login attempts
    level: medium

    Firewall rule:
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    """,
    """
    YARA rule:
    rule Web_Server_Exploit {
        meta:
            description = "Detects attempts to exploit web server vulnerabilities"
            author = "NeuroStrike"
            severity = "high"
        strings:
            $s1 = "eval(" nocase
            $s2 = "exec(" nocase
            $s3 = "/bin/sh" nocase
            $s4 = "cmd.exe" nocase
        condition:
            any of them
    }

    Snort rule:
    alert tcp any any -> $HOME_NET 80 (msg:"Potential web server exploit attempt"; flow:to_server,established; content:"|2F 62 69 6E 2F 73 68|"; classtype:web-application-attack; sid:1000002; rev:1;)

    Sigma rule:
    title: Web Server Exploit Attempt
    status: experimental
    description: Detects attempts to exploit web server vulnerabilities
    author: NeuroStrike
    logsource:
      product: webserver
      service: access
    detection:
      selection:
        request:
          - '*.php?*=*eval(*'
          - '*.php?*=*exec(*'
          - '*cmd.exe*'
          - '*/bin/sh*'
      condition: selection
    falsepositives:
      - Legitimate web applications using these functions
    level: high

    Firewall rule:
    iptables -A INPUT -p tcp --dport 80 -m string --string "/bin/sh" --algo bm -j DROP
    iptables -A INPUT -p tcp --dport 80 -m string --string "cmd.exe" --algo bm -j DROP
    """
]

class LLMWrapper:
    """
    Wrapper class for LLM models
    Provides a consistent interface regardless of the underlying model
    """

    def __init__(self, model_config: Dict[str, Any]):
        """
        Initialize the LLM wrapper

        Args:
            model_config: Configuration for the LLM model
        """
        self.logger = get_logger("llm_wrapper")
        self.config = model_config
        self.model = self._load_model()

    def _load_model(self):
        """Load the appropriate LLM model based on configuration"""
        provider = self.config.get("provider", "openai").lower()
        model_name = self.config.get("model", "gpt-4")
        temperature = self.config.get("temperature", 0.7)
        max_tokens = self.config.get("max_tokens", 2000)

        if provider == "openai":
            return self._load_openai_model(model_name, temperature, max_tokens)
        elif provider == "local":
            return self._load_local_model(model_name, temperature, max_tokens)
        elif provider == "huggingface":
            return self._load_huggingface_model(model_name, temperature, max_tokens)
        else:
            self.logger.error(f"Unsupported LLM provider: {provider}")
            raise ValueError(f"Unsupported LLM provider: {provider}")

    def _load_openai_model(self, model_name, temperature, max_tokens):
        """Load an OpenAI model"""
        # Check if we should use LangChain or our custom client
        use_custom_client = True  # Set to True to use our custom client instead of LangChain

        if use_custom_client:
            self.logger.info(f"Loading OpenAI model using custom client: {model_name}")
            return CustomOpenAIWrapper(model_name, temperature, max_tokens)

        # Fall back to LangChain if requested
        if not LANGCHAIN_AVAILABLE:
            self.logger.warning("LangChain not available. Using custom OpenAI client.")
            return CustomOpenAIWrapper(model_name, temperature, max_tokens)

        api_key = os.environ.get(self.config.get("api_key_env", "OPENAI_API_KEY"))
        if not api_key:
            self.logger.warning(f"API key not found in environment variable {self.config.get('api_key_env')}. Using MockLLM for testing.")
            return MockLLM()

        self.logger.info(f"Loading OpenAI model via LangChain: {model_name}")

        try:
            if model_name.startswith("gpt-3.5") or model_name.startswith("gpt-4"):
                return ChatOpenAI(
                    model_name=model_name,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    openai_api_key=api_key
                )
            else:
                return OpenAI(
                    model_name=model_name,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    openai_api_key=api_key
                )
        except Exception as e:
            self.logger.warning(f"Error loading OpenAI model via LangChain: {e}. Using custom OpenAI client.")
            return CustomOpenAIWrapper(model_name, temperature, max_tokens)

    def _load_local_model(self, model_name, temperature, max_tokens):
        """Load a local model"""
        self.logger.warning("Local model loading not implemented yet. Using MockLLM for testing.")
        return MockLLM()

    def _load_huggingface_model(self, model_name, temperature, max_tokens):
        """Load a HuggingFace model"""
        # Use our custom HuggingFace client
        self.logger.info(f"Loading HuggingFace model using custom client: {model_name}")

        try:
            # Create a client instance to check API status
            client = get_huggingface_client()

            # Check if the API key is valid
            if client.check_api_status():
                self.logger.info(f"HuggingFace API key is valid. Using CustomHuggingFaceWrapper.")
                return CustomHuggingFaceWrapper(model_name, temperature, max_tokens)
            else:
                self.logger.warning("HuggingFace API key is invalid or API is unreachable. Using MockLLM for testing.")
                return MockLLM()
        except Exception as e:
            self.logger.warning(f"Error loading HuggingFace model: {e}. Using MockLLM for testing.")
            return MockLLM()

    def generate(self, prompt: str) -> str:
        """
        Generate a response from the LLM

        Args:
            prompt: The prompt to send to the LLM

        Returns:
            The generated response as a string
        """
        self.logger.debug(f"Generating response for prompt: {prompt[:100]}...")

        # First try with the configured model
        try:
            if hasattr(self.model, "invoke"):
                # For newer LangChain models or our custom wrappers
                response = self.model.invoke(prompt)
                if hasattr(response, "content"):
                    return response.content
                return str(response)
            elif hasattr(self.model, "predict"):
                # For older LangChain models
                return self.model.predict(prompt)
            else:
                # Fallback
                return str(self.model(prompt))
        except requests.exceptions.ConnectionError as e:
            self.logger.warning(f"Connection error with LLM API: {e}. Falling back to MockLLM.")
            # Fall back to MockLLM if there's a connection error
            mock_llm = MockLLM()
            return mock_llm.invoke(prompt)
        except requests.exceptions.Timeout as e:
            self.logger.warning(f"Timeout error with LLM API: {e}. Falling back to MockLLM.")
            # Fall back to MockLLM if there's a timeout
            mock_llm = MockLLM()
            return mock_llm.invoke(prompt)
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Request error with LLM API: {e}. Falling back to MockLLM.")
            # Fall back to MockLLM for any request-related error
            mock_llm = MockLLM()
            return mock_llm.invoke(prompt)
        except Exception as e:
            self.logger.error(f"Error generating response: {e}")
            self.logger.warning("Falling back to MockLLM due to error.")
            # Fall back to MockLLM for any other error
            mock_llm = MockLLM()
            return mock_llm.invoke(prompt)

def load_llm() -> LLMWrapper:
    """
    Load an LLM model based on configuration

    Returns:
        An initialized LLMWrapper instance
    """
    logger = get_logger("model_loader")

    # Load configuration
    try:
        with open("config/settings.yaml", "r") as file:
            config = yaml.safe_load(file)
            llm_config = config.get("llm", {})
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        llm_config = {
            "provider": "openai",
            "model": "gpt-4",
            "temperature": 0.7,
            "max_tokens": 2000,
            "api_key_env": "OPENAI_API_KEY"
        }

    # Create and return the LLM wrapper
    return LLMWrapper(llm_config)
