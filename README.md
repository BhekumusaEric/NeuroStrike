# NeuroStrike: AI Red vs Blue Cyber War Game

NeuroStrike is a real-world cybersecurity tool that leverages AI to create a Red Team (offensive) and Blue Team (defensive) system for network security assessment and protection.

## Overview

NeuroStrike consists of two intelligent agents:

- **🔴 Red Agent**: Analyzes networks, identifies vulnerabilities, and generates exploitation strategies
- **🔵 Blue Agent**: Assesses vulnerabilities, generates mitigations, and implements defenses

Unlike simulations, NeuroStrike is designed to work with real networks, making it a practical tool for cybersecurity professionals.

## Features

### Red Agent Capabilities
- Network scanning and enumeration
- Vulnerability identification and analysis
- Exploit plan generation
- Controlled exploit execution (with safety measures)

### Blue Agent Capabilities
- Vulnerability assessment and verification
- Mitigation strategy generation
- Security rule creation (YARA, Snort, Sigma)
- System monitoring and intrusion detection

### Key Components
- LLM-powered analysis and strategy generation
- Real-world network interaction
- Comprehensive reporting
- Both CLI and web-based interfaces

## Installation

### Prerequisites
- Python 3.8+
- Network access to target systems
- OpenAI API key (for LLM functionality)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/NeuroStrike.git
cd NeuroStrike
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

4. Run the application:
```bash
python run.py
```

## Usage

### Command Line Interface

The CLI provides a comprehensive interface for interacting with NeuroStrike:

```bash
python run.py --mode both --ui cli
```

Available commands:
- `scan <target>` - Scan a target network or host
- `analyze` - Analyze scan results to identify vulnerabilities
- `exploit <vuln_id>` - Generate an exploit plan for a vulnerability
- `execute <plan_id>` - Execute an exploit plan
- `defend` - Generate defense strategies for vulnerabilities
- `mitigate <plan_id>` - Apply a mitigation plan
- `rules <exploit_id>` - Generate defense rules for a threat
- `monitor` - Monitor the system for security events
- `report [red|blue]` - Generate a comprehensive report

### Web Interface

The web interface provides a user-friendly way to interact with NeuroStrike:

```bash
python run.py --mode both --ui web
```

The interface includes tabs for:
- Red Team operations
- Blue Team operations
- Comprehensive reporting

## Safety Considerations

NeuroStrike includes several safety features to prevent unintended damage:

- **Safe Mode**: By default, exploits are only simulated, not executed
- **Auto-Remediation Control**: Defensive actions require explicit approval
- **Backup Before Fix**: Automatically backs up files before modifying them
- **Excluded IPs**: Configure IP addresses to exclude from scanning

## Project Structure

```
NeuroStrike/
│
├── README.md
├── requirements.txt
├── run.py                      # Entry point to launch system
│
├── config/
│   ├── settings.yaml           # Global config (model names, thresholds, flags)
│   └── prompts.yaml            # Red and Blue team prompt templates
│
├── data/
│   ├── logs/                   # Log files
│   ├── reports/                # Generated reports
│   └── rules/                  # Generated security rules
│
├── agents/
│   ├── __init__.py
│   ├── red_agent.py            # Offensive agent logic
│   └── blue_agent.py           # Defensive agent logic
│
├── ai_models/
│   └── model_loader.py         # LLM loader
│
├── core/
│   ├── analyzer.py             # Network analysis
│   ├── intrusion_detector.py   # Log anomaly detection
│   ├── exploit_simulator.py    # Exploit execution engine
│   └── defense_engine.py       # Defense implementation
│
├── interface/
│   ├── app_ui.py               # Web UI
│   └── cli.py                  # Command-line interface
│
└── utils/
    └── logger.py               # Logging utilities
```

## Disclaimer

This tool is intended for legitimate security testing and educational purposes only. Always ensure you have proper authorization before scanning or testing any network or system. The developers are not responsible for any misuse of this tool.

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
