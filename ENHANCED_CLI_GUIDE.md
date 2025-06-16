# NeuroStrike Enhanced CLI Guide

## 🚀 Overview

The NeuroStrike Enhanced CLI provides a comprehensive command-line interface for cybersecurity operations with improved user experience, advanced features, and better functionality.

## 🎯 Quick Start

### Running the Enhanced CLI

```bash
# Run with both Red and Blue agents
python enhanced_cli_demo.py --mode both

# Run Red Agent only (offensive operations)
python enhanced_cli_demo.py --mode red --safe-mode

# Run Blue Agent only (defensive operations)
python enhanced_cli_demo.py --mode blue --auto-remediate

# Run with demo data for testing
python enhanced_cli_demo.py --demo-data
```

### First Steps

1. **Check Status**: `status` - See current system state
2. **Set Target**: `set target 127.0.0.1` - Set a safe target for testing
3. **View Workflows**: `workflow` - See suggested command sequences
4. **Interactive Tutorial**: `tutorial` - Guided walkthrough
5. **Get Help**: `help` - List all commands

## 🔥 New Features

### Enhanced User Experience
- **Colored Output**: Commands, results, and status messages are color-coded
- **Smart Prompts**: Dynamic prompts showing current target and agent status
- **Progress Indicators**: Visual feedback for long-running operations
- **Error Suggestions**: Helpful troubleshooting tips when commands fail

### Advanced Command Parsing
- **Flexible Arguments**: Support for command-line style options
- **Auto-completion**: Tab completion for commands and parameters
- **Command History**: Navigate through previous commands
- **Session Management**: Save and restore CLI sessions

### Interactive Features
- **Tutorials**: Step-by-step guided tutorials
- **Workflows**: Suggested command sequences for different scenarios
- **Status Dashboard**: Real-time system status and statistics
- **Smart Defaults**: Use current target when none specified

## 📋 Command Reference

### System Commands

#### `status`
Show comprehensive system status including:
- Agent status (Red/Blue)
- Current target information
- Vulnerability counts
- Session statistics

#### `set <option> <value>`
Configure system settings:
- `set target <ip>` - Set default target IP
- `set autosave <on|off>` - Enable/disable auto-save

#### `workflow`
Display suggested command workflows for:
- Red Team (offensive) operations
- Blue Team (defensive) operations
- Binary analysis workflows
- Memory analysis workflows

#### `tutorial`
Interactive tutorial system with guided walkthroughs

#### `history [n|clear]`
- `history` - Show last 20 commands
- `history 50` - Show last 50 commands
- `history clear` - Clear command history

### Session Management

#### `save <type>`
- `save session` - Save current session data
- `save config` - Save current configuration

#### `load <file>`
Load previously saved session data

### Enhanced Scanning

#### `scan [options] [target]`
Advanced network scanning with options:
- `scan <target>` - Basic scan
- `scan` - Scan current target
- `scan -p 80,443 <target>` - Scan specific ports
- `scan -A <target>` - Aggressive scan (OS detection, version detection)

**Features:**
- Detailed scan parameters display
- Progress indicators
- Comprehensive results with host discovery
- Port and service enumeration
- OS detection results
- Troubleshooting suggestions on failure

### Red Team Operations

#### `analyze`
Enhanced vulnerability analysis with:
- Detailed vulnerability descriptions
- Severity assessments
- CVE information
- Exploitation difficulty ratings

#### `exploit <vuln_id>`
Generate sophisticated exploit plans with:
- Step-by-step execution plans
- Required commands
- Expected outcomes
- Safety warnings

#### `execute <plan_id>`
Execute exploit plans with:
- Safety confirmations
- Real-time progress
- Detailed result reporting
- Simulation mode support

### Blue Team Operations

#### `defend`
Generate comprehensive defense strategies:
- Vulnerability assessments
- CVSS scoring
- Mitigation plan generation
- Priority recommendations

#### `mitigate <plan_id>`
Apply mitigation plans with:
- Change tracking
- Verification results
- Rollback capabilities
- Safety confirmations

#### `rules <exploit_id>`
Generate defense rules:
- YARA rules for malware detection
- Snort/Suricata network rules
- Sigma rules for log analysis
- Firewall rules
- Automatic deployment options

#### `monitor`
Enhanced system monitoring with:
- Real-time event detection
- Threat intelligence integration
- Alert prioritization
- Automated response triggers

### Binary Analysis

#### `analyze_binary <path>`
Comprehensive binary analysis:
- File type and metadata
- Section analysis
- Function enumeration
- Import/export analysis
- Security feature detection

#### `find_binary_vulns`
Vulnerability discovery in binaries:
- Buffer overflow detection
- Format string vulnerabilities
- Use-after-free detection
- Integer overflow analysis

### Reporting

#### `report <type>`
Generate detailed reports:
- `report red` - Red Team operation summary
- `report blue` - Blue Team defense summary
- Automatic file saving
- JSON format for integration

## 🎨 Visual Enhancements

### Color Coding
- 🔴 **Red**: Errors and critical issues
- 🟡 **Yellow**: Warnings and important notes
- 🟢 **Green**: Success messages and confirmations
- 🔵 **Blue**: Information and headers
- 🟣 **Purple**: Special operations
- 🟦 **Cyan**: Data and statistics

### Status Indicators
- ✅ Success operations
- ❌ Failed operations
- ⚠️ Warnings and cautions
- ℹ️ Information messages
- 🔍 Analysis operations
- 🛡️ Security operations
- 🎯 Target operations

## 🔧 Configuration

### Environment Variables
The enhanced CLI respects all standard NeuroStrike environment variables:
- `OPENAI_API_KEY` - For AI-powered analysis
- `SAFE_MODE` - Enable/disable safe mode
- `AUTO_REMEDIATE` - Enable/disable auto-remediation

### Configuration Files
- Session data: `data/sessions/`
- Configuration backups: `data/configs/`
- Reports: `data/reports/`

## 🛡️ Safety Features

### Safe Mode
- All exploits are simulated by default
- Clear warnings before dangerous operations
- Confirmation prompts for destructive actions
- Detailed simulation results

### Auto-Save
- Automatic session backup every 10 commands
- Manual save/load capabilities
- Configuration preservation
- Command history retention

## 💡 Tips and Best Practices

### Getting Started
1. Always run `status` first to understand the current state
2. Use `set target` to establish a default target
3. Follow the suggested workflows for your use case
4. Use the tutorial system to learn advanced features

### Efficient Usage
- Use command history (↑/↓ arrows) to repeat commands
- Set up auto-save to preserve your work
- Use the `-A` flag for comprehensive scans
- Save sessions before complex operations

### Troubleshooting
- Check `status` if commands aren't working as expected
- Use `help <command>` for detailed command information
- Review error messages for specific suggestions
- Check log files in the `logs/` directory

## 🔗 Integration

The enhanced CLI is fully compatible with:
- All existing NeuroStrike agents and modules
- External security tools (nmap, metasploit, etc.)
- CI/CD pipelines via command-line arguments
- Custom scripts and automation

## 📞 Support

For issues or questions:
1. Check the built-in help system: `help`
2. Review the troubleshooting section
3. Check the project documentation
4. Report issues through the project repository

---

**Happy Hacking! 🔐**
