# AI SOC Co-Pilot

**Copilot for Security Teams – AI that reads logs, explains incidents, and suggests actions.**

An intelligent Security Operations Center (SOC) assistant that analyzes security logs, provides plain-English summaries, maps events to MITRE ATT&CK framework, and suggests actionable responses for security analysts.

## Features

- **Log Analysis**: Parse and analyze JSON security logs (CloudTrail, SIEM events, etc.)
- **MITRE ATT&CK Mapping**: Rule-based mapping to MITRE ATT&CK tactics and techniques
- **AI-Powered Insights**: Uses OpenAI GPT models to generate human-readable summaries
- **Severity Assessment**: Automatic severity scoring based on log content and threat indicators
- **Actionable Recommendations**: Provides specific actions for security analysts to take
- **Slack Integration Ready**: Generates formatted alerts for SOC team channels
- **Interactive Web UI**: Clean Streamlit interface for easy log analysis

## Quick Start

### Prerequisites

- Python 3.8+
- OpenAI API key (optional but recommended for AI features)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd "AI SOC Co-Pilot"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up your OpenAI API key (optional):
```bash
# Create a .env file
echo "OPENAI_API_KEY=your_openai_api_key_here" > .env
```

### Running the Application

```bash
streamlit run streamlit_app.py
```

The application will open in your browser at `http://localhost:8501`

## Usage

1. **Upload a Log**: Use the file uploader or paste JSON directly into the text area
2. **Analyze**: Click the "Analyze log" button
3. **Review Results**:
   - View parsed key fields
   - See MITRE ATT&CK mappings
   - Check severity assessment
   - Read AI-generated summary and recommendations
   - Copy Slack alert text for team notifications

### Example Log Format

The tool works with various JSON log formats. See `sample_logs/example_cloudtrail.json` for a CloudTrail example:

```json
{
  "eventName": "ConsoleLogin",
  "eventSource": "signin.amazonaws.com",
  "userIdentity": {
    "userName": "Alice"
  },
  "sourceIPAddress": "198.51.100.23",
  "responseElements": {
    "ConsoleLogin": "Failure"
  }
}
```

## Configuration Options

- **OpenAI Integration**: Set `OPENAI_API_KEY` environment variable for AI features
- **Ollama Support**: Set `USE_OLLAMA = True` in `streamlit_app.py` for local LLM usage
- **MITRE Rules**: Extend `MITRE_RULES` in `mitre_mapping.py` for custom threat detection

## Architecture

### Core Components

- **streamlit_app.py**: Main application with UI and orchestration logic
- **mitre_mapping.py**: Rule-based MITRE ATT&CK mapping definitions
- **sample_logs/**: Example security logs for testing

### Analysis Pipeline

1. **JSON Parsing**: Validates and parses input logs
2. **Field Extraction**: Extracts key security-relevant fields
3. **MITRE Mapping**: Applies rule-based matching to MITRE ATT&CK framework
4. **Severity Scoring**: Calculates risk level based on indicators
5. **AI Analysis**: Generates summary and recommendations using LLM
6. **Output Generation**: Formats results for analyst consumption

## Extending the Tool

### Adding MITRE Rules

Edit `mitre_mapping.py` to add new detection rules:

```python
MITRE_RULES = [
    ("your_keyword", "MITRE_Tactic", "Description of the threat"),
    # Add more rules here
]
```

### Customizing Severity Scoring

Modify the `severity_score()` function in `streamlit_app.py` to adjust risk calculations.

### Supporting New Log Formats

Extend the `extract_fields()` function to parse additional log types and formats.

## Security Considerations

- **API Keys**: Store API keys securely using environment variables or .env files
- **Log Privacy**: Be mindful of sensitive data in logs when using external AI services
- **Human Review**: Always verify AI-generated recommendations before taking action
- **Network Security**: Consider running in isolated environments for sensitive logs

## Contributing

This is a prototype/demonstration tool. Contributions for additional log formats, MITRE rules, and analysis capabilities are welcome.
