# Phishing Link Scanner

A comprehensive tool for scanning URLs to identify potential phishing threats using multiple detection methods.

## Features

- **Heuristic Pattern Analysis**: Detect suspicious patterns in URLs
- **VirusTotal Integration**: Scan URLs against VirusTotal's database of known threats
- **Google Safe Browsing API**: Use Google's threat intelligence to identify malicious URLs
- **Database Storage**: Save scan results for future reference
- **User-friendly GUI**: Easy-to-use interface with Tkinter
- **Detailed Reports**: Comprehensive scanning results with risk assessment
- **History Management**: View, search, and manage previous scan results
- **Direct VirusTotal Web Check**: Easily check URLs on VirusTotal's web interface even without an API key
- **Google Safe Browsing Web Check**: Check URLs against Google's Safe Browsing service even without an API key

## Screenshots

(Add screenshots of your application here)

## Installation

### Prerequisites

- Python 3.6 or higher
- Required Python packages (install using `pip install -r requirements.txt`):
  - requests
  - sqlite3 (usually included with Python)
  - tkinter (usually included with Python)

### Setup

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/phishing-link-scanner.git
   cd phishing-link-scanner
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

3. (Optional) Obtain API keys:
   - [VirusTotal API Key](https://www.virustotal.com/gui/join-us)
   - [Google Safe Browsing API Key](https://developers.google.com/safe-browsing/v4/get-started)

## Usage

### GUI Mode

Run the application with a graphical user interface:

```
python main.py
```

or

```
python main.py gui
```

#### Direct VirusTotal Checking

For any scan, you can:
1. Click the "Check on VirusTotal" button to open the URL directly in VirusTotal's web interface
2. View detailed results including web-based VirusTotal information when API keys aren't available

#### Google Safe Browsing Integration

You can also:
1. Click the "Check on Google Safe Browsing" button to open the URL in Google's Transparency Report
2. View web-based Google Safe Browsing results directly in the application
3. Get alerts about potentially harmful websites without needing to configure an API key

### Command Line Mode

Scan URLs directly from the command line:

```
python main.py cli example.com suspicious-site.com --output report.json
```

Optional arguments:
- `--vt-api-key`: Your VirusTotal API key
- `--gsb-api-key`: Your Google Safe Browsing API key
- `--output`: Save results to a file (JSON format)

## Configuration

API keys can be configured in the GUI under the Settings tab or stored in a `settings.json` file:

```json
{
  "vt_api_key": "your-virustotal-api-key",
  "gsb_api_key": "your-google-safe-browsing-api-key"
}
```

If API keys are not provided, the application can still:
- Run heuristic analysis on URLs
- Attempt to fetch information from VirusTotal's web interface
- Check URLs against Google's Safe Browsing service via web interface
- Provide buttons to check URLs directly on VirusTotal and Google Safe Browsing websites

## Database

Scan results are stored in a SQLite database file (`phishing_scanner.db`). The database contains:

- URL information
- Scan timestamp
- Risk assessment
- Detailed scan results

## Project Structure

- `main.py`: Main entry point
- `phiscanner.py`: Core scanning functionality
- `phiscanner_ui.py`: Tkinter GUI implementation
- `database.py`: Database handling for scan results
- `phishing_scanner.db`: SQLite database file for storing results
- `settings.json`: Configuration file for API keys

## Limitations

- Free API tiers have rate limits
- Heuristic detection may result in false positives
- No offline scanning capabilities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- VirusTotal for threat intelligence
- Google Safe Browsing for phishing detection
- Tkinter for the GUI framework 