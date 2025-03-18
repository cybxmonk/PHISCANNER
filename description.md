# PhiScanner: Advanced Phishing URL Detection Tool

PhiScanner is a sophisticated cybersecurity tool designed to help users identify potentially dangerous URLs that may be associated with phishing attacks. With its powerful detection capabilities and user-friendly interface, PhiScanner provides an accessible way for both technical and non-technical users to verify the safety of web links before visiting them.

## Overview

Phishing attacks remain one of the most common and effective cyber threats, with attackers creating increasingly convincing fake websites to steal sensitive information. PhiScanner helps combat this threat by analyzing URLs through multiple detection methods and providing clear risk assessments, all within a modern, intuitive interface.

## Key Features

### Multi-layered Detection

PhiScanner employs a comprehensive, multi-layered approach to URL analysis:

1. **Heuristic Pattern Analysis**: 
   - Examines URL structure for suspicious patterns
   - Detects common phishing indicators like unusual subdomains, numeric patterns, and excessive URL parameters
   - Identifies suspicious TLDs and domain patterns commonly associated with phishing
   - Advanced whitelist system for legitimate security services

2. **VirusTotal Integration**:
   - Checks URLs against VirusTotal's extensive database
   - Provides detailed breakdowns of detection statistics
   - Works with or without an API key (falls back to web interface when no API key is available)
   - One-click access to full VirusTotal analysis

3. **Google Safe Browsing**:
   - Leverages Google's threat intelligence system
   - Identifies known malicious websites
   - Works with or without an API key (using Transparency Report when no API key is available)
   - Provides specific information about the type of threat (malware, phishing, etc.)

### User-Friendly Interface

PhiScanner features a clean, modern interface designed for ease of use:

1. **Visual Risk Indicators**:
   - Color-coded risk levels (green for low, orange for medium, red for high)
   - Interactive visual gauge showing risk level
   - Prominent warning messages for suspicious URLs

2. **Detailed Results Display**:
   - Comprehensive breakdown of detection results
   - Clear explanations of why URLs are flagged
   - Links to external verification sources
   - Formatted for easy understanding

3. **History Management**:
   - Complete history of all scanned URLs
   - Searchable database of previous scans
   - Detailed view of historical scan results
   - Ability to delete old scan records

### Offline and Online Capabilities

PhiScanner can work effectively even without internet access or API keys:

1. **Standalone Heuristic Detection**:
   - Sophisticated pattern analysis works offline
   - No API keys required for basic functionality
   - Advanced algorithms to minimize false positives

2. **Web Integration**:
   - Fallback to web interfaces when API keys aren't available
   - Direct buttons to check URLs on VirusTotal and Google Safe Browsing
   - Ability to extract information from web services

### Database and History

Keep track of all your URL scans:

1. **SQLite Database**:
   - Automatically saves all scan results
   - Maintains complete scan history
   - Stores detailed analysis data

2. **History Management**:
   - View previous scan results
   - Search for specific URLs
   - Sort by date, risk level, or URL

## How It Works

1. **URL Input**:
   - Enter any URL you want to check
   - Automatically adds HTTP/HTTPS if missing
   - Supports batch scanning of multiple URLs

2. **Analysis Process**:
   - URL is checked against heuristic patterns
   - If API keys are available, checks against VirusTotal and Google Safe Browsing
   - If no API keys, uses web-based alternatives
   - Results are combined to determine overall risk level

3. **Results Display**:
   - Clear risk level indicator (Low, Medium, High)
   - Visual gauge showing risk position
   - Detailed breakdown of detection results
   - Explanation of why the URL was flagged (if applicable)

4. **Additional Verification**:
   - One-click buttons to check on VirusTotal
   - One-click buttons to check on Google Safe Browsing
   - Detailed view with raw data for technical users

## Benefits

1. **Enhanced Security**:
   - Prevent phishing attacks before they happen
   - Protect sensitive personal and financial information
   - Avoid malware infections from malicious websites

2. **Accessibility**:
   - User-friendly interface for non-technical users
   - Detailed data for security professionals
   - Works with or without API keys

3. **Comprehensive Analysis**:
   - Multiple detection methods reduce false negatives
   - Advanced heuristics catch new phishing sites
   - Integration with major security services

4. **Educational Value**:
   - Learn about common phishing techniques
   - Understand what makes URLs suspicious
   - Develop better cybersecurity habits

## Use Cases

1. **Personal Security**:
   - Check suspicious links from emails before clicking
   - Verify links shared in messaging apps
   - Ensure shopping websites are legitimate

2. **Organizational Security**:
   - Help desk tool for verifying reported suspicious URLs
   - Security awareness training tool
   - First-line defense against targeted phishing campaigns

3. **Security Research**:
   - Analyze suspected phishing campaigns
   - Build databases of malicious URLs
   - Test detection capabilities

## Technical Details

Built with Python and modern libraries:
- **Backend**: Pure Python with requests for API communication
- **Database**: SQLite for efficient local storage
- **User Interface**: Tkinter for cross-platform compatibility
- **API Integration**: VirusTotal and Google Safe Browsing APIs

## Getting Started

Run the application with a simple command:

```
python main.py
```

For the best experience, consider obtaining free API keys for:
- VirusTotal: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
- Google Safe Browsing: [https://developers.google.com/safe-browsing/v4/get-started](https://developers.google.com/safe-browsing/v4/get-started)

However, PhiScanner works effectively even without these keys, falling back to web-based methods and heuristic analysis.

## Conclusion

PhiScanner provides a powerful, user-friendly solution for identifying phishing URLs before they can cause harm. With its multi-layered detection approach, intuitive interface, and flexible deployment options, it's an essential tool for anyone concerned about online security in today's threat landscape. 