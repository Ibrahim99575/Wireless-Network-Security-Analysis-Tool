# Wireless-Network-Security-Analysis-Tool

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

Welcome to the Wireless Network Security Analysis Tool project! This project aims to develop a comprehensive tool to assess the security of wireless networks, focusing on various aspects like authentication, encryption, password complexity, and network isolation. The tool is designed to provide real-time vulnerability detection, prioritize risks, and offer actionable recommendations to enhance the security posture of Wi-Fi networks.

## Table of Contents
- [Introduction](#introduction)
- [Problem Statement](#problem-statement)
- [Research Objectives](#research-objectives)
- [Proposed System](#proposed-system)
  - [System Diagram](#system-diagram)
  - [Modules](#modules)
- [Implementation](#implementation)
- [Results & Discussions](#results--discussions)
- [Conclusions & Future Work](#conclusions--future-work)
- [Conclusion](#conclusion)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Introduction
In an era where remote work and constant connectivity via wireless networks are the norm, ensuring the security of data transmission has become a critical issue. This project explores the evolution of wireless network security protocols since the late 1990s and emphasizes the need for continual adaptation to combat evolving cyber threats. By analyzing existing standards and protocols, this project aims to identify vulnerabilities and propose modernized security practices.

## Problem Statement
Wireless networks face escalating complexity and evolving cyber threats, making them vulnerable to breaches and data compromise. The proliferation of public Wi-Fi networks poses significant security risks, as users often lack accessible methods to assess the safety of these networks. There's a notable absence of a user-friendly security analysis tool tailored for average users, which hinders proactive vulnerability identification and mitigation.

## Research Objectives
- Develop a tool for real-time vulnerability detection in wireless networks.
- Prioritize vulnerabilities based on their potential risk and impact.
- Provide clear, actionable recommendations to address vulnerabilities.
- Ensure the tool integrates seamlessly with existing security infrastructure.
- Implement a security scoring system within the tool.
- Assess authentication, encryption, and password complexity to gauge Wi-Fi network security.

## Proposed System
### System Diagram

<img src="[https://github.com/Ibrahim99575/web-drum-play/blob/bc39e933259468ad10ab23f96306e046926f3ba4/UI.png](https://github.com/Ibrahim99575/Wireless-Network-Security-Analysis-Tool/blob/a0172ae5859c2ff7b1863f5ad51b0597cfb1d8ec/block_diagram_pages-to-jpg-0001.jpg)"/>

### Modules
- #### Protocol Analysis Module: Analyzes wireless network protocols and assesses their security. Provides a protocol score based on the analysis.

- #### Firewall Detection Module: Detects the presence and effectiveness of network firewalls. Assigns a firewall score based on the findings.

- #### Password Analysis Module: Evaluates the strength of Wi-Fi passwords.Uses entropy calculation and common password checks to determine a password score.

- #### Network Isolation Detection Module: Checks for network isolation measures. Provides a network isolation score.

- #### Secure Score Assessment Module: Aggregates scores from all modules to generate a comprehensive secure score.

## Implementation
The tool is implemented in Python and utilizes several libraries, including math, collections.Counter, and a generative AI module for advanced analysis. The password analysis algorithm calculates entropy and checks against a dictionary of common passwords to determine password strength.

## Results & Discussions
This project introduces a novel security score system to help users evaluate the robustness of wireless networks. The findings highlight the critical importance of secure Wi-Fi networks, exemplified by the strong security of certain testbeds compared to insecure public networks. The tool provides a comprehensive assessment and offers actionable insights to improve network security.

## Conclusions & Future Work
The Wireless Network Security Analysis Tool provides an accessible solution for assessing Wi-Fi security. It integrates multiple security checks and produces a secure score to guide users in enhancing their network defenses. Future work includes optimizing the web scraping module for real-time scoring, exploring packet capture techniques, and considering integration with antivirus software for broader security coverage.

## Conclusion
This project introduces a novel tool for assessing Wi-Fi security, providing an accessible solution for users to gauge their network's vulnerability. By incorporating modules for firewall detection, network isolation, protocol analysis, and password strength assessment, along with a secure score, the tool offers a comprehensive approach to network security.

## Installation
### Prerequisites
- Python 3.8 or higher
- Internet connection for fetching security updates

### Steps
1. Clone the repository:

``` 
git clone https://github.com/yourusername/wireless-network-security-tool.git
cd wireless-network-security-tool
```

2. Install required dependencies:

`
pip install -r requirements.txt
`

3. Run the tool:

`
python main.py
`

## Usage
1. Launch the Tool:
`
python main.py
`

2. Enter Wi-Fi Details: Input your Wi-Fi SSID and password.

3. Analyze Network: Click on Analyze to start the security assessment.

4. View Results: The tool will provide a security score and actionable recommendations.

## License
This project is open-source and available under the <a href="https://github.com/Ibrahim99575/web-drum-play/blob/fd574d3b7ff978c83c95bece92f8c7ba4486b120/LICENSE/">MIT License</a>.
For more details and to access the tool, please visit the project repository.

If you have any questions or need further assistance, feel free to contact the project maintainer, Ibrahim Ali, at ibrahim.ali.99575@gmail.com.

Happy securing! 🚀🔒
