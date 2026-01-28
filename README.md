# Wazuh-OpenSearch MCP Bridge

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance **Model Context Protocol (MCP)** server built with **FastMCP** to provide AI agents with direct, real-time access to Wazuh security data via OpenSearch.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Tools](#api-tools)
  - [search_raw_logs](#search_raw_logs)
  - [search_alerts](#search_alerts)
  - [get_agent_data](#get_agent_data)
  - [search_vulnerabilities](#search_vulnerabilities)
- [License](#license)
- [Contributing](#contributing)
- [Support](#support)

## Overview

This bridge allows Agentic AI frameworks (like OpenWebUI or custom LangGraph setups) to query security telemetry directly. It is designed to support:

* **SOC Automation:** Automated alert enrichment.
* **Vulnerability Management:** AI-driven scanning and prioritization.
* **Agentic IR:** Enabling "Executor" agents to pull logs for incident response.

## Features

- **Raw Log Search:** Query `wazuh-archives-*` for deep forensic analysis.
- **Alert Monitoring:** Fetch real-time alerts with severity filtering.
- **Agent Intelligence:** Retrieve status and metadata for specific Wazuh agents.
- **Vulnerability Queries:** Targeted search for vulnerability-detector groups.

## Prerequisites

- Python 3.8 or higher
- Access to a Wazuh OpenSearch instance
- Required Python packages (see [requirements.txt](requirements.txt))

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/wazuh-mcp-soc-automation.git
   cd wazuh-mcp-bridge
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Before running the server, you need to configure the connection to your OpenSearch instance:

1. Copy the sample environment file:
   ```bash
   cp .env.sample .env
   ```

2. Edit the `.env` file with your OpenSearch credentials:
   ```env
   OPENSEARCH_HOST="localhost"
   OPENSEARCH_PORT=9200
   OPENSEARCH_USER=admin
   OPENSEARCH_PASSWORD="your-opensearch-password"
   ```

## Usage

To start the MCP server, run:

```bash
python src/main.py
```

The server will start and listen for MCP requests from connected AI agents.

## API Tools

### search_raw_logs

Search for raw logs in OpenSearch based on a query and time range.

**Parameters:**
- `query` (str): The search query string
- `time_range` (str, optional): Time range for the search (default: "1h")

**Returns:**
List of log entries matching the query

### search_alerts

Search for Wazuh alerts in OpenSearch with a specified minimum severity level.

**Parameters:**
- `query` (str): The search query string
- `time_range` (str, optional): Time range for the search (default: "1h")
- `min_level` (int, optional): Minimum alert level (default: 0)

**Returns:**
List of alerts matching the criteria

### get_agent_data

Retrieve agent data from OpenSearch. Requires either agent_id or agent_name.

**Parameters:**
- `agent_id` (str, optional): The ID of the agent to query
- `agent_name` (str, optional): The name of the agent to query

**Returns:**
Agent data (status, version, etc.)

### search_vulnerabilities

Search for vulnerabilities in OpenSearch, with an optional query, time range, and minimum severity level.

**Parameters:**
- `query` (str, optional): The search query string (default: "*")
- `time_range` (str, optional): Time range for the search (default: "1h")
- `min_level` (int, optional): Minimum vulnerability level (default: 7)

**Returns:**
List of vulnerabilities matching the criteria

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Support

For support, please open an issue on the GitHub repository or contact the maintainers.
