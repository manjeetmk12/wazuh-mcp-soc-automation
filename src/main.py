
# File: main_opensearch.py
# This is a modified FastMCP server to directly query OpenSearch.

import logging
from loguru import logger
from mcp.server.fastmcp import FastMCP
from opensearchpy import OpenSearch
import os
from dotenv import load_dotenv
from pydantic import BaseModel

# Load environment variables for security
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger.info("✅ Starting OpenSearch-FastMCP server...")

# Retrieve connection details from environment variables
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD")

try:
    opensearch_client = OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=True,
        verify_certs=False, # Set to True in production with proper certificates
        ssl_assert_hostname=False
    )
    opensearch_client.info() # Test the connection
    logger.info("✅ Successfully connected to OpenSearch cluster.")
except Exception as e:
    logger.error(f"Error connecting to OpenSearch: {e}")
    opensearch_client = None

# Initialize FastMCP
mcp = FastMCP("wazuh-opensearch")

# 2. Tool to Search Raw Logs
@mcp.tool()
def search_raw_logs(query: str, time_range: str = "1h") -> list:
    """Searches for raw logs in OpenSearch based on a query and time range."""
    if not opensearch_client:
        return {"error": "OpenSearch client not initialized."}
    
    search_body = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": query}}],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}]
            }
        },
        "size": 20
    }
    
    try:
        response = opensearch_client.search(
            body=search_body,
            index="wazuh-archives-*" # Use the archive index for raw logs
        )
        return [hit['_source'] for hit in response['hits']['hits']]
    except Exception as e:
        logger.error(f"Error searching raw logs: {e}")
        return []

# 3. Tool to Search for Alerts
@mcp.tool()
def search_alerts(query: str, time_range: str = "1h", min_level: int = 0) -> list:
    """Searches for Wazuh alerts in OpenSearch with a specified minimum severity level."""
    if not opensearch_client:
        return {"error": "OpenSearch client not initialized."}
    
    search_body = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": query}}],
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"range": {"rule.level": {"gte": min_level}}}
                ]
            }
        },
        "size": 20
    }
    
    try:
        response = opensearch_client.search(
            body=search_body,
            index="wazuh-alerts-*" # Use the alerts index
        )
        return [hit['_source'] for hit in response['hits']['hits']]
    except Exception as e:
        logger.error(f"Error searching alerts: {e}")
        return []
    
# 4. Tool to Get Wazuh Agent Data (e.g., status, version)
@mcp.tool()
def get_agent_data(agent_id: str = None, agent_name: str = None) -> list:
    """
    Retrieves agent data from OpenSearch. Requires either agent_id or agent_name.
    """
    if not opensearch_client:
        return {"error": "OpenSearch client not initialized."}

    # Construct the query
    if agent_id:
        query_string = f"agent.id: \"{agent_id}\""
    elif agent_name:
        query_string = f"agent.name: \"{agent_name}\""
    else:
        return {"error": "Either agent_id or agent_name must be provided."}
    
    search_body = {
        "query": {
            "query_string": {"query": query_string}
        },
        "size": 1
    }
    
    try:
        response = opensearch_client.search(
            body=search_body,
            index="wazuh-agent-*" # Use the agent status index
        )
        return [hit['_source'] for hit in response['hits']['hits']]
    except Exception as e:
        logger.error(f"Error getting agent data: {e}")
        return []
    
# 5. Tool to Search for Vulnerabilities

@mcp.tool()
def search_vulnerabilities(query: str = "*", time_range: str = "1h", min_level: int = 7) -> list:
    """
    Searches for vulnerabilities in OpenSearch, with an optional query, time range,
    and a minimum severity level.
    """
    if not opensearch_client:
        return {"error": "OpenSearch client not initialized."}

    # The specific query for vulnerability alerts
    vulnerability_query = "rule.groups:vulnerability-detector"
    
    # Combine the specific vulnerability query with the user's query
    if query and query != "*":
        combined_query = f"{vulnerability_query} AND ({query})"
    else:
        combined_query = vulnerability_query

    search_body = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": combined_query}}],
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"range": {"rule.level": {"gte": min_level}}}
                ]
            }
        },
        "size": 20
    }
    
    try:
        response = opensearch_client.search(
            body=search_body,
            index="wazuh-alerts-*" # Vulnerability alerts are in the alerts index
        )
        return [hit['_source'] for hit in response['hits']['hits']]
    except Exception as e:
        logger.error(f"Error searching vulnerabilities: {e}")
        return []

# 5. Start FastMCP server
if __name__== "__main__":
    mcp.run(transport="stdio")
