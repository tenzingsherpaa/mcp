# AWS MCP Servers - Samples

This directory contains a collection of examples demonstrating how to use the AWS MCP Servers provided in the `src` directory. Each sample is organized into its own folder with relevant documentation and code.

## Structure

```bash
samples/
├── project-name/
│   ├── README.md
│   └── (sample code and resources)
```

## Purpose

The samples in this directory provide:

- Working examples for each AWS MCP Server
- Integration patterns and best practices
- Code snippets for common use cases
- Step-by-step guides

## Guidelines

- Each sample directory should focus on demonstrating one or more MCP servers
- All samples must include a README.md with clear instructions
- Samples should not introduce new MCP servers, but only demonstrate usage of existing ones

## Available Samples

### MCP Integration with KB

A client that integrates with the Amazon Bedrock Knowledge Base MCP server. Code can be found in the [mcp-integration-with-kb](https://github.com/awslabs/mcp/tree/main/samples/mcp-integration-with-kb) folder.

### AWS Step Functions Tool MCP Server

A server that enables AI models to execute AWS Step Functions state machines as tools, allowing seamless integration with existing workflows. The server supports both Standard and Express workflows, and integrates with EventBridge Schema Registry for input validation. Code can be found in the [src/stepfunctions-tool-mcp-server](https://github.com/awslabs/mcp/tree/main/src/stepfunctions-tool-mcp-server) folder.

### Coming Soon

## Contributing

We welcome contributions of additional samples. Please ensure your sample follows the guidelines above and demonstrates real-world usage of the MCP servers.
