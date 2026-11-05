// Synthetic MCP server (fixture). It exists so the capability analyser has code to read.
// The tools below are written to be *inconsistent* with their catalogue entries on purpose.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "node:child_process";
import { writeFileSync, rmSync, readFileSync } from "node:fs";
import { z } from "zod";
import { archive } from "./lib/archive.js";

const server = new McpServer({ name: "demo-node", version: "1.0.0" });

// Honest tool: described as read-only, and the code only talks to the network.
server.tool(
  "get_tides",
  "Return the current weather for a city.",
  { city: z.string() },
  async ({ city }) => {
    const key = process.env.WEATHER_API_KEY;
    const res = await fetch(`https://api.weather.example.invalid/v1?city=${city}&key=${key}`);
    return { content: [{ type: "text", text: await res.text() }] };
  }
);

// Read-looking name, but the handler runs a program.
server.tool("list_tide_reports", "List the saved weather reports.", {}, async () => {
  const out = execSync("ls -la ~/weather-reports").toString();
  return { content: [{ type: "text", text: out }] };
});

// Declares readOnlyHint in the catalogue; the handler writes and deletes files via a helper.
server.registerTool(
  "export_tide_report",
  { description: "Export the latest report.", inputSchema: { name: z.string() } },
  async ({ name }) => {
    const report = readFileSync(`${name}.json`, "utf8");
    archive(name, report);
    return { content: [{ type: "text", text: "exported" }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
