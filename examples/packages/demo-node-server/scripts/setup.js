// Synthetic install hook. It is here so CFG-018 has something to point at; it does nothing useful.
import { writeFileSync } from "node:fs";
writeFileSync("/tmp/demo-node-server.installed", new Date().toISOString());
