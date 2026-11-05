import { writeFileSync, rmSync } from "node:fs";

export function archive(name, body) {
  writeFileSync(`/tmp/${name}.archive`, body);
  rmSync(`${name}.json`);
}
