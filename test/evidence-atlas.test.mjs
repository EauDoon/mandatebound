import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("each link in the offline atlas maps to a shipped source dependency", () => {
  const html = readFileSync(new URL("../docs/evidence-atlas.html", import.meta.url), "utf8");
  const modules = new Map([...html.matchAll(/<details data-node="([^"]+)"[^>]*>([\s\S]*?)<\/details>/gu)]
    .map(([, id, body]) => [id, body]));
  assert.ok(modules.size > 1);
  for (const [id, body] of modules) {
    const source = readFileSync(new URL(`../src/${id}.ts`, import.meta.url), "utf8");
    assert.ok(body.includes(`https://github.com/EauDoon/mandatebound/blob/main/src/${id}.ts`), id);
    for (const [, dependency, target] of body.matchAll(/data-edge="([^"]+)" href="#record-([^"]+)"/gu)) {
      assert.equal(dependency, target);
      assert.ok(modules.has(target), target);
      assert.ok(source.includes(`from "./${target}.js"`) || source.includes(`import("./${target}.js")`), `${id} -> ${target}`);
    }
  }
});
