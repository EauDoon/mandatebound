import { sha256Digest } from "./canonical.js";
import type {
  LiabilityOutcome,
  LiabilityPolicy,
  Rulebook,
  ValidationIssue,
} from "./domain.js";
import {
  POLICY_FACT_NAMES,
  POLICY_FACT_VALUES,
  evaluateRulebook,
  validateRulebook,
  type PolicyFactName,
  type PolicyFacts,
} from "./policy.js";
import { validateArtifact } from "./validation.js";

const MAX_POLICY_TEST_CASES = 256;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface PolicyPack {
  readonly policy: LiabilityPolicy;
  readonly rulebook: Rulebook;
}

export interface PolicyToolIssue {
  readonly code:
    | "MB_POLICY_SHAPE"
    | "MB_POLICY_SCHEMA"
    | "MB_POLICY_DSL"
    | "MB_POLICY_REFERENCE"
    | "MB_POLICY_TEST";
  readonly path: string;
  readonly message: string;
}

export interface PolicyPackValidationReport {
  readonly valid: boolean;
  readonly policyDigest?: ReturnType<typeof sha256Digest>;
  readonly rulebookDigest?: ReturnType<typeof sha256Digest>;
  readonly issues: readonly PolicyToolIssue[];
}

export interface PolicyTestExpectation {
  readonly outcome: LiabilityOutcome;
  readonly reasonCode?: string;
}

export interface PolicyTestCase {
  readonly id: string;
  readonly facts: PolicyFacts;
  readonly expected: PolicyTestExpectation;
}

export interface PolicyTestResult {
  readonly id: string;
  readonly passed: boolean;
  readonly expected: PolicyTestExpectation;
  readonly actual: {
    readonly outcome: LiabilityOutcome;
    readonly reasonCode: string;
    readonly matchedRuleId?: string;
  };
}

export interface PolicyTestReport {
  readonly valid: boolean;
  readonly passed: boolean;
  readonly total: number;
  readonly passedCount: number;
  readonly failedCount: number;
  readonly results: readonly PolicyTestResult[];
  readonly issues: readonly PolicyToolIssue[];
}

export interface RuleChange {
  readonly ruleId: string;
  readonly change: "added" | "removed" | "modified";
  readonly beforeDigest?: ReturnType<typeof sha256Digest>;
  readonly afterDigest?: ReturnType<typeof sha256Digest>;
}

export interface PolicyBehaviorChange {
  readonly caseId: string;
  readonly before: {
    readonly outcome: LiabilityOutcome;
    readonly reasonCode: string;
    readonly matchedRuleId?: string;
  };
  readonly after: {
    readonly outcome: LiabilityOutcome;
    readonly reasonCode: string;
    readonly matchedRuleId?: string;
  };
}

export interface RulebookDiffReport {
  readonly valid: boolean;
  readonly changed: boolean;
  readonly beforeDigest?: ReturnType<typeof sha256Digest>;
  readonly afterDigest?: ReturnType<typeof sha256Digest>;
  readonly revision: {
    readonly before?: number;
    readonly after?: number;
    readonly changed: boolean;
  };
  readonly defaultOutcomeChanged: boolean;
  readonly rules: readonly RuleChange[];
  readonly behaviorChanges: readonly PolicyBehaviorChange[];
  readonly issues: readonly PolicyToolIssue[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}

function schemaIssues(prefix: string, issues: readonly ValidationIssue[]): readonly PolicyToolIssue[] {
  return issues.map((issue) => ({
    code: "MB_POLICY_SCHEMA",
    path: `${prefix}${issue.path}`,
    message: "Policy artifact schema validation failed",
  }));
}

function invalidShape(path: string, message: string): PolicyToolIssue {
  return { code: "MB_POLICY_SHAPE", path, message };
}

function parsePolicyPack(input: unknown): {
  readonly pack?: PolicyPack;
  readonly report: PolicyPackValidationReport;
} {
  if (!isRecord(input) || !hasExactKeys(input, ["policy", "rulebook"])) {
    return {
      report: {
        valid: false,
        issues: [invalidShape("$", "Policy pack must contain only policy and rulebook")],
      },
    };
  }

  const policyValidation = validateArtifact<LiabilityPolicy>("liability_policy", input["policy"]);
  const rulebookSchema = validateArtifact<Rulebook>("rulebook", input["rulebook"]);
  const rulebookDsl = validateRulebook(input["rulebook"]);
  const issues: PolicyToolIssue[] = [
    ...(policyValidation.ok ? [] : schemaIssues("$.policy", policyValidation.issues)),
    ...(rulebookSchema.ok ? [] : schemaIssues("$.rulebook", rulebookSchema.issues)),
    ...rulebookDsl.issues.map((issue) => ({
      code: "MB_POLICY_DSL" as const,
      path: `$.rulebook${issue.path === "$" ? "" : issue.path.slice(1)}`,
      message: "Rulebook is outside the bounded policy language",
    })),
  ];

  if (!policyValidation.ok || !rulebookSchema.ok || !rulebookDsl.valid) {
    return { report: { valid: false, issues } };
  }

  const policy = policyValidation.value;
  const rulebook = rulebookSchema.value;
  const policyDigest = sha256Digest(policy);
  const rulebookDigest = sha256Digest(rulebook);
  if (
    policy.rulebookRef.artifactType !== "rulebook"
    || policy.rulebookRef.artifactId !== rulebook.artifactId
    || policy.rulebookRef.digest !== rulebookDigest
  ) {
    issues.push({
      code: "MB_POLICY_REFERENCE",
      path: "$.policy.rulebookRef",
      message: "Policy rulebook reference does not match the supplied rulebook",
    });
  }

  return {
    ...(issues.length === 0 ? { pack: { policy, rulebook } } : {}),
    report: {
      valid: issues.length === 0,
      policyDigest,
      rulebookDigest,
      issues,
    },
  };
}

export function validatePolicyPack(input: unknown): PolicyPackValidationReport {
  return parsePolicyPack(input).report;
}

function validateFacts(value: unknown, path: string): {
  readonly facts?: PolicyFacts;
  readonly issues: readonly PolicyToolIssue[];
} {
  if (!isRecord(value)) {
    return { issues: [invalidShape(path, "Policy facts must be an object")] };
  }
  const actualNames = Object.keys(value).sort();
  if (
    actualNames.length !== POLICY_FACT_NAMES.length
    || actualNames.some((name, index) => name !== POLICY_FACT_NAMES[index])
  ) {
    return { issues: [invalidShape(path, "Policy facts must use the complete closed vocabulary")] };
  }
  const issues: PolicyToolIssue[] = [];
  for (const name of POLICY_FACT_NAMES) {
    const allowed = POLICY_FACT_VALUES[name] as readonly string[];
    if (typeof value[name] !== "string" || !allowed.includes(value[name])) {
      issues.push(invalidShape(`${path}.${name}`, "Policy fact value is not allowed"));
    }
  }
  return issues.length === 0
    ? { facts: value as unknown as PolicyFacts, issues }
    : { issues };
}

function validatePolicyTestCases(input: unknown): {
  readonly cases?: readonly PolicyTestCase[];
  readonly issues: readonly PolicyToolIssue[];
} {
  if (!Array.isArray(input) || input.length === 0 || input.length > MAX_POLICY_TEST_CASES) {
    return {
      issues: [invalidShape("$.cases", "Policy tests must contain 1 to 256 cases")],
    };
  }
  const issues: PolicyToolIssue[] = [];
  const cases: PolicyTestCase[] = [];
  const ids = new Set<string>();
  for (const [index, candidate] of input.entries()) {
    const path = `$.cases[${String(index)}]`;
    if (
      !isRecord(candidate)
      || !hasExactKeys(candidate, ["id", "facts", "expected"])
      || typeof candidate["id"] !== "string"
      || !IDENTIFIER.test(candidate["id"])
    ) {
      issues.push(invalidShape(path, "Policy test case has an invalid closed shape"));
      continue;
    }
    if (ids.has(candidate["id"])) {
      issues.push(invalidShape(`${path}.id`, "Policy test identifiers must be unique"));
      continue;
    }
    ids.add(candidate["id"]);
    const facts = validateFacts(candidate["facts"], `${path}.facts`);
    issues.push(...facts.issues);
    const expected = candidate["expected"];
    if (
      !isRecord(expected)
      || !hasExactKeys(expected, ["outcome"], ["reasonCode"])
      || !["principal", "operator", "model_vendor", "unresolved"].includes(
        String(expected["outcome"]),
      )
      || (
        expected["reasonCode"] !== undefined
        && (typeof expected["reasonCode"] !== "string" || !IDENTIFIER.test(expected["reasonCode"]))
      )
    ) {
      issues.push(invalidShape(`${path}.expected`, "Policy test expectation is invalid"));
      continue;
    }
    if (facts.facts !== undefined) {
      cases.push({
        id: candidate["id"],
        facts: facts.facts,
        expected: {
          outcome: expected["outcome"] as LiabilityOutcome,
          ...(typeof expected["reasonCode"] === "string"
            ? { reasonCode: expected["reasonCode"] }
            : {}),
        },
      });
    }
  }
  return issues.length === 0 ? { cases, issues } : { issues };
}

export function testPolicyPack(input: unknown): PolicyTestReport {
  if (
    !isRecord(input)
    || !hasExactKeys(input, ["policy", "rulebook", "cases"])
  ) {
    return {
      valid: false,
      passed: false,
      total: 0,
      passedCount: 0,
      failedCount: 0,
      results: [],
      issues: [invalidShape("$", "Policy test input must contain policy, rulebook, and cases")],
    };
  }
  const parsed = parsePolicyPack({ policy: input["policy"], rulebook: input["rulebook"] });
  const tests = validatePolicyTestCases(input["cases"]);
  const issues = [...parsed.report.issues, ...tests.issues];
  if (parsed.pack === undefined || tests.cases === undefined) {
    return {
      valid: false,
      passed: false,
      total: 0,
      passedCount: 0,
      failedCount: 0,
      results: [],
      issues,
    };
  }

  const pack = parsed.pack;
  const results = tests.cases.map((testCase): PolicyTestResult => {
    const evaluated = evaluateRulebook(pack.rulebook, testCase.facts);
    const passed = evaluated.outcome === testCase.expected.outcome
      && (
        testCase.expected.reasonCode === undefined
        || evaluated.reasonCode === testCase.expected.reasonCode
      );
    return {
      id: testCase.id,
      passed,
      expected: testCase.expected,
      actual: {
        outcome: evaluated.outcome,
        reasonCode: evaluated.reasonCode,
        ...(evaluated.matchedRuleId === undefined
          ? {}
          : { matchedRuleId: evaluated.matchedRuleId }),
      },
    };
  });
  const passedCount = results.filter((result) => result.passed).length;
  return {
    valid: true,
    passed: passedCount === results.length,
    total: results.length,
    passedCount,
    failedCount: results.length - passedCount,
    results,
    issues: [],
  };
}

function validateRulebookForDiff(
  value: unknown,
  path: "$.before" | "$.after",
): { readonly rulebook?: Rulebook; readonly issues: readonly PolicyToolIssue[] } {
  const schema = validateArtifact<Rulebook>("rulebook", value);
  const dsl = validateRulebook(value);
  const issues: PolicyToolIssue[] = [
    ...(schema.ok ? [] : schemaIssues(path, schema.issues)),
    ...dsl.issues.map((issue) => ({
      code: "MB_POLICY_DSL" as const,
      path: `${path}${issue.path === "$" ? "" : issue.path.slice(1)}`,
      message: "Rulebook is outside the bounded policy language",
    })),
  ];
  return schema.ok && dsl.valid
    ? { rulebook: schema.value, issues }
    : { issues };
}

export function diffRulebooks(input: unknown): RulebookDiffReport {
  if (
    !isRecord(input)
    || !hasExactKeys(input, ["before", "after"], ["cases"])
  ) {
    return {
      valid: false,
      changed: false,
      revision: { changed: false },
      defaultOutcomeChanged: false,
      rules: [],
      behaviorChanges: [],
      issues: [invalidShape("$", "Rulebook diff input must contain before and after")],
    };
  }
  const before = validateRulebookForDiff(input["before"], "$.before");
  const after = validateRulebookForDiff(input["after"], "$.after");
  const cases = input["cases"] === undefined
    ? { cases: [] as readonly PolicyTestCase[], issues: [] as readonly PolicyToolIssue[] }
    : validatePolicyTestCases(input["cases"]);
  const issues = [...before.issues, ...after.issues, ...cases.issues];
  if (before.rulebook === undefined || after.rulebook === undefined || cases.cases === undefined) {
    return {
      valid: false,
      changed: false,
      revision: { changed: false },
      defaultOutcomeChanged: false,
      rules: [],
      behaviorChanges: [],
      issues,
    };
  }

  const beforeRules = new Map(before.rulebook.rules.map((rule) => [rule.id, rule]));
  const afterRules = new Map(after.rulebook.rules.map((rule) => [rule.id, rule]));
  const ids = [...new Set([...beforeRules.keys(), ...afterRules.keys()])].sort();
  const rules: RuleChange[] = [];
  for (const ruleId of ids) {
    const previous = beforeRules.get(ruleId);
    const next = afterRules.get(ruleId);
    if (previous === undefined && next !== undefined) {
      rules.push({ ruleId, change: "added", afterDigest: sha256Digest(next) });
    } else if (previous !== undefined && next === undefined) {
      rules.push({ ruleId, change: "removed", beforeDigest: sha256Digest(previous) });
    } else if (
      previous !== undefined
      && next !== undefined
      && sha256Digest(previous) !== sha256Digest(next)
    ) {
      rules.push({
        ruleId,
        change: "modified",
        beforeDigest: sha256Digest(previous),
        afterDigest: sha256Digest(next),
      });
    }
  }

  const behaviorChanges: PolicyBehaviorChange[] = [];
  for (const testCase of cases.cases) {
    const previous = evaluateRulebook(before.rulebook, testCase.facts);
    const next = evaluateRulebook(after.rulebook, testCase.facts);
    if (
      previous.outcome !== next.outcome
      || previous.reasonCode !== next.reasonCode
      || previous.matchedRuleId !== next.matchedRuleId
    ) {
      behaviorChanges.push({
        caseId: testCase.id,
        before: {
          outcome: previous.outcome,
          reasonCode: previous.reasonCode,
          ...(previous.matchedRuleId === undefined
            ? {}
            : { matchedRuleId: previous.matchedRuleId }),
        },
        after: {
          outcome: next.outcome,
          reasonCode: next.reasonCode,
          ...(next.matchedRuleId === undefined
            ? {}
            : { matchedRuleId: next.matchedRuleId }),
        },
      });
    }
  }

  const beforeDigest = sha256Digest(before.rulebook);
  const afterDigest = sha256Digest(after.rulebook);
  return {
    valid: true,
    changed: beforeDigest !== afterDigest,
    beforeDigest,
    afterDigest,
    revision: {
      before: before.rulebook.revision,
      after: after.rulebook.revision,
      changed: before.rulebook.revision !== after.rulebook.revision,
    },
    defaultOutcomeChanged: before.rulebook.defaultOutcome !== after.rulebook.defaultOutcome,
    rules,
    behaviorChanges,
    issues: [],
  };
}
