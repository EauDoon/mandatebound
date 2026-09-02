import type {
  LiabilityOutcome,
  PolicyRule,
  RuleCondition,
  Rulebook,
} from "./domain.js";

const ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const ASCII_DIGITS = "0123456789";
const ASCII_IDENTIFIER_LEAD = ASCII_UPPERCASE + ASCII_LOWERCASE + ASCII_DIGITS;
const ASCII_IDENTIFIER_CHARACTERS = ASCII_IDENTIFIER_LEAD + "._:-";

/**
 * The complete fact vocabulary understood by mandate-to-liability-v1.
 *
 * These are opaque identifiers, not property paths. The evaluator never
 * resolves a fact name against an input object.
 */
export const POLICY_FACT_VALUES = {
  input_state: ["valid", "invalid"],
  evidence_state: ["sufficient", "missing", "tampered", "contradictory"],
  policy_state: ["active", "inactive", "invalid"],
  trust_state: ["pinned", "mismatch", "invalid"],
  mandate_state: ["valid", "invalid", "expired", "revoked", "out_of_scope", "missing"],
  receipt_state: ["trusted", "untrusted", "missing"],
  execution_state: ["compliant", "noncompliant", "replayed", "missing"],
  operator_controls: ["compliant", "noncompliant", "unknown"],
  operator_violation: [
    "none",
    "invalid_mandate",
    "expired_mandate",
    "revoked_mandate",
    "replayed_execution",
    "out_of_scope",
    "control_failure",
  ],
  model_provenance: ["matched", "mismatched", "missing"],
  causation_state: ["sufficient", "insufficient", "conflicting", "multi_causal", "missing"],
} as const;

export type PolicyFactName = keyof typeof POLICY_FACT_VALUES;
export type PolicyFactValue<Name extends PolicyFactName = PolicyFactName> =
  (typeof POLICY_FACT_VALUES)[Name][number];
export type PolicyFacts = Readonly<{
  [Name in PolicyFactName]: (typeof POLICY_FACT_VALUES)[Name][number];
}>;

export const POLICY_FACT_NAMES = Object.freeze(
  Object.keys(POLICY_FACT_VALUES).sort() as PolicyFactName[],
);

const ALLOWED_CONDITION_OPERATORS = new Set(["eq", "in", "all", "any", "not"]);
const ALLOWED_OUTCOMES = new Set<LiabilityOutcome>([
  "principal",
  "operator",
  "model_vendor",
  "unresolved",
]);
const MAX_RULES = 64;
const MAX_CONDITION_DEPTH = 8;
const MAX_CONDITIONS = 256;
const MAX_GROUP_WIDTH = 32;

export interface PolicyConfigurationIssue {
  readonly path: string;
  readonly code:
    | "invalid_shape"
    | "unsupported_operator"
    | "unknown_fact"
    | "invalid_fact_value"
    | "unsafe_integer"
    | "duplicate_rule_id"
    | "duplicate_priority"
    | "limit_exceeded"
    | "invalid_outcome";
  readonly message: string;
}

export interface RulebookValidation {
  readonly valid: boolean;
  readonly issues: readonly PolicyConfigurationIssue[];
}

export interface ConditionEvaluationTrace {
  readonly path: string;
  readonly operator: "eq" | "in" | "all" | "any" | "not";
  readonly matched: boolean;
  readonly fact?: PolicyFactName;
  readonly actual?: PolicyFactValue;
  readonly expected?: PolicyFactValue | readonly PolicyFactValue[];
}

export interface RuleEvaluationTrace {
  readonly ruleId: string;
  readonly priority: number;
  readonly matched: boolean;
  readonly conditions: readonly ConditionEvaluationTrace[];
}

export interface PolicyEvaluation {
  readonly outcome: LiabilityOutcome;
  readonly reasonCode: string;
  readonly matchedRuleId?: string;
  readonly trace: readonly RuleEvaluationTrace[];
}

export class PolicyConfigurationError extends Error {
  readonly issues: readonly PolicyConfigurationIssue[];

  constructor(issues: readonly PolicyConfigurationIssue[]) {
    super("Rulebook is outside the bounded mandate-to-liability-v1 DSL");
    this.name = "PolicyConfigurationError";
    this.issues = issues;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function isBoundedIdentifier(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 128) return false;
  const first = value[0];
  if (first === undefined || !ASCII_IDENTIFIER_LEAD.includes(first)) {
    return false;
  }
  for (const character of value) if (!ASCII_IDENTIFIER_CHARACTERS.includes(character)) return false;
  return true;
}

function isFactName(value: unknown): value is PolicyFactName {
  return typeof value === "string" && Object.hasOwn(POLICY_FACT_VALUES, value);
}

function isAllowedFactValue<Name extends PolicyFactName>(
  fact: Name,
  value: unknown,
): value is PolicyFactValue<Name> {
  return (
    typeof value === "string" &&
    (POLICY_FACT_VALUES[fact] as readonly string[]).includes(value)
  );
}

function pushIssue(
  issues: PolicyConfigurationIssue[],
  path: string,
  code: PolicyConfigurationIssue["code"],
  message: string,
): void {
  issues.push({ path, code, message });
}

function validateCondition(
  condition: unknown,
  path: string,
  depth: number,
  counter: { count: number },
  issues: PolicyConfigurationIssue[],
): void {
  counter.count += 1;
  if (counter.count > MAX_CONDITIONS || depth > MAX_CONDITION_DEPTH) {
    pushIssue(issues, path, "limit_exceeded", "Condition bounds exceeded");
    return;
  }
  if (!isPlainObject(condition) || typeof condition.op !== "string") {
    pushIssue(issues, path, "invalid_shape", "Condition must be a closed object with an operator");
    return;
  }
  if (!ALLOWED_CONDITION_OPERATORS.has(condition.op)) {
    pushIssue(issues, `${path}.op`, "unsupported_operator", "Operator is not in the bounded DSL");
    return;
  }

  if (condition.op === "eq") {
    if (!hasExactKeys(condition, ["op", "fact", "value"])) {
      pushIssue(issues, path, "invalid_shape", "eq accepts only op, fact, and value");
      return;
    }
    if (!isFactName(condition.fact)) {
      pushIssue(issues, `${path}.fact`, "unknown_fact", "Fact is not in the closed vocabulary");
      return;
    }
    if (!isAllowedFactValue(condition.fact, condition.value)) {
      pushIssue(issues, `${path}.value`, "invalid_fact_value", "Value is not valid for this fact");
    }
    return;
  }

  if (condition.op === "in") {
    if (!hasExactKeys(condition, ["op", "fact", "values"])) {
      pushIssue(issues, path, "invalid_shape", "in accepts only op, fact, and values");
      return;
    }
    if (!isFactName(condition.fact)) {
      pushIssue(issues, `${path}.fact`, "unknown_fact", "Fact is not in the closed vocabulary");
      return;
    }
    if (
      !Array.isArray(condition.values) ||
      condition.values.length === 0 ||
      condition.values.length > MAX_GROUP_WIDTH
    ) {
      pushIssue(issues, `${path}.values`, "invalid_shape", "values must be a bounded non-empty array");
      return;
    }
    const seen = new Set<string>();
    for (const [index, value] of condition.values.entries()) {
      if (!isAllowedFactValue(condition.fact, value)) {
        pushIssue(
          issues,
          `${path}.values[${String(index)}]`,
          "invalid_fact_value",
          "Value is not valid for this fact",
        );
      } else if (seen.has(value)) {
        pushIssue(
          issues,
          `${path}.values[${String(index)}]`,
          "invalid_shape",
          "Duplicate values are not permitted",
        );
      } else {
        seen.add(value);
      }
    }
    return;
  }

  if (condition.op === "not") {
    if (!hasExactKeys(condition, ["op", "condition"])) {
      pushIssue(issues, path, "invalid_shape", "not accepts only op and condition");
      return;
    }
    validateCondition(condition.condition, `${path}.condition`, depth + 1, counter, issues);
    return;
  }

  if (!hasExactKeys(condition, ["op", "conditions"])) {
    pushIssue(issues, path, "invalid_shape", `${condition.op} accepts only op and conditions`);
    return;
  }
  if (
    !Array.isArray(condition.conditions) ||
    condition.conditions.length === 0 ||
    condition.conditions.length > MAX_GROUP_WIDTH
  ) {
    pushIssue(issues, `${path}.conditions`, "invalid_shape", "conditions must be a bounded non-empty array");
    return;
  }
  for (const [index, child] of condition.conditions.entries()) {
    validateCondition(child, `${path}.conditions[${String(index)}]`, depth + 1, counter, issues);
  }
}

export function validateRulebook(rulebook: unknown): RulebookValidation {
  const issues: PolicyConfigurationIssue[] = [];
  if (!isPlainObject(rulebook)) {
    return {
      valid: false,
      issues: [{ path: "$", code: "invalid_shape", message: "Rulebook must be an object" }],
    };
  }
  if (
    !hasExactKeys(rulebook, [
      "schemaVersion",
      "artifactId",
      "revision",
      "semanticsVersion",
      "issuedAt",
      "rules",
      "defaultOutcome",
    ])
  ) {
    pushIssue(issues, "$", "invalid_shape", "Rulebook contains missing or unknown properties");
  }
  if (rulebook.schemaVersion !== "1.0.0" || rulebook.semanticsVersion !== "mandate-to-liability-v1") {
    pushIssue(issues, "$", "invalid_shape", "Unsupported rulebook semantics version");
  }
  if (!isBoundedIdentifier(rulebook.artifactId)) {
    pushIssue(issues, "$.artifactId", "invalid_shape", "Artifact id must be a bounded protocol identifier");
  }
  if (!isSafeInteger(rulebook.revision) || rulebook.revision < 1) {
    pushIssue(issues, "$.revision", "unsafe_integer", "Revision must be a positive safe integer");
  }
  if (rulebook.defaultOutcome !== "unresolved") {
    pushIssue(issues, "$.defaultOutcome", "invalid_outcome", "Default outcome must fail closed");
  }
  if (!Array.isArray(rulebook.rules) || rulebook.rules.length === 0 || rulebook.rules.length > MAX_RULES) {
    pushIssue(issues, "$.rules", "limit_exceeded", "Rulebook must contain 1 to 64 rules");
    return { valid: issues.length === 0, issues };
  }

  const ids = new Set<string>();
  const priorities = new Set<number>();
  for (const [index, candidate] of rulebook.rules.entries()) {
    const path = `$.rules[${String(index)}]`;
    if (!isPlainObject(candidate) || !hasExactKeys(candidate, ["id", "priority", "when", "outcome", "reasonCode"])) {
      pushIssue(issues, path, "invalid_shape", "Rule must be a closed object");
      continue;
    }
    if (!isBoundedIdentifier(candidate.id)) {
      pushIssue(issues, `${path}.id`, "invalid_shape", "Rule id must be a bounded protocol identifier");
    } else if (ids.has(candidate.id)) {
      pushIssue(issues, `${path}.id`, "duplicate_rule_id", "Rule ids must be unique");
    } else {
      ids.add(candidate.id);
    }
    if (!isSafeInteger(candidate.priority) || candidate.priority < 0 || candidate.priority > 1_000_000) {
      pushIssue(issues, `${path}.priority`, "unsafe_integer", "Priority must be an integer from 0 to 1000000");
    } else if (priorities.has(candidate.priority)) {
      pushIssue(issues, `${path}.priority`, "duplicate_priority", "Priorities must be unique");
    } else {
      priorities.add(candidate.priority);
    }
    if (!ALLOWED_OUTCOMES.has(candidate.outcome as LiabilityOutcome)) {
      pushIssue(issues, `${path}.outcome`, "invalid_outcome", "Outcome is not allowed");
    }
    if (!isBoundedIdentifier(candidate.reasonCode)) {
      pushIssue(issues, `${path}.reasonCode`, "invalid_shape", "Reason code must be a bounded protocol identifier");
    }
    validateCondition(candidate.when, `${path}.when`, 0, { count: 0 }, issues);
  }
  return { valid: issues.length === 0, issues };
}

export function assertValidRulebook(rulebook: unknown): asserts rulebook is Rulebook {
  const validation = validateRulebook(rulebook);
  if (!validation.valid) {
    throw new PolicyConfigurationError(validation.issues);
  }
}

function assertValidPolicyFacts(facts: unknown): asserts facts is PolicyFacts {
  if (
    !isPlainObject(facts)
    || !hasExactKeys(facts, POLICY_FACT_NAMES)
    || POLICY_FACT_NAMES.some((name) => !isAllowedFactValue(name, facts[name]))
  ) {
    throw new PolicyConfigurationError([{
      path: "$facts",
      code: "invalid_shape",
      message: "Policy facts must use the complete closed vocabulary",
    }]);
  }
}

function evaluateCondition(
  condition: RuleCondition,
  facts: PolicyFacts,
  path: string,
  trace: ConditionEvaluationTrace[],
): boolean {
  if (condition.op === "eq") {
    const fact = condition.fact as PolicyFactName;
    const actual = facts[fact];
    const expected = condition.value as PolicyFactValue;
    const matched = actual === expected;
    trace.push({ path, operator: "eq", matched, fact, actual, expected });
    return matched;
  }
  if (condition.op === "in") {
    const fact = condition.fact as PolicyFactName;
    const actual = facts[fact];
    const expected = condition.values as readonly PolicyFactValue[];
    const matched = expected.includes(actual);
    trace.push({ path, operator: "in", matched, fact, actual, expected });
    return matched;
  }
  if (condition.op === "not") {
    const childTrace: ConditionEvaluationTrace[] = [];
    const matched = !evaluateCondition(condition.condition, facts, `${path}.condition`, childTrace);
    trace.push({ path, operator: "not", matched }, ...childTrace);
    return matched;
  }
  if (condition.op === "all" || condition.op === "any") {
    const childResults = condition.conditions.map((child, index) =>
      evaluateCondition(child, facts, `${path}.conditions[${String(index)}]`, trace),
    );
    const matched = condition.op === "all" ? childResults.every(Boolean) : childResults.some(Boolean);
    trace.push({ path, operator: condition.op, matched });
    return matched;
  }
  // assertValidRulebook rejects the remaining operators before evaluation.
  throw new PolicyConfigurationError([
    {
      path,
      code: "unsupported_operator",
      message: "Operator is not in the bounded DSL",
    },
  ]);
}

function orderedRules(rulebook: Rulebook): readonly PolicyRule[] {
  return [...rulebook.rules].sort((left, right) => {
    if (left.priority !== right.priority) return right.priority - left.priority;
    return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
  });
}

export function evaluateRulebook(rulebook: Rulebook, facts: PolicyFacts): PolicyEvaluation {
  assertValidRulebook(rulebook);
  assertValidPolicyFacts(facts);
  const ruleTrace: RuleEvaluationTrace[] = [];
  for (const rule of orderedRules(rulebook)) {
    const conditions: ConditionEvaluationTrace[] = [];
    const matched = evaluateCondition(rule.when, facts, `rule:${rule.id}`, conditions);
    ruleTrace.push({ ruleId: rule.id, priority: rule.priority, matched, conditions });
    if (matched) {
      return {
        outcome: rule.outcome,
        reasonCode: rule.reasonCode,
        matchedRuleId: rule.id,
        trace: ruleTrace,
      };
    }
  }
  return {
    outcome: rulebook.defaultOutcome,
    reasonCode: "unresolved_default",
    trace: ruleTrace,
  };
}
