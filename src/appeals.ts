import type { AppealEvent, AppealEventType, Sha256Digest } from "./domain.js";
import { canonicalize, sha256Digest } from "./canonical.js";

export type AppealStatus = "open" | "upheld" | "reversed" | "withdrawn" | "conflicted";
export type CompletenessState = "unproven" | "verified" | "mismatch";

export interface AppealCheckpoint {
  readonly sequence: number;
  readonly headDigest: Sha256Digest;
}

export interface AppealIssue {
  readonly code: string;
  readonly message: string;
}

export interface AppealHistory {
  readonly appealId: string;
  readonly decisionId: string;
  readonly status: AppealStatus;
  readonly events: readonly AppealEvent[];
  readonly headDigest?: Sha256Digest;
  readonly completeness: {
    readonly state: CompletenessState;
    readonly checkpoint?: AppealCheckpoint;
  };
  readonly issues: readonly AppealIssue[];
}

export class AppealError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "AppealError";
    this.code = code;
  }
}

const TERMINAL_EVENTS = new Set<AppealEventType>(["upheld", "reversed", "withdrawn"]);

export function appealEventDigest(event: AppealEvent): Sha256Digest {
  return sha256Digest(canonicalize(event));
}

function statusFor(events: readonly AppealEvent[], conflicted: boolean): AppealStatus {
  if (conflicted) return "conflicted";
  const finalEvent = events.at(-1);
  if (finalEvent?.eventType === "upheld") return "upheld";
  if (finalEvent?.eventType === "reversed") return "reversed";
  if (finalEvent?.eventType === "withdrawn") return "withdrawn";
  return "open";
}

function checkpointState(
  events: readonly AppealEvent[],
  checkpoint: AppealCheckpoint | undefined,
): AppealHistory["completeness"] {
  if (checkpoint === undefined) return { state: "unproven" };
  const head = events.at(-1);
  if (
    head !== undefined
    && head.sequence === checkpoint.sequence
    && appealEventDigest(head) === checkpoint.headDigest
  ) {
    return { state: "verified", checkpoint };
  }
  return { state: "mismatch", checkpoint };
}

/**
 * Replays an appeal in supplied append order. It never sorts away evidence of
 * a fork, duplicate sequence, or reordered event.
 */
export function replayAppealEvents(
  events: readonly AppealEvent[],
  checkpoint?: AppealCheckpoint,
): AppealHistory {
  if (events.length === 0) {
    return {
      appealId: "",
      decisionId: "",
      status: "conflicted",
      events: [],
      completeness: checkpoint === undefined
        ? { state: "unproven" }
        : { state: "mismatch", checkpoint },
      issues: [{ code: "ALB_APPEAL_EMPTY", message: "Appeal history is empty." }],
    };
  }

  const first = events[0];
  if (first === undefined) throw new Error("Unreachable empty appeal history.");
  const issues: AppealIssue[] = [];
  const eventIds = new Map<string, Sha256Digest>();
  const sequences = new Set<number>();
  const children = new Map<string, number>();
  let previousDigest: Sha256Digest | undefined;
  let terminalSeen = false;

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event === undefined) continue;
    const digest = appealEventDigest(event);

    if (event.appealId !== first.appealId || event.decisionId !== first.decisionId) {
      issues.push({ code: "ALB_APPEAL_BINDING", message: "Appeal event binding is inconsistent." });
    }
    if (event.sequence !== index + 1 || sequences.has(event.sequence)) {
      issues.push({ code: "ALB_APPEAL_SEQUENCE", message: "Appeal sequence is not contiguous." });
    }
    sequences.add(event.sequence);

    const priorForId = eventIds.get(event.artifactId);
    if (priorForId !== undefined && priorForId !== digest) {
      issues.push({ code: "ALB_APPEAL_EQUIVOCATION", message: "Appeal event identifier was reused." });
    } else if (priorForId !== undefined) {
      issues.push({ code: "ALB_APPEAL_DUPLICATE", message: "Appeal event was duplicated." });
    }
    eventIds.set(event.artifactId, digest);

    if (index === 0) {
      if (event.eventType !== "filed" || event.previousEventDigest !== undefined) {
        issues.push({ code: "ALB_APPEAL_GENESIS", message: "Appeal genesis event is invalid." });
      }
    } else {
      if (event.eventType === "filed") {
        issues.push({ code: "ALB_APPEAL_GENESIS", message: "Appeal filed event may appear only at genesis." });
      }
      if (event.previousEventDigest !== previousDigest) {
        issues.push({ code: "ALB_APPEAL_CHAIN", message: "Appeal event chain is invalid." });
      }
      if (event.previousEventDigest !== undefined) {
        children.set(event.previousEventDigest, (children.get(event.previousEventDigest) ?? 0) + 1);
      }
      if (terminalSeen) {
        issues.push({ code: "ALB_APPEAL_TERMINAL", message: "Appeal contains an event after resolution." });
      }
    }

    if (event.eventType === "evidence_added" && event.evidenceBundleDigest === undefined) {
      issues.push({ code: "ALB_APPEAL_EVIDENCE", message: "Evidence event is missing its bundle digest." });
    }
    if (event.eventType === "reversed" && event.supersedingDecisionId === undefined) {
      issues.push({ code: "ALB_APPEAL_SUPERSESSION", message: "Reversal is missing a superseding decision." });
    }
    if (event.eventType !== "reversed" && event.supersedingDecisionId !== undefined) {
      issues.push({ code: "ALB_APPEAL_SUPERSESSION", message: "Supersession is only valid for reversal." });
    }

    if (TERMINAL_EVENTS.has(event.eventType)) terminalSeen = true;
    previousDigest = digest;
  }

  if ([...children.values()].some((count) => count > 1)) {
    issues.push({ code: "ALB_APPEAL_FORK", message: "Appeal history contains a fork." });
  }

  const completeness = checkpointState(events, checkpoint);
  if (completeness.state === "mismatch") {
    issues.push({ code: "ALB_APPEAL_CHECKPOINT", message: "Appeal checkpoint does not match the history." });
  }
  const frozenEvents = events.map((event) => structuredClone(event));
  return {
    appealId: first.appealId,
    decisionId: first.decisionId,
    status: statusFor(events, issues.length > 0),
    events: frozenEvents,
    ...(previousDigest === undefined ? {} : { headDigest: previousDigest }),
    completeness,
    issues,
  };
}

export function assertAppealAppendable(
  existing: readonly AppealEvent[],
  event: AppealEvent,
): void {
  if (existing.length === 0) {
    if (event.sequence !== 1 || event.eventType !== "filed" || event.previousEventDigest !== undefined) {
      throw new AppealError("ALB_APPEAL_GENESIS", "Appeal must begin with a filed event.");
    }
    return;
  }

  const replay = replayAppealEvents(existing);
  if (replay.issues.length > 0) {
    throw new AppealError("ALB_APPEAL_CONFLICT", "Existing appeal history is conflicted.");
  }
  if (replay.status !== "open") {
    throw new AppealError("ALB_APPEAL_TERMINAL", "Resolved appeal cannot accept another event.");
  }
  if (event.appealId !== replay.appealId || event.decisionId !== replay.decisionId) {
    throw new AppealError("ALB_APPEAL_BINDING", "Appeal event binding is inconsistent.");
  }
  if (event.sequence !== existing.length + 1 || event.previousEventDigest !== replay.headDigest) {
    throw new AppealError("ALB_APPEAL_FORK", "Appeal event does not extend the current head.");
  }
  if (existing.some((item) => item.artifactId === event.artifactId)) {
    throw new AppealError("ALB_APPEAL_DUPLICATE", "Appeal event identifier already exists.");
  }

  const candidate = replayAppealEvents([...existing, event]);
  if (candidate.issues.length > 0) {
    throw new AppealError(candidate.issues[0]?.code ?? "ALB_APPEAL_INVALID", "Appeal event is invalid.");
  }
}
