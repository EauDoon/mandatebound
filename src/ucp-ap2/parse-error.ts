/**
 * Error type raised when the UCP/AP2 evidence adapter fails to parse, validate,
 * or canonicalize a piece of evidence. Callers map this into the bounded
 * InteropIssue list returned from each verify function.
 */
export class UcpAp2ParseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "UcpAp2ParseError";
  }
}
