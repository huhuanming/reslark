export class ReslarkError extends Error {
  constructor(code, message, { exitCode = 4, retryable = false, details } = {}) {
    super(message);
    this.code = code;
    this.exitCode = exitCode;
    this.retryable = retryable;
    this.details = details;
  }
  toJSON() {
    return { code: this.code, message: this.message, retryable: this.retryable, ...(this.details ? { details: this.details } : {}) };
  }
}
export const fail = (code, message, options) => { throw new ReslarkError(code, message, options); };
export const invalid = (message) => fail('INVALID_ARGUMENT', message, { exitCode: 2 });
export const asError = (error) => error instanceof ReslarkError ? error : new ReslarkError('INTERNAL_ERROR', error.message || String(error));
