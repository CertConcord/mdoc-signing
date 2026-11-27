const classifications = new WeakMap();

export class MdocValidationError extends Error {
  constructor(code, overall = 'INVALID') {
    super(code);
    this.code = code;
    this.overall = overall;
  }
}
export function requireThat(condition, code, overall = 'INVALID') {
  if (!condition) {
    const error = new MdocValidationError(code, overall);
    if (typeof code === 'string' && code.length > 0 &&
      ['INVALID', 'INDETERMINATE', 'UNSUPPORTED'].includes(overall)) {
      classifications.set(error, Object.freeze({ overall, reason: code }));
    }
    throw error;
  }
}

export function validationFailure(error) {
  const classification = classifications.get(error);
  return classification && { ...classification };
}
