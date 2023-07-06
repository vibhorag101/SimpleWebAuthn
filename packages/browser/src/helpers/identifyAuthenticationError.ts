import { isValidDomain } from './isValidDomain';
import { WebAuthnError } from './webAuthnError';
import { browserSupportsWebAuthn } from './browserSupportsWebAuthn';
/**
 * Attempt to intuit _why_ an error was raised after calling `navigator.credentials.get()`
 */
export function identifyAuthenticationError({
  error,
  options,
}: {
  error: Error;
  options: CredentialRequestOptions;
}): WebAuthnError | Error {
  const { publicKey } = options;

  if (!publicKey) {
    throw Error('options was missing required publicKey property');
  }

  if (error.name === 'AbortError') {
    if (options.signal instanceof AbortSignal) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 16)
      return new WebAuthnError({
        message: 'Authentication ceremony was sent an abort signal',
        code: 'ERROR_CEREMONY_ABORTED',
        cause: error,
      });
    }
  } else if (error.name === 'NotAllowedError') {
    // check if origin is opaque origin
    if (window.location.origin === 'null') {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 7)
      return new WebAuthnError({
        message: 'The origin is an opaque origin',
        code: 'ERROR_OPAQUE_ORIGIN',
        cause: error,
      });
    }
    // check if browser supports webauthn
    else if(!browserSupportsWebAuthn()){
      return new WebAuthnError({
        message: "The browser doesn't support WebAuthn",
        code: 'ERROR_WEBAUTHN_NOT_SUPPORTED',
        cause: error,
      });
    }
    else {
      return new WebAuthnError({
        message: "The user cancelled the operation. Please try again",
        code: 'ERROR_USER_CANCELLED_OPERATION',
        cause: error,
      });
    }
  } else if (error.name === 'SecurityError') {
    const effectiveDomain = window.location.hostname;
    if (!isValidDomain(effectiveDomain)) {
      // https://www.w3.org/TR/webauthn-2/#sctn-discover-from-external-source (Step 5)
      return new WebAuthnError({
        message: `${window.location.hostname} is an invalid domain`,
        code: 'ERROR_INVALID_DOMAIN',
        cause: error,
      });
    } else if (publicKey.rpId !== effectiveDomain) {
      // https://www.w3.org/TR/webauthn-2/#sctn-discover-from-external-source (Step 6)
      return new WebAuthnError({
        message: `The RP ID "${publicKey.rpId}" is invalid for this domain`,
        code: 'ERROR_INVALID_RP_ID',
        cause: error,
      });
    }
  } else if (error.name === 'UnknownError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion (Step 1)
    // https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion (Step 12)
    return new WebAuthnError({
      message: 'The authenticator was unable to process the specified options, or could not create a new assertion signature',
      code: 'ERROR_AUTHENTICATOR_GENERAL_ERROR',
      cause: error,
    });
  }

  return error;
}
