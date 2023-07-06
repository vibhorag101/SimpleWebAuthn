import { browserSupportsWebAuthn } from './browserSupportsWebAuthn';
import { isValidDomain } from './isValidDomain';
import { WebAuthnError } from './webAuthnError';

/**
 * Attempt to intuit _why_ an error was raised after calling `navigator.credentials.create()`
 */
export function identifyRegistrationError({
  error,
  options,
}: {
  error: Error;
  options: CredentialCreationOptions;
}): WebAuthnError | Error {
  const { publicKey } = options;

  if (!publicKey) {
    throw Error('options was missing required publicKey property');
  }

  if (error.name === 'AbortError') {
    if (options.signal instanceof AbortSignal) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 16)
      return new WebAuthnError({
        message: 'Registration ceremony was sent an abort signal',
        code: 'ERROR_CEREMONY_ABORTED',
        cause: error,
      });
    }
  } else if (error.name === 'ConstraintError') {
    if (publicKey.authenticatorSelection?.requireResidentKey === true) {
      // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 4)
      return new WebAuthnError({
        message: 'Discoverable credentials were required but no available authenticator supported it',
        code: 'ERROR_AUTHENTICATOR_MISSING_DISCOVERABLE_CREDENTIAL_SUPPORT',
        cause: error,
      });
    } else if (publicKey.authenticatorSelection?.userVerification === 'required') {
      // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 5)
      return new WebAuthnError({
        message: 'User verification was required but no available authenticator supported it',
        code: 'ERROR_AUTHENTICATOR_MISSING_USER_VERIFICATION_SUPPORT',
        cause: error,
      });
    }
  } else if (error.name === 'InvalidStateError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 20)
    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 3)
    return new WebAuthnError({
      message: 'The authenticator was previously registered',
      code: 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED',
      cause: error
    });
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

  } else if (error.name === 'NotSupportedError') {
    const validPubKeyCredParams = publicKey.pubKeyCredParams.filter(
      param => param.type === 'public-key',
    );

    if (validPubKeyCredParams.length === 0) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 10)
      return new WebAuthnError({
        message: 'No entry in pubKeyCredParams was of type "public-key"',
        code: 'ERROR_MALFORMED_PUBKEYCREDPARAMS',
        cause: error,
      });
    }

    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 2)
    return new WebAuthnError({
      message: 'No available authenticator supported any of the specified pubKeyCredParams algorithms',
      code: 'ERROR_AUTHENTICATOR_NO_SUPPORTED_PUBKEYCREDPARAMS_ALG',
      cause: error,
    });
  } else if (error.name === 'SecurityError') {
    const effectiveDomain = window.location.hostname;
    if (!isValidDomain(effectiveDomain)) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 7)
      return new WebAuthnError({
        message: `${window.location.hostname} is an invalid domain`,
        code: 'ERROR_INVALID_DOMAIN',
        cause: error
      });
    } else if (publicKey.rp.id !== effectiveDomain) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 8)
      return new WebAuthnError({
        message: `The RP ID "${publicKey.rp.id}" is invalid for this domain`,
        code: 'ERROR_INVALID_RP_ID',
        cause: error,
      });
    }
  } else if (error.name === 'TypeError') {
    if (publicKey.user.id.byteLength < 1 || publicKey.user.id.byteLength > 64) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 5)
      return new WebAuthnError({
        message: 'User ID was not between 1 and 64 characters',
        code: 'ERROR_INVALID_USER_ID_LENGTH',
        cause: error,
      });
    }
  } else if (error.name === 'UnknownError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 1)
    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 8)
    return new WebAuthnError({
      message: 'The authenticator was unable to process the specified options, or could not create a new credential',
      code: 'ERROR_AUTHENTICATOR_GENERAL_ERROR',
      cause: error,
    });
  }

  return error;
}
