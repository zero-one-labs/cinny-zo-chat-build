import { g as getDefaultExportFromCjs, _ as _defineProperty, l as logger, K as KnownMembership, a as _asyncToGenerator, L as LogSpan, b as logDuration, D as DeviceIsolationModeKind, E as EventType, H as HistoryVisibility$1, T as TypedEventEmitter, C as CryptoEvent, M as Method, d as decodeBase64, e as encodeUri, f as ToDeviceMessageId, h as calculateRetryBackoff, s as sleep, i as DeviceVerification, k as Device$1, m as TypedReEmitter, V as VerificationRequestEvent, n as VerificationPhase, o as VerificationMethod$1, p as MsgType, q as VerifierEvent, t as defer, I as ImportRoomKeyStage, u as MatrixError, v as ClientPrefix, w as deriveRecoveryKeyFromPassphrase, A as AllDevicesIsolationMode, x as ClientStoppedError, y as encodeBase64, z as DeviceVerificationStatus, U as UserVerificationStatus, B as CrossSigningKey, S as SECRET_STORAGE_ALGORITHM_V1_AES, F as secureRandomString, G as encodeRecoveryKey, J as MatrixEventEvent, N as MapWithDefault, O as DecryptionError, P as DecryptionFailureCode, Q as EventShieldColour, R as EventShieldReason, W as IndexedDBCryptoStore, X as MigrationState, Y as decryptAESSecretStorageItem } from "./index-DpuEdkbE.js";
let wasm;
function __wbg_set_wasm(val) {
  wasm = val;
}
let WASM_VECTOR_LEN = 0;
let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
  if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
    cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8ArrayMemory0;
}
const lTextEncoder = typeof TextEncoder === "undefined" ? (0, module.require)("util").TextEncoder : TextEncoder;
let cachedTextEncoder = new lTextEncoder("utf-8");
const encodeString = typeof cachedTextEncoder.encodeInto === "function" ? function(arg, view) {
  return cachedTextEncoder.encodeInto(arg, view);
} : function(arg, view) {
  const buf = cachedTextEncoder.encode(arg);
  view.set(buf);
  return {
    read: arg.length,
    written: buf.length
  };
};
function passStringToWasm0(arg, malloc, realloc) {
  if (realloc === void 0) {
    const buf = cachedTextEncoder.encode(arg);
    const ptr2 = malloc(buf.length, 1) >>> 0;
    getUint8ArrayMemory0().subarray(ptr2, ptr2 + buf.length).set(buf);
    WASM_VECTOR_LEN = buf.length;
    return ptr2;
  }
  let len = arg.length;
  let ptr = malloc(len, 1) >>> 0;
  const mem = getUint8ArrayMemory0();
  let offset = 0;
  for (; offset < len; offset++) {
    const code = arg.charCodeAt(offset);
    if (code > 127) break;
    mem[ptr + offset] = code;
  }
  if (offset !== len) {
    if (offset !== 0) {
      arg = arg.slice(offset);
    }
    ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
    const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
    const ret = encodeString(arg, view);
    offset += ret.written;
    ptr = realloc(ptr, len, offset, 1) >>> 0;
  }
  WASM_VECTOR_LEN = offset;
  return ptr;
}
let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
  if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || cachedDataViewMemory0.buffer.detached === void 0 && cachedDataViewMemory0.buffer !== wasm.memory.buffer) {
    cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
  }
  return cachedDataViewMemory0;
}
function addToExternrefTable0(obj) {
  const idx = wasm.__externref_table_alloc();
  wasm.__wbindgen_export_4.set(idx, obj);
  return idx;
}
function handleError(f, args) {
  try {
    return f.apply(this, args);
  } catch (e) {
    const idx = addToExternrefTable0(e);
    wasm.__wbindgen_exn_store(idx);
  }
}
const lTextDecoder = typeof TextDecoder === "undefined" ? (0, module.require)("util").TextDecoder : TextDecoder;
let cachedTextDecoder = new lTextDecoder("utf-8", { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
function getStringFromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}
function isLikeNone(x) {
  return x === void 0 || x === null;
}
function getArrayU8FromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}
const CLOSURE_DTORS = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((state) => {
  wasm.__wbindgen_export_6.get(state.dtor)(state.a, state.b);
});
function makeMutClosure(arg0, arg1, dtor, f) {
  const state = { a: arg0, b: arg1, cnt: 1, dtor };
  const real = (...args) => {
    state.cnt++;
    const a = state.a;
    state.a = 0;
    try {
      return f(a, state.b, ...args);
    } finally {
      if (--state.cnt === 0) {
        wasm.__wbindgen_export_6.get(state.dtor)(a, state.b);
        CLOSURE_DTORS.unregister(state);
      } else {
        state.a = a;
      }
    }
  };
  real.original = state;
  CLOSURE_DTORS.register(real, state, state);
  return real;
}
function makeClosure(arg0, arg1, dtor, f) {
  const state = { a: arg0, b: arg1, cnt: 1, dtor };
  const real = (...args) => {
    state.cnt++;
    try {
      return f(state.a, state.b, ...args);
    } finally {
      if (--state.cnt === 0) {
        wasm.__wbindgen_export_6.get(state.dtor)(state.a, state.b);
        state.a = 0;
        CLOSURE_DTORS.unregister(state);
      }
    }
  };
  real.original = state;
  CLOSURE_DTORS.register(real, state, state);
  return real;
}
function debugString(val) {
  const type = typeof val;
  if (type == "number" || type == "boolean" || val == null) {
    return `${val}`;
  }
  if (type == "string") {
    return `"${val}"`;
  }
  if (type == "symbol") {
    const description = val.description;
    if (description == null) {
      return "Symbol";
    } else {
      return `Symbol(${description})`;
    }
  }
  if (type == "function") {
    const name = val.name;
    if (typeof name == "string" && name.length > 0) {
      return `Function(${name})`;
    } else {
      return "Function";
    }
  }
  if (Array.isArray(val)) {
    const length = val.length;
    let debug = "[";
    if (length > 0) {
      debug += debugString(val[0]);
    }
    for (let i = 1; i < length; i++) {
      debug += ", " + debugString(val[i]);
    }
    debug += "]";
    return debug;
  }
  const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
  let className;
  if (builtInMatches && builtInMatches.length > 1) {
    className = builtInMatches[1];
  } else {
    return toString.call(val);
  }
  if (className == "Object") {
    try {
      return "Object(" + JSON.stringify(val) + ")";
    } catch (_) {
      return "Object";
    }
  }
  if (val instanceof Error) {
    return `${val.name}: ${val.message}
${val.stack}`;
  }
  return className;
}
function passArray8ToWasm0(arg, malloc) {
  const ptr = malloc(arg.length * 1, 1) >>> 0;
  getUint8ArrayMemory0().set(arg, ptr / 1);
  WASM_VECTOR_LEN = arg.length;
  return ptr;
}
function takeFromExternrefTable0(idx) {
  const value = wasm.__wbindgen_export_4.get(idx);
  wasm.__externref_table_dealloc(idx);
  return value;
}
function _assertClass(instance, klass) {
  if (!(instance instanceof klass)) {
    throw new Error(`expected instance of ${klass.name}`);
  }
}
function passArrayJsValueToWasm0(array, malloc) {
  const ptr = malloc(array.length * 4, 4) >>> 0;
  for (let i = 0; i < array.length; i++) {
    const add = addToExternrefTable0(array[i]);
    getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
  }
  WASM_VECTOR_LEN = array.length;
  return ptr;
}
function getArrayJsValueFromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  const mem = getDataViewMemory0();
  const result = [];
  for (let i = ptr; i < ptr + 4 * len; i += 4) {
    result.push(wasm.__wbindgen_export_4.get(mem.getUint32(i, true)));
  }
  wasm.__externref_drop_slice(ptr, len);
  return result;
}
let cachedUint16ArrayMemory0 = null;
function getUint16ArrayMemory0() {
  if (cachedUint16ArrayMemory0 === null || cachedUint16ArrayMemory0.byteLength === 0) {
    cachedUint16ArrayMemory0 = new Uint16Array(wasm.memory.buffer);
  }
  return cachedUint16ArrayMemory0;
}
function getArrayU16FromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return getUint16ArrayMemory0().subarray(ptr / 2, ptr / 2 + len);
}
function getVersions() {
  const ret = wasm.getVersions();
  return Versions.__wrap(ret);
}
function start() {
  wasm.start();
}
function __wbg_adapter_58(arg0, arg1, arg2) {
  const ret = wasm.closure43_externref_shim_multivalue_shim(arg0, arg1, arg2);
  if (ret[1]) {
    throw takeFromExternrefTable0(ret[0]);
  }
}
function __wbg_adapter_61(arg0, arg1) {
  wasm._dyn_core__ops__function__FnMut_____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__h0def4b7acf9443a4(arg0, arg1);
}
function __wbg_adapter_64(arg0, arg1, arg2) {
  wasm.closure740_externref_shim(arg0, arg1, arg2);
}
function __wbg_adapter_67(arg0, arg1) {
  wasm._dyn_core__ops__function__Fn_____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__h1d83a6fb10cd0388(arg0, arg1);
}
function __wbg_adapter_70(arg0, arg1, arg2) {
  wasm.closure427_externref_shim(arg0, arg1, arg2);
}
function __wbg_adapter_788(arg0, arg1, arg2, arg3) {
  wasm.closure439_externref_shim(arg0, arg1, arg2, arg3);
}
const DecryptionErrorCode = Object.freeze({
  /**
   * The room key is not known
   */
  MissingRoomKey: 0,
  "0": "MissingRoomKey",
  /**
   * The room key is known but ratcheted
   */
  UnknownMessageIndex: 1,
  "1": "UnknownMessageIndex",
  /**
   * Decryption failed because of a mismatch between the identity keys of the
   * device we received the room key from and the identity keys recorded in
   * the plaintext of the room key to-device message.
   */
  MismatchedIdentityKeys: 2,
  "2": "MismatchedIdentityKeys",
  /**
   * We weren't able to link the message back to any known device.
   */
  UnknownSenderDevice: 3,
  "3": "UnknownSenderDevice",
  /**
   * The sender device is not cross-signed.
   */
  UnsignedSenderDevice: 4,
  "4": "UnsignedSenderDevice",
  /**
   * The sender's identity is unverified, but was previously verified.
   */
  SenderIdentityVerificationViolation: 5,
  "5": "SenderIdentityVerificationViolation",
  /**
   * Other failure.
   */
  UnableToDecrypt: 6,
  "6": "UnableToDecrypt"
});
const DeviceKeyAlgorithmName = Object.freeze({
  /**
   * The Ed25519 signature algorithm.
   */
  Ed25519: 0,
  "0": "Ed25519",
  /**
   * The Curve25519 ECDH algorithm.
   */
  Curve25519: 1,
  "1": "Curve25519",
  /**
   * An unknown device key algorithm.
   */
  Unknown: 3,
  "3": "Unknown"
});
const DeviceKeyName = Object.freeze({
  /**
   * The curve25519 device key.
   */
  Curve25519: 0,
  "0": "Curve25519",
  /**
   * The ed25519 device key.
   */
  Ed25519: 1,
  "1": "Ed25519",
  /**
   * An unknown device key.
   */
  Unknown: 2,
  "2": "Unknown"
});
const EncryptionAlgorithm = Object.freeze({
  /**
   * Olm version 1 using Curve25519, AES-256, and SHA-256.
   */
  OlmV1Curve25519AesSha2: 0,
  "0": "OlmV1Curve25519AesSha2",
  /**
   * Megolm version 1 using AES-256 and SHA-256.
   */
  MegolmV1AesSha2: 1,
  "1": "MegolmV1AesSha2",
  /**
   * Unsupported algorithm.
   *
   * Applications should ignore this value if it is received, and should
   * never set it.
   */
  Unknown: 2,
  "2": "Unknown"
});
const HistoryVisibility = Object.freeze({
  /**
   * Previous events are accessible to newly joined members from
   * the point they were invited onwards.
   *
   * Events stop being accessible when the member's state changes
   * to something other than *invite* or *join*.
   */
  Invited: 0,
  "0": "Invited",
  /**
   * Previous events are accessible to newly joined members from
   * the point they joined the room onwards.
   *
   * Events stop being accessible when the member's state changes
   * to something other than *join*.
   */
  Joined: 1,
  "1": "Joined",
  /**
   * Previous events are always accessible to newly joined members.
   *
   * All events in the room are accessible, even those sent when
   * the member was not a part of the room.
   */
  Shared: 2,
  "2": "Shared",
  /**
   * All events while this is the `HistoryVisibility` value may be
   * shared by any participating homeserver with anyone, regardless
   * of whether they have ever joined the room.
   */
  WorldReadable: 3,
  "3": "WorldReadable"
});
const LocalTrust = Object.freeze({
  /**
   * The device has been verified and is trusted.
   */
  Verified: 0,
  "0": "Verified",
  /**
   * The device been blacklisted from communicating.
   */
  BlackListed: 1,
  "1": "BlackListed",
  /**
   * The trust state of the device is being ignored.
   */
  Ignored: 2,
  "2": "Ignored",
  /**
   * The trust state is unset.
   */
  Unset: 3,
  "3": "Unset"
});
const LoggerLevel = Object.freeze({
  /**
   * `TRACE` level.
   *
   * Designate very low priority, often extremely verbose,
   * information.
   */
  Trace: 0,
  "0": "Trace",
  /**
   * `DEBUG` level.
   *
   * Designate lower priority information.
   */
  Debug: 1,
  "1": "Debug",
  /**
   * `INFO` level.
   *
   * Designate useful information.
   */
  Info: 2,
  "2": "Info",
  /**
   * `WARN` level.
   *
   * Designate hazardous situations.
   */
  Warn: 3,
  "3": "Warn",
  /**
   * `ERROR` level.
   *
   * Designate very serious errors.
   */
  Error: 4,
  "4": "Error"
});
const QrCodeMode = Object.freeze({
  /**
   * The new device is displaying the QR code.
   */
  Login: 0,
  "0": "Login",
  /**
   * The existing device is displaying the QR code.
   */
  Reciprocate: 1,
  "1": "Reciprocate"
});
const QrState = Object.freeze({
  /**
   * We have received the other device's details (from the
   * `m.key.verification.request` or `m.key.verification.ready`) and
   * established the shared secret, so can
   * display the QR code.
   */
  Created: 0,
  "0": "Created",
  /**
   * The other side has scanned our QR code and sent an
   * `m.key.verification.start` message with `method: m.reciprocate.v1` with
   * matching shared secret.
   */
  Scanned: 1,
  "1": "Scanned",
  /**
   * Our user has confirmed that the other device scanned successfully. We
   * have sent an `m.key.verification.done`.
   */
  Confirmed: 2,
  "2": "Confirmed",
  /**
   * We have scanned the other side's QR code and are able to send a
   * `m.key.verification.start` message with `method: m.reciprocate.v1`.
   *
   * Call `Qr::reciprocate` to build the start message.
   *
   * Note that, despite the name of this state, we have not necessarily
   * yet sent the `m.reciprocate.v1` message.
   */
  Reciprocated: 3,
  "3": "Reciprocated",
  /**
   * Verification complete: we have received an `m.key.verification.done`
   * from the other side.
   */
  Done: 4,
  "4": "Done",
  /**
   * Verification cancelled or failed.
   */
  Cancelled: 5,
  "5": "Cancelled"
});
const RequestType = Object.freeze({
  /**
   * Represents a `KeysUploadRequest`.
   */
  KeysUpload: 0,
  "0": "KeysUpload",
  /**
   * Represents a `KeysQueryRequest`.
   */
  KeysQuery: 1,
  "1": "KeysQuery",
  /**
   * Represents a `KeysClaimRequest`.
   */
  KeysClaim: 2,
  "2": "KeysClaim",
  /**
   * Represents a `ToDeviceRequest`.
   */
  ToDevice: 3,
  "3": "ToDevice",
  /**
   * Represents a `SignatureUploadRequest`.
   */
  SignatureUpload: 4,
  "4": "SignatureUpload",
  /**
   * Represents a `RoomMessageRequest`.
   */
  RoomMessage: 5,
  "5": "RoomMessage",
  /**
   * Represents a `KeysBackupRequest`.
   */
  KeysBackup: 6,
  "6": "KeysBackup"
});
const ShieldColor = Object.freeze({
  /**
   * Important warning
   */
  Red: 0,
  "0": "Red",
  /**
   * Low warning
   */
  Grey: 1,
  "1": "Grey",
  /**
   * No warning
   */
  None: 2,
  "2": "None"
});
const ShieldStateCode = Object.freeze({
  /**
   * Not enough information available to check the authenticity.
   */
  AuthenticityNotGuaranteed: 0,
  "0": "AuthenticityNotGuaranteed",
  /**
   * The sending device isn't yet known by the Client.
   */
  UnknownDevice: 1,
  "1": "UnknownDevice",
  /**
   * The sending device hasn't been verified by the sender.
   */
  UnsignedDevice: 2,
  "2": "UnsignedDevice",
  /**
   * The sender hasn't been verified by the Client's user.
   */
  UnverifiedIdentity: 3,
  "3": "UnverifiedIdentity",
  /**
   * An unencrypted event in an encrypted room.
   */
  SentInClear: 4,
  "4": "SentInClear",
  /**
   * The sender was previously verified but changed their identity.
   */
  VerificationViolation: 5,
  "5": "VerificationViolation"
});
const SignatureState = Object.freeze({
  /**
   * The signature is missing.
   */
  Missing: 0,
  "0": "Missing",
  /**
   * The signature is invalid.
   */
  Invalid: 1,
  "1": "Invalid",
  /**
   * The signature is valid but the device or user identity that created the
   * signature is not trusted.
   */
  ValidButNotTrusted: 2,
  "2": "ValidButNotTrusted",
  /**
   * The signature is valid and the device or user identity that created the
   * signature is trusted.
   */
  ValidAndTrusted: 3,
  "3": "ValidAndTrusted"
});
const TrustRequirement = Object.freeze({
  /**
   * Decrypt events from everyone regardless of trust
   */
  Untrusted: 0,
  "0": "Untrusted",
  /**
   * Only decrypt events from cross-signed or legacy devices
   */
  CrossSignedOrLegacy: 1,
  "1": "CrossSignedOrLegacy",
  /**
   * Only decrypt events from cross-signed devices
   */
  CrossSigned: 2,
  "2": "CrossSigned"
});
const VerificationMethod = Object.freeze({
  /**
   * The `m.sas.v1` verification method.
   *
   * SAS means Short Authentication String.
   */
  SasV1: 0,
  "0": "SasV1",
  /**
   * The `m.qr_code.scan.v1` verification method.
   */
  QrCodeScanV1: 1,
  "1": "QrCodeScanV1",
  /**
   * The `m.qr_code.show.v1` verification method.
   */
  QrCodeShowV1: 2,
  "2": "QrCodeShowV1",
  /**
   * The `m.reciprocate.v1` verification method.
   */
  ReciprocateV1: 3,
  "3": "ReciprocateV1"
});
const VerificationRequestPhase = Object.freeze({
  /**
   * The verification request has been newly created by us.
   */
  Created: 0,
  "0": "Created",
  /**
   * The verification request was received from the other party.
   */
  Requested: 1,
  "1": "Requested",
  /**
   * The verification request is ready to start a verification flow.
   */
  Ready: 2,
  "2": "Ready",
  /**
   * The verification request has transitioned into a concrete verification
   * flow. For example it transitioned into the emoji based SAS
   * verification.
   */
  Transitioned: 3,
  "3": "Transitioned",
  /**
   * The verification flow that was started with this request has finished.
   */
  Done: 4,
  "4": "Done",
  /**
   * The verification process has been cancelled.
   */
  Cancelled: 5,
  "5": "Cancelled"
});
const __wbindgen_enum_IdbRequestReadyState = ["pending", "done"];
const __wbindgen_enum_IdbTransactionMode = ["readonly", "readwrite", "versionchange", "readwriteflush", "cleanup"];
const AttachmentFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_attachment_free(ptr >>> 0, 1));
class Attachment {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    AttachmentFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_attachment_free(ptr, 0);
  }
  /**
   * Encrypt the content of the `Uint8Array`.
   *
   * It produces an `EncryptedAttachment`, which can be used to
   * retrieve the media encryption information, or the encrypted
   * data.
   * @param {Uint8Array} array
   * @returns {EncryptedAttachment}
   */
  static encrypt(array) {
    const ptr0 = passArray8ToWasm0(array, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.attachment_encrypt(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return EncryptedAttachment.__wrap(ret[0]);
  }
  /**
   * Decrypt an `EncryptedAttachment`.
   *
   * The encrypted attachment can be created manually, or from the
   * `encrypt` method.
   *
   * **Warning**: The encrypted attachment can be used only
   * **once**! The encrypted data will still be present, but the
   * media encryption info (which contain secrets) will be
   * destroyed. It is still possible to get a JSON-encoded backup
   * by calling `EncryptedAttachment.mediaEncryptionInfo`.
   * @param {EncryptedAttachment} attachment
   * @returns {Uint8Array}
   */
  static decrypt(attachment) {
    _assertClass(attachment, EncryptedAttachment);
    const ret = wasm.attachment_decrypt(attachment.__wbg_ptr);
    if (ret[3]) {
      throw takeFromExternrefTable0(ret[2]);
    }
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
  }
}
const BackupDecryptionKeyFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_backupdecryptionkey_free(ptr >>> 0, 1));
class BackupDecryptionKey {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(BackupDecryptionKey.prototype);
    obj.__wbg_ptr = ptr;
    BackupDecryptionKeyFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    BackupDecryptionKeyFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_backupdecryptionkey_free(ptr, 0);
  }
  /**
   * Create a new random [`BackupDecryptionKey`].
   * @returns {BackupDecryptionKey}
   */
  static createRandomKey() {
    const ret = wasm.backupdecryptionkey_createRandomKey();
    return BackupDecryptionKey.__wrap(ret);
  }
  /**
   * Try to create a [`BackupDecryptionKey`] from a base 64 encoded string.
   * @param {string} key
   * @returns {BackupDecryptionKey}
   */
  static fromBase64(key) {
    const ptr0 = passStringToWasm0(key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.backupdecryptionkey_fromBase64(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return BackupDecryptionKey.__wrap(ret[0]);
  }
  /**
   * Convert the backup decryption key to a base 64 encoded string.
   * @returns {string}
   */
  toBase64() {
    const ret = wasm.backupdecryptionkey_toBase64(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the public part of the backup key.
   * @returns {MegolmV1BackupKey}
   */
  get megolmV1PublicKey() {
    const ret = wasm.backupdecryptionkey_megolmV1PublicKey(this.__wbg_ptr);
    return MegolmV1BackupKey.__wrap(ret);
  }
  /**
   * Try to decrypt a message that was encrypted using the public part of the
   * backup key.
   * @param {string} ephemeral_key
   * @param {string} mac
   * @param {string} ciphertext
   * @returns {string}
   */
  decryptV1(ephemeral_key, mac, ciphertext) {
    let deferred5_0;
    let deferred5_1;
    try {
      const ptr0 = passStringToWasm0(ephemeral_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len0 = WASM_VECTOR_LEN;
      const ptr1 = passStringToWasm0(mac, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len1 = WASM_VECTOR_LEN;
      const ptr2 = passStringToWasm0(ciphertext, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len2 = WASM_VECTOR_LEN;
      const ret = wasm.backupdecryptionkey_decryptV1(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
      var ptr4 = ret[0];
      var len4 = ret[1];
      if (ret[3]) {
        ptr4 = 0;
        len4 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred5_0 = ptr4;
      deferred5_1 = len4;
      return getStringFromWasm0(ptr4, len4);
    } finally {
      wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
  }
}
const BackupKeysFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_backupkeys_free(ptr >>> 0, 1));
class BackupKeys {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(BackupKeys.prototype);
    obj.__wbg_ptr = ptr;
    BackupKeysFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    BackupKeysFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_backupkeys_free(ptr, 0);
  }
  /**
   * The key used to decrypt backed up room keys
   * @returns {BackupDecryptionKey | undefined}
   */
  get decryptionKey() {
    const ret = wasm.__wbg_get_backupkeys_decryptionKey(this.__wbg_ptr);
    return ret === 0 ? void 0 : BackupDecryptionKey.__wrap(ret);
  }
  /**
   * The key used to decrypt backed up room keys
   * @param {BackupDecryptionKey | null} [arg0]
   */
  set decryptionKey(arg0) {
    let ptr0 = 0;
    if (!isLikeNone(arg0)) {
      _assertClass(arg0, BackupDecryptionKey);
      ptr0 = arg0.__destroy_into_raw();
    }
    wasm.__wbg_set_backupkeys_decryptionKey(this.__wbg_ptr, ptr0);
  }
  /**
   * The version that we are using for backups.
   * @returns {string | undefined}
   */
  get backupVersion() {
    const ret = wasm.__wbg_get_backupkeys_backupVersion(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * The version that we are using for backups.
   * @param {string | null} [arg0]
   */
  set backupVersion(arg0) {
    var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupkeys_backupVersion(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The key used to decrypt backed up room keys, encoded as base64
   *
   * @deprecated Use `BackupKeys.decryptionKey.toBase64()`
   * @returns {string | undefined}
   */
  get decryptionKeyBase64() {
    const ret = wasm.backupkeys_decryptionKeyBase64(this.__wbg_ptr);
    return ret;
  }
}
const BackupSecretsBundleFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_backupsecretsbundle_free(ptr >>> 0, 1));
class BackupSecretsBundle {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(BackupSecretsBundle.prototype);
    obj.__wbg_ptr = ptr;
    BackupSecretsBundleFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    BackupSecretsBundleFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_backupsecretsbundle_free(ptr, 0);
  }
  /**
   * The backup decryption key, encoded as unpadded base64.
   * @returns {string}
   */
  get key() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_backupsecretsbundle_key(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The backup decryption key, encoded as unpadded base64.
   * @param {string} arg0
   */
  set key(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_key(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The backup version which this backup decryption key is used with.
   * @returns {string}
   */
  get backup_version() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_backupsecretsbundle_backup_version(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The backup version which this backup decryption key is used with.
   * @param {string} arg0
   */
  set backup_version(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_backup_version(this.__wbg_ptr, ptr0, len0);
  }
}
const Base64EncodedPkMessageFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_base64encodedpkmessage_free(ptr >>> 0, 1));
class Base64EncodedPkMessage {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Base64EncodedPkMessage.prototype);
    obj.__wbg_ptr = ptr;
    Base64EncodedPkMessageFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    Base64EncodedPkMessageFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_base64encodedpkmessage_free(ptr, 0);
  }
  /**
   * The base64-encoded ciphertext.
   * @returns {string}
   */
  get ciphertext() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_base64encodedpkmessage_ciphertext(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The base64-encoded ciphertext.
   * @param {string} arg0
   */
  set ciphertext(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_key(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The base64-encoded message authentication code (MAC).
   * @returns {string}
   */
  get mac() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_base64encodedpkmessage_mac(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The base64-encoded message authentication code (MAC).
   * @param {string} arg0
   */
  set mac(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_backup_version(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The base64-encoded ephemeral public key.
   * @returns {string}
   */
  get ephemeralKey() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_base64encodedpkmessage_ephemeralKey(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The base64-encoded ephemeral public key.
   * @param {string} arg0
   */
  set ephemeralKey(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_base64encodedpkmessage_ephemeralKey(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * Creates a new base64-encoded encrypted message from its parts.
   * @param {string} ciphertext
   * @param {string} mac
   * @param {string} ephemeral_key
   */
  constructor(ciphertext, mac, ephemeral_key) {
    const ptr0 = passStringToWasm0(ciphertext, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(mac, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(ephemeral_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.base64encodedpkmessage_new(ptr0, len0, ptr1, len1, ptr2, len2);
    this.__wbg_ptr = ret >>> 0;
    Base64EncodedPkMessageFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
}
const BaseMigrationDataFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_basemigrationdata_free(ptr >>> 0, 1));
class BaseMigrationData {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    BaseMigrationDataFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_basemigrationdata_free(ptr, 0);
  }
  /**
   * The user id of the account owner.
   * @returns {UserId | undefined}
   */
  get userId() {
    const ret = wasm.__wbg_get_basemigrationdata_userId(this.__wbg_ptr);
    return ret === 0 ? void 0 : UserId.__wrap(ret);
  }
  /**
   * The user id of the account owner.
   * @param {UserId | null} [arg0]
   */
  set userId(arg0) {
    let ptr0 = 0;
    if (!isLikeNone(arg0)) {
      _assertClass(arg0, UserId);
      ptr0 = arg0.__destroy_into_raw();
    }
    wasm.__wbg_set_basemigrationdata_userId(this.__wbg_ptr, ptr0);
  }
  /**
   * The device ID of the account owner.
   * @returns {DeviceId | undefined}
   */
  get deviceId() {
    const ret = wasm.__wbg_get_basemigrationdata_deviceId(this.__wbg_ptr);
    return ret === 0 ? void 0 : DeviceId.__wrap(ret);
  }
  /**
   * The device ID of the account owner.
   * @param {DeviceId | null} [arg0]
   */
  set deviceId(arg0) {
    let ptr0 = 0;
    if (!isLikeNone(arg0)) {
      _assertClass(arg0, DeviceId);
      ptr0 = arg0.__destroy_into_raw();
    }
    wasm.__wbg_set_basemigrationdata_deviceId(this.__wbg_ptr, ptr0);
  }
  /**
   * The pickle string holding the Olm Account, as returned by
   * `olm_pickle_account` in libolm.
   * @returns {string}
   */
  get pickledAccount() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_basemigrationdata_pickledAccount(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The pickle string holding the Olm Account, as returned by
   * `olm_pickle_account` in libolm.
   * @param {string} arg0
   */
  set pickledAccount(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_key(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The backup version that is currently active.
   * @returns {string | undefined}
   */
  get backupVersion() {
    const ret = wasm.__wbg_get_basemigrationdata_backupVersion(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * The backup version that is currently active.
   * @param {string | null} [arg0]
   */
  set backupVersion(arg0) {
    var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_basemigrationdata_backupVersion(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The backup recovery key, as a base64-encoded string.
   * @returns {string | undefined}
   */
  get backupRecoveryKey() {
    const ret = wasm.__wbg_get_basemigrationdata_backupRecoveryKey(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * The backup recovery key, as a base64-encoded string.
   * @param {string | null} [arg0]
   */
  set backupRecoveryKey(arg0) {
    var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_basemigrationdata_backupRecoveryKey(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The private, base64-encoded, master cross-signing key.
   * @returns {string | undefined}
   */
  get privateCrossSigningMasterKey() {
    const ret = wasm.__wbg_get_basemigrationdata_privateCrossSigningMasterKey(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * The private, base64-encoded, master cross-signing key.
   * @param {string | null} [arg0]
   */
  set privateCrossSigningMasterKey(arg0) {
    var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_basemigrationdata_privateCrossSigningMasterKey(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The private, base64-encoded, self-signing key.
   * @returns {string | undefined}
   */
  get privateCrossSigningSelfSigningKey() {
    const ret = wasm.__wbg_get_basemigrationdata_privateCrossSigningSelfSigningKey(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * The private, base64-encoded, self-signing key.
   * @param {string | null} [arg0]
   */
  set privateCrossSigningSelfSigningKey(arg0) {
    var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_basemigrationdata_privateCrossSigningSelfSigningKey(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The private, base64-encoded, user-signing key.
   * @returns {string | undefined}
   */
  get privateCrossSigningUserSigningKey() {
    const ret = wasm.__wbg_get_basemigrationdata_privateCrossSigningUserSigningKey(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * The private, base64-encoded, user-signing key.
   * @param {string | null} [arg0]
   */
  set privateCrossSigningUserSigningKey(arg0) {
    var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_basemigrationdata_privateCrossSigningUserSigningKey(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * Create a new `BaseMigrationData` with default values.
   */
  constructor() {
    const ret = wasm.basemigrationdata_new();
    this.__wbg_ptr = ret >>> 0;
    BaseMigrationDataFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
}
const CancelInfoFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_cancelinfo_free(ptr >>> 0, 1));
class CancelInfo {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(CancelInfo.prototype);
    obj.__wbg_ptr = ptr;
    CancelInfoFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    CancelInfoFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_cancelinfo_free(ptr, 0);
  }
  /**
   * Get the human readable reason of the cancellation.
   * @returns {string}
   */
  reason() {
    const ret = wasm.cancelinfo_reason(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the `code` (e.g. `m.user`) that was used to cancel the
   * verification.
   * @returns {string}
   */
  cancelCode() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.cancelinfo_cancelCode(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Was the verification cancelled by us?
   * @returns {boolean}
   */
  cancelledbyUs() {
    const ret = wasm.cancelinfo_cancelledbyUs(this.__wbg_ptr);
    return ret !== 0;
  }
}
const CheckCodeFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_checkcode_free(ptr >>> 0, 1));
class CheckCode {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(CheckCode.prototype);
    obj.__wbg_ptr = ptr;
    CheckCodeFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    CheckCodeFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_checkcode_free(ptr, 0);
  }
  /**
   * Convert the check code to an array of two bytes.
   *
   * The bytes can be converted to a more user-friendly representation. The
   * [`CheckCode::to_digit`] converts the bytes to a two-digit number.
   * @returns {Uint8Array}
   */
  as_bytes() {
    const ret = wasm.checkcode_as_bytes(this.__wbg_ptr);
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
  }
  /**
   * Convert the check code to two base-10 numbers.
   *
   * The number should be displayed with a leading 0 in case the first digit
   * is a 0.
   * @returns {number}
   */
  to_digit() {
    const ret = wasm.checkcode_to_digit(this.__wbg_ptr);
    return ret;
  }
}
const CollectStrategyFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_collectstrategy_free(ptr >>> 0, 1));
class CollectStrategy {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(CollectStrategy.prototype);
    obj.__wbg_ptr = ptr;
    CollectStrategyFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    CollectStrategyFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_collectstrategy_free(ptr, 0);
  }
  /**
   * Tests for equality between two [`CollectStrategy`]s.
   * @param {CollectStrategy} other
   * @returns {boolean}
   */
  eq(other) {
    _assertClass(other, CollectStrategy);
    const ret = wasm.collectstrategy_eq(this.__wbg_ptr, other.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Device based sharing strategy.
   *
   * @deprecated: use one of {@link allDevices}, {@link
   * errorOnUnverifiedUserProblem} or {@link onlyTrustedDevices}.
   * @param {boolean} only_allow_trusted_devices
   * @param {boolean} error_on_verified_user_problem
   * @returns {CollectStrategy}
   */
  static deviceBasedStrategy(only_allow_trusted_devices, error_on_verified_user_problem) {
    const ret = wasm.collectstrategy_deviceBasedStrategy(only_allow_trusted_devices, error_on_verified_user_problem);
    return CollectStrategy.__wrap(ret);
  }
  /**
   * Share with all (unblacklisted) devices.
   * @returns {CollectStrategy}
   */
  static allDevices() {
    const ret = wasm.collectstrategy_allDevices();
    return CollectStrategy.__wrap(ret);
  }
  /**
   * Share with all devices, except that errors for *verified* users cause
   * sharing to fail with an error.
   *
   * In this strategy, if a verified user has an unsigned device, or
   * a verified user has replaced their identity, key
   * sharing will fail with an error.
   *
   * Otherwise, keys are shared with unsigned devices as normal.
   *
   * Once the problematic devices are blacklisted or whitelisted the
   * caller can try sharing a second time.
   * @returns {CollectStrategy}
   */
  static errorOnUnverifiedUserProblem() {
    const ret = wasm.collectstrategy_errorOnUnverifiedUserProblem();
    return CollectStrategy.__wrap(ret);
  }
  /**
   * Share based on identity. Only distribute to devices signed by their
   * owner. If a user has no published identity he will not receive
   * any room keys.
   * @returns {CollectStrategy}
   */
  static identityBasedStrategy() {
    const ret = wasm.collectstrategy_identityBasedStrategy();
    return CollectStrategy.__wrap(ret);
  }
  /**
   * Only share keys with devices that we "trust". A device is trusted if any
   * of the following is true:
   *     - It was manually marked as trusted.
   *     - It was marked as verified via interactive verification.
   *     - It is signed by its owner identity, and this identity has been
   *       trusted via interactive verification.
   *     - It is the current own device of the user.
   * @returns {CollectStrategy}
   */
  static onlyTrustedDevices() {
    const ret = wasm.collectstrategy_onlyTrustedDevices();
    return CollectStrategy.__wrap(ret);
  }
}
const CrossSigningBootstrapRequestsFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_crosssigningbootstraprequests_free(ptr >>> 0, 1));
class CrossSigningBootstrapRequests {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(CrossSigningBootstrapRequests.prototype);
    obj.__wbg_ptr = ptr;
    CrossSigningBootstrapRequestsFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    CrossSigningBootstrapRequestsFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_crosssigningbootstraprequests_free(ptr, 0);
  }
  /**
   * An optional request to upload a device key.
   *
   * This will either be `undefined`, or an "outgoing request" as returned by
   * {@link OlmMachine.outgoingRequests}.
   *
   * If it is defined, the request should be sent first, and the result sent
   * back with {@link OlmMachine.markRequestAsSent}.
   * @returns {any}
   */
  get uploadKeysRequest() {
    const ret = wasm.__wbg_get_crosssigningbootstraprequests_uploadKeysRequest(this.__wbg_ptr);
    return ret;
  }
  /**
   * Request to upload the cross-signing keys.
   *
   * Should be sent second.
   * @returns {UploadSigningKeysRequest}
   */
  get uploadSigningKeysRequest() {
    const ret = wasm.__wbg_get_crosssigningbootstraprequests_uploadSigningKeysRequest(this.__wbg_ptr);
    return UploadSigningKeysRequest.__wrap(ret);
  }
  /**
   * Request to upload key signatures, including those for the cross-signing
   * keys, and maybe some for the optional uploaded key too.
   *
   * Should be sent last.
   * @returns {SignatureUploadRequest}
   */
  get uploadSignaturesRequest() {
    const ret = wasm.__wbg_get_crosssigningbootstraprequests_uploadSignaturesRequest(this.__wbg_ptr);
    return SignatureUploadRequest.__wrap(ret);
  }
}
const CrossSigningKeyExportFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_crosssigningkeyexport_free(ptr >>> 0, 1));
class CrossSigningKeyExport {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(CrossSigningKeyExport.prototype);
    obj.__wbg_ptr = ptr;
    CrossSigningKeyExportFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    CrossSigningKeyExportFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_crosssigningkeyexport_free(ptr, 0);
  }
  /**
   * The seed of the master key encoded as unpadded base64.
   * @returns {string | undefined}
   */
  get masterKey() {
    const ret = wasm.crosssigningkeyexport_masterKey(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * The seed of the self signing key encoded as unpadded base64.
   * @returns {string | undefined}
   */
  get self_signing_key() {
    const ret = wasm.crosssigningkeyexport_self_signing_key(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * The seed of the user signing key encoded as unpadded base64.
   * @returns {string | undefined}
   */
  get userSigningKey() {
    const ret = wasm.crosssigningkeyexport_userSigningKey(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
}
const CrossSigningStatusFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_crosssigningstatus_free(ptr >>> 0, 1));
class CrossSigningStatus {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(CrossSigningStatus.prototype);
    obj.__wbg_ptr = ptr;
    CrossSigningStatusFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    CrossSigningStatusFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_crosssigningstatus_free(ptr, 0);
  }
  /**
   * Do we have the master key?
   * @returns {boolean}
   */
  get hasMaster() {
    const ret = wasm.crosssigningstatus_hasMaster(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Do we have the self signing key? This one is necessary to sign
   * our own devices.
   * @returns {boolean}
   */
  get hasSelfSigning() {
    const ret = wasm.crosssigningstatus_hasSelfSigning(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Do we have the user signing key? This one is necessary to sign
   * other users.
   * @returns {boolean}
   */
  get hasUserSigning() {
    const ret = wasm.crosssigningstatus_hasUserSigning(this.__wbg_ptr);
    return ret !== 0;
  }
}
const Curve25519PublicKeyFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_curve25519publickey_free(ptr >>> 0, 1));
class Curve25519PublicKey {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Curve25519PublicKey.prototype);
    obj.__wbg_ptr = ptr;
    Curve25519PublicKeyFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    Curve25519PublicKeyFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_curve25519publickey_free(ptr, 0);
  }
  /**
   * Create a new [`Curve25519PublicKey`] from a base64 encoded string.
   * @param {string} key
   */
  constructor(key) {
    const ptr0 = passStringToWasm0(key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.curve25519publickey_new(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    Curve25519PublicKeyFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * The number of bytes a Curve25519 public key has.
   * @returns {number}
   */
  get length() {
    const ret = wasm.curve25519publickey_length(this.__wbg_ptr);
    return ret >>> 0;
  }
  /**
   * Serialize an Curve25519 public key to an unpadded base64
   * representation.
   * @returns {string}
   */
  toBase64() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.curve25519publickey_toBase64(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const Curve25519SecretKeyFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_curve25519secretkey_free(ptr >>> 0, 1));
class Curve25519SecretKey {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Curve25519SecretKey.prototype);
    obj.__wbg_ptr = ptr;
    Curve25519SecretKeyFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    Curve25519SecretKeyFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_curve25519secretkey_free(ptr, 0);
  }
  /**
   * Generates a new random Curve25519 secret key.
   * @returns {Curve25519SecretKey}
   */
  static new() {
    const ret = wasm.curve25519secretkey_new();
    return Curve25519SecretKey.__wrap(ret);
  }
  /**
   * Creates a `Curve25519SecretKey` from a base64-encoded representation of
   * the key.
   * @param {string} string
   * @returns {Curve25519SecretKey}
   */
  static fromBase64(string) {
    const ptr0 = passStringToWasm0(string, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.curve25519secretkey_fromBase64(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return Curve25519SecretKey.__wrap(ret[0]);
  }
  /**
   * Encodes the secret key into a base64 string.
   * @returns {string}
   */
  toBase64() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.curve25519secretkey_toBase64(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Converts the secret key into a raw byte vector.
   * @returns {Uint8Array}
   */
  toUint8Array() {
    const ret = wasm.curve25519secretkey_toUint8Array(this.__wbg_ptr);
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
  }
  /**
   * Creates a `Curve25519SecretKey` from a raw byte slice.
   * @param {Uint8Array} slice
   * @returns {Curve25519SecretKey}
   */
  static fromUint8Array(slice) {
    const ptr0 = passArray8ToWasm0(slice, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.curve25519secretkey_fromUint8Array(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return Curve25519SecretKey.__wrap(ret[0]);
  }
}
const DecryptedRoomEventFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_decryptedroomevent_free(ptr >>> 0, 1));
class DecryptedRoomEvent {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(DecryptedRoomEvent.prototype);
    obj.__wbg_ptr = ptr;
    DecryptedRoomEventFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DecryptedRoomEventFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_decryptedroomevent_free(ptr, 0);
  }
  /**
   * The JSON-encoded decrypted event.
   * @returns {string}
   */
  get event() {
    const ret = wasm.__wbg_get_decryptedroomevent_event(this.__wbg_ptr);
    return ret;
  }
  /**
   * The user ID of the event sender, note this is untrusted data
   * unless the `verification_state` is as well trusted.
   * @returns {UserId | undefined}
   */
  get sender() {
    const ret = wasm.decryptedroomevent_sender(this.__wbg_ptr);
    return ret === 0 ? void 0 : UserId.__wrap(ret);
  }
  /**
   * The device ID of the device that sent us the event, note this
   * is untrusted data unless `verification_state` is as well
   * trusted.
   * @returns {DeviceId | undefined}
   */
  get senderDevice() {
    const ret = wasm.decryptedroomevent_senderDevice(this.__wbg_ptr);
    return ret === 0 ? void 0 : DeviceId.__wrap(ret);
  }
  /**
   * The Curve25519 key of the device that created the megolm
   * decryption key originally.
   * @returns {string | undefined}
   */
  get senderCurve25519Key() {
    const ret = wasm.decryptedroomevent_senderCurve25519Key(this.__wbg_ptr);
    return ret;
  }
  /**
   * The signing Ed25519 key that have created the megolm key that
   * was used to decrypt this session.
   * @returns {string | undefined}
   */
  get senderClaimedEd25519Key() {
    const ret = wasm.decryptedroomevent_senderClaimedEd25519Key(this.__wbg_ptr);
    return ret;
  }
  /**
   * Returns an empty array
   *
   * Previously, this returned the chain of Curve25519 keys through which
   * this session was forwarded, via `m.forwarded_room_key` events.
   * However, that is not cryptographically reliable, and clients should not
   * be using it.
   *
   * @see https://github.com/matrix-org/matrix-spec/issues/1089
   * @returns {Array<any>}
   */
  get forwardingCurve25519KeyChain() {
    const ret = wasm.decryptedroomevent_forwardingCurve25519KeyChain(this.__wbg_ptr);
    return ret;
  }
  /**
   * The verification state of the device that sent us the event.
   * Note this is the state of the device at the time of
   * decryption. It may change in the future if a device gets
   * verified or deleted.
   * @param {boolean} strict
   * @returns {ShieldState | undefined}
   */
  shieldState(strict) {
    const ret = wasm.decryptedroomevent_shieldState(this.__wbg_ptr, strict);
    return ret === 0 ? void 0 : ShieldState.__wrap(ret);
  }
}
const DecryptionSettingsFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_decryptionsettings_free(ptr >>> 0, 1));
class DecryptionSettings {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DecryptionSettingsFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_decryptionsettings_free(ptr, 0);
  }
  /**
   * The trust level required to decrypt the event
   * @returns {TrustRequirement}
   */
  get sender_device_trust_requirement() {
    const ret = wasm.__wbg_get_decryptionsettings_sender_device_trust_requirement(this.__wbg_ptr);
    return ret;
  }
  /**
   * The trust level required to decrypt the event
   * @param {TrustRequirement} arg0
   */
  set sender_device_trust_requirement(arg0) {
    wasm.__wbg_set_decryptionsettings_sender_device_trust_requirement(this.__wbg_ptr, arg0);
  }
  /**
   * Create a new `DecryptionSettings` with the given trust requirement.
   * @param {TrustRequirement} sender_device_trust_requirement
   */
  constructor(sender_device_trust_requirement) {
    const ret = wasm.decryptionsettings_new(sender_device_trust_requirement);
    this.__wbg_ptr = ret >>> 0;
    DecryptionSettingsFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
}
const DehydratedDeviceFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_dehydrateddevice_free(ptr >>> 0, 1));
class DehydratedDevice {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(DehydratedDevice.prototype);
    obj.__wbg_ptr = ptr;
    DehydratedDeviceFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DehydratedDeviceFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_dehydrateddevice_free(ptr, 0);
  }
  /**
   * Create the request to upload the dehydrated device
   * @param {string} initial_device_display_name
   * @param {DehydratedDeviceKey} dehydrated_device_key
   * @returns {Promise<PutDehydratedDeviceRequest>}
   */
  keysForUpload(initial_device_display_name, dehydrated_device_key) {
    _assertClass(dehydrated_device_key, DehydratedDeviceKey);
    const ret = wasm.dehydrateddevice_keysForUpload(this.__wbg_ptr, initial_device_display_name, dehydrated_device_key.__wbg_ptr);
    return ret;
  }
}
const DehydratedDeviceKeyFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_dehydrateddevicekey_free(ptr >>> 0, 1));
class DehydratedDeviceKey {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(DehydratedDeviceKey.prototype);
    obj.__wbg_ptr = ptr;
    DehydratedDeviceKeyFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DehydratedDeviceKeyFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_dehydrateddevicekey_free(ptr, 0);
  }
  /**
   * Generates a new random dehydrated device key.
   * @returns {DehydratedDeviceKey}
   */
  static createRandomKey() {
    const ret = wasm.dehydrateddevicekey_createRandomKey();
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return DehydratedDeviceKey.__wrap(ret[0]);
  }
  /**
   * Generates a dehydrated device key from a given array.
   * @param {Uint8Array} array
   * @returns {DehydratedDeviceKey}
   */
  static createKeyFromArray(array) {
    const ret = wasm.dehydrateddevicekey_createKeyFromArray(array);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return DehydratedDeviceKey.__wrap(ret[0]);
  }
  /**
   * Convert the dehydrated device key to a base64-encoded string.
   * @returns {string}
   */
  toBase64() {
    const ret = wasm.dehydrateddevicekey_toBase64(this.__wbg_ptr);
    return ret;
  }
}
const DehydratedDevicesFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_dehydrateddevices_free(ptr >>> 0, 1));
class DehydratedDevices {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(DehydratedDevices.prototype);
    obj.__wbg_ptr = ptr;
    DehydratedDevicesFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DehydratedDevicesFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_dehydrateddevices_free(ptr, 0);
  }
  /**
   * Create a new {@link DehydratedDevice} which can be uploaded to the
   * server.
   * @returns {Promise<DehydratedDevice>}
   */
  create() {
    const ret = wasm.dehydrateddevices_create(this.__wbg_ptr);
    return ret;
  }
  /**
   * Rehydrate a dehydrated device.
   * @param {DehydratedDeviceKey} dehydrated_device_key
   * @param {DeviceId} device_id
   * @param {string} device_data
   * @returns {Promise<RehydratedDevice>}
   */
  rehydrate(dehydrated_device_key, device_id, device_data) {
    _assertClass(dehydrated_device_key, DehydratedDeviceKey);
    _assertClass(device_id, DeviceId);
    const ptr0 = passStringToWasm0(device_data, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.dehydrateddevices_rehydrate(this.__wbg_ptr, dehydrated_device_key.__wbg_ptr, device_id.__wbg_ptr, ptr0, len0);
    return ret;
  }
  /**
   * Get the cached dehydrated device key if any.
   *
   * `None` if the key was not previously cached (via
   * {@link DehydratedDevices.saveDehydratedDeviceKey}).
   * @returns {Promise<DehydratedDeviceKey | undefined>}
   */
  getDehydratedDeviceKey() {
    const ret = wasm.dehydrateddevices_getDehydratedDeviceKey(this.__wbg_ptr);
    return ret;
  }
  /**
   * Store the dehydrated device key in the crypto store.
   * @param {DehydratedDeviceKey} dehydrated_device_key
   * @returns {Promise<void>}
   */
  saveDehydratedDeviceKey(dehydrated_device_key) {
    _assertClass(dehydrated_device_key, DehydratedDeviceKey);
    const ret = wasm.dehydrateddevices_saveDehydratedDeviceKey(this.__wbg_ptr, dehydrated_device_key.__wbg_ptr);
    return ret;
  }
  /**
   * Clear the dehydrated device key saved in the crypto store.
   * @returns {Promise<void>}
   */
  deleteDehydratedDeviceKey() {
    const ret = wasm.dehydrateddevices_deleteDehydratedDeviceKey(this.__wbg_ptr);
    return ret;
  }
}
const DeviceFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_device_free(ptr >>> 0, 1));
class Device {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Device.prototype);
    obj.__wbg_ptr = ptr;
    DeviceFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DeviceFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_device_free(ptr, 0);
  }
  /**
   * Request an interactive verification with this device.
   *
   * Returns a 2-element array `[VerificationRequest, ToDeviceRequest]`.
   * @param {any[] | null} [methods]
   * @returns {Array<any>}
   */
  requestVerification(methods) {
    var ptr0 = isLikeNone(methods) ? 0 : passArrayJsValueToWasm0(methods, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    const ret = wasm.device_requestVerification(this.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Encrypt a to-device message to be sent to this device, using Olm
   * encryption.
   *
   * Prior to calling this method you must ensure that an Olm session is
   * available for the target device. This can be done by calling
   * {@link OlmMachine.getMissingSessions}.
   *
   * The caller is responsible for sending the encrypted
   * event to the target device. If multiple messages are
   * encrypted for the same device using this method they should be sent in
   * the same order as they are encrypted.
   *
   * # Returns
   *
   * Returns a promise for a JSON string containing the `content` of an
   * encrypted event, which be used to create the payload for a
   * `/sendToDevice` API.
   * @param {string} event_type
   * @param {any} content
   * @returns {Promise<string>}
   */
  encryptToDeviceEvent(event_type, content) {
    const ptr0 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.device_encryptToDeviceEvent(this.__wbg_ptr, ptr0, len0, content);
    return ret;
  }
  /**
   * Is this device considered to be verified.
   *
   * This method returns true if either the `is_locally_trusted`
   * method returns `true` or if the `is_cross_signing_trusted`
   * method returns `true`.
   * @returns {boolean}
   */
  isVerified() {
    const ret = wasm.device_isVerified(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Is this device considered to be verified using cross signing.
   * @returns {boolean}
   */
  isCrossSigningTrusted() {
    const ret = wasm.device_isCrossSigningTrusted(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Is this device cross-signed by its owner?
   * @returns {boolean}
   */
  isCrossSignedByOwner() {
    const ret = wasm.device_isCrossSignedByOwner(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Set the local trust state of the device to the given state.
   *
   * This won’t affect any cross signing trust state, this only
   * sets a flag marking to have the given trust state.
   *
   * `trust_state` represents the new trust state that should be
   * set for the device.
   * @param {LocalTrust} local_state
   * @returns {Promise<any>}
   */
  setLocalTrust(local_state) {
    const ret = wasm.device_setLocalTrust(this.__wbg_ptr, local_state);
    return ret;
  }
  /**
   * The user ID of the device owner.
   * @returns {UserId}
   */
  get userId() {
    const ret = wasm.device_userId(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * The unique ID of the device.
   * @returns {DeviceId}
   */
  get deviceId() {
    const ret = wasm.device_deviceId(this.__wbg_ptr);
    return DeviceId.__wrap(ret);
  }
  /**
   * Get the human readable name of the device.
   * @returns {string | undefined}
   */
  get displayName() {
    const ret = wasm.device_displayName(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * Get the key of the given key algorithm belonging to this device.
   * @param {DeviceKeyAlgorithmName} algorithm
   * @returns {DeviceKey | undefined}
   */
  getKey(algorithm) {
    const ret = wasm.device_getKey(this.__wbg_ptr, algorithm);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] === 0 ? void 0 : DeviceKey.__wrap(ret[0]);
  }
  /**
   * Get the Curve25519 key of the given device.
   * @returns {Curve25519PublicKey | undefined}
   */
  get curve25519Key() {
    const ret = wasm.device_curve25519Key(this.__wbg_ptr);
    return ret === 0 ? void 0 : Curve25519PublicKey.__wrap(ret);
  }
  /**
   * Get the Ed25519 key of the given device.
   * @returns {Ed25519PublicKey | undefined}
   */
  get ed25519Key() {
    const ret = wasm.device_ed25519Key(this.__wbg_ptr);
    return ret === 0 ? void 0 : Ed25519PublicKey.__wrap(ret);
  }
  /**
   * Get a map containing all the device keys.
   * @returns {Map<any, any>}
   */
  get keys() {
    const ret = wasm.device_keys(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the list of algorithms this device supports.
   *
   * Returns `Array<EncryptionAlgorithm>`.
   * @returns {Array<any>}
   */
  get algorithms() {
    const ret = wasm.device_algorithms(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get a map containing all the device signatures.
   * @returns {Signatures}
   */
  get signatures() {
    const ret = wasm.device_signatures(this.__wbg_ptr);
    return Signatures.__wrap(ret);
  }
  /**
   * Get the trust state of the device.
   * @returns {LocalTrust}
   */
  get localTrustState() {
    const ret = wasm.device_localTrustState(this.__wbg_ptr);
    return ret;
  }
  /**
   * Is the device locally marked as trusted?
   * @returns {boolean}
   */
  isLocallyTrusted() {
    const ret = wasm.device_isLocallyTrusted(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Is the device locally marked as blacklisted?
   *
   * Blacklisted devices won’t receive any group sessions.
   * @returns {boolean}
   */
  isBlacklisted() {
    const ret = wasm.device_isBlacklisted(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Is the device deleted?
   * @returns {boolean}
   */
  isDeleted() {
    const ret = wasm.device_isDeleted(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Timestamp representing the first time this device has been seen (in
   * milliseconds).
   * @returns {bigint}
   */
  firstTimeSeen() {
    const ret = wasm.device_firstTimeSeen(this.__wbg_ptr);
    return BigInt.asUintN(64, ret);
  }
  /**
   * Mark this device as verified.
   * Works only if the device is owned by the current user.
   *
   * Returns a signature upload request that needs to be sent out.
   * @returns {Promise<any>}
   */
  verify() {
    const ret = wasm.device_verify(this.__wbg_ptr);
    return ret;
  }
  /**
   * Whether or not the device is a dehydrated device.
   * @returns {boolean}
   */
  get isDehydrated() {
    const ret = wasm.device_isDehydrated(this.__wbg_ptr);
    return ret !== 0;
  }
}
const DeviceIdFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_deviceid_free(ptr >>> 0, 1));
class DeviceId {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(DeviceId.prototype);
    obj.__wbg_ptr = ptr;
    DeviceIdFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DeviceIdFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_deviceid_free(ptr, 0);
  }
  /**
   * Create a new `DeviceId`.
   * @param {string} id
   */
  constructor(id) {
    const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.deviceid_new(ptr0, len0);
    this.__wbg_ptr = ret >>> 0;
    DeviceIdFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Return the device ID as a string.
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.deviceid_toString(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const DeviceKeyFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_devicekey_free(ptr >>> 0, 1));
class DeviceKey {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(DeviceKey.prototype);
    obj.__wbg_ptr = ptr;
    DeviceKeyFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DeviceKeyFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_devicekey_free(ptr, 0);
  }
  /**
   * Get the name of the device key.
   * @returns {DeviceKeyName}
   */
  get name() {
    const ret = wasm.devicekey_name(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the value associated to the `Curve25519` device key name.
   * @returns {Curve25519PublicKey | undefined}
   */
  get curve25519() {
    const ret = wasm.devicekey_curve25519(this.__wbg_ptr);
    return ret === 0 ? void 0 : Curve25519PublicKey.__wrap(ret);
  }
  /**
   * Get the value associated to the `Ed25519` device key name.
   * @returns {Ed25519PublicKey | undefined}
   */
  get ed25519() {
    const ret = wasm.devicekey_ed25519(this.__wbg_ptr);
    return ret === 0 ? void 0 : Ed25519PublicKey.__wrap(ret);
  }
  /**
   * Get the value associated to the `Unknown` device key name.
   * @returns {string | undefined}
   */
  get unknown() {
    const ret = wasm.devicekey_unknown(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * Convert the `DeviceKey` into a base64 encoded string.
   * @returns {string}
   */
  toBase64() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.devicekey_toBase64(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const DeviceKeyAlgorithmFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_devicekeyalgorithm_free(ptr >>> 0, 1));
class DeviceKeyAlgorithm {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(DeviceKeyAlgorithm.prototype);
    obj.__wbg_ptr = ptr;
    DeviceKeyAlgorithmFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DeviceKeyAlgorithmFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_devicekeyalgorithm_free(ptr, 0);
  }
  /**
   * Read the device key algorithm's name. If the name is
   * `Unknown`, one may be interested by the `to_string` method to
   * read the original name.
   * @returns {DeviceKeyAlgorithmName}
   */
  get name() {
    const ret = wasm.devicekeyalgorithm_name(this.__wbg_ptr);
    return ret;
  }
  /**
   * Return the device key algorithm as a string.
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.devicekeyalgorithm_toString(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const DeviceKeyIdFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_devicekeyid_free(ptr >>> 0, 1));
class DeviceKeyId {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(DeviceKeyId.prototype);
    obj.__wbg_ptr = ptr;
    DeviceKeyIdFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DeviceKeyIdFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_devicekeyid_free(ptr, 0);
  }
  /**
   * Parse/validate and create a new `DeviceKeyId`.
   * @param {string} id
   */
  constructor(id) {
    const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.devicekeyid_new(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    DeviceKeyIdFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Returns key algorithm of the device key ID.
   * @returns {DeviceKeyAlgorithm}
   */
  get algorithm() {
    const ret = wasm.devicekeyid_algorithm(this.__wbg_ptr);
    return DeviceKeyAlgorithm.__wrap(ret);
  }
  /**
   * Returns device ID of the device key ID.
   * @returns {DeviceId}
   */
  get deviceId() {
    const ret = wasm.devicekeyid_deviceId(this.__wbg_ptr);
    return DeviceId.__wrap(ret);
  }
  /**
   * Return the device key ID as a string.
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.devicekeyid_toString(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const DeviceListsFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_devicelists_free(ptr >>> 0, 1));
class DeviceLists {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    DeviceListsFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_devicelists_free(ptr, 0);
  }
  /**
   * Create an empty `DeviceLists`.
   *
   * `changed` and `left` must be an array of `UserId`.
   *
   * Items inside `changed` and `left` will be invalidated by this method. Be
   * careful not to use the `UserId`s after this method has been called.
   * @param {UserId[] | null} [changed]
   * @param {UserId[] | null} [left]
   */
  constructor(changed, left) {
    var ptr0 = isLikeNone(changed) ? 0 : passArrayJsValueToWasm0(changed, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(left) ? 0 : passArrayJsValueToWasm0(left, wasm.__wbindgen_malloc);
    var len1 = WASM_VECTOR_LEN;
    const ret = wasm.devicelists_new(ptr0, len0, ptr1, len1);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    DeviceListsFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Returns true if there are no device list updates.
   * @returns {boolean}
   */
  isEmpty() {
    const ret = wasm.devicelists_isEmpty(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * List of users who have updated their device identity keys or
   * who now share an encrypted room with the client since the
   * previous sync
   * @returns {UserId[]}
   */
  get changed() {
    const ret = wasm.devicelists_changed(this.__wbg_ptr);
    var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
    return v1;
  }
  /**
   * List of users who no longer share encrypted rooms since the
   * previous sync response.
   * @returns {UserId[]}
   */
  get left() {
    const ret = wasm.devicelists_left(this.__wbg_ptr);
    var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
    return v1;
  }
}
const EciesFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_ecies_free(ptr >>> 0, 1));
class Ecies {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    EciesFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_ecies_free(ptr, 0);
  }
  /**
   * Create a new, random, unestablished ECIES session.
   *
   * This method will use the
   * [`MATRIX_QR_CODE_LOGIN`](https://github.com/matrix-org/matrix-spec-proposals/pull/4108)
   * info for domain separation when creating the session.
   */
  constructor() {
    const ret = wasm.ecies_new();
    this.__wbg_ptr = ret >>> 0;
    EciesFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Get our [`Curve25519PublicKey`].
   *
   * This public key needs to be sent to the other side to be able to
   * establish an ECIES channel.
   * @returns {Curve25519PublicKey}
   */
  public_key() {
    const ret = wasm.ecies_public_key(this.__wbg_ptr);
    return Curve25519PublicKey.__wrap(ret);
  }
  /**
   * Create a [`EstablishedEcies`] from an initial message encrypted by the
   * other side.
   * @param {string} initial_message
   * @returns {InboundCreationResult}
   */
  establish_inbound_channel(initial_message) {
    const ptr0 = passStringToWasm0(initial_message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ecies_establish_inbound_channel(this.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return InboundCreationResult.__wrap(ret[0]);
  }
  /**
   * Create an [`EstablishedEcies`] session using the other side's Curve25519
   * public key and an initial plaintext.
   *
   * After the channel has been established, we can encrypt messages to send
   * to the other side. The other side uses the initial message to
   * establishes the same channel on its side.
   * @param {Curve25519PublicKey} public_key
   * @param {string} initial_message
   * @returns {OutboundCreationResult}
   */
  establish_outbound_channel(public_key, initial_message) {
    _assertClass(public_key, Curve25519PublicKey);
    const ptr0 = passStringToWasm0(initial_message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ecies_establish_outbound_channel(this.__wbg_ptr, public_key.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return OutboundCreationResult.__wrap(ret[0]);
  }
}
const Ed25519PublicKeyFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_ed25519publickey_free(ptr >>> 0, 1));
class Ed25519PublicKey {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Ed25519PublicKey.prototype);
    obj.__wbg_ptr = ptr;
    Ed25519PublicKeyFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    Ed25519PublicKeyFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_ed25519publickey_free(ptr, 0);
  }
  /**
   * The number of bytes an Ed25519 public key has.
   * @returns {number}
   */
  get length() {
    const ret = wasm.ed25519publickey_length(this.__wbg_ptr);
    return ret >>> 0;
  }
  /**
   * Serialize an Ed25519 public key to an unpadded base64
   * representation.
   * @returns {string}
   */
  toBase64() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.ed25519publickey_toBase64(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const Ed25519SignatureFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_ed25519signature_free(ptr >>> 0, 1));
class Ed25519Signature {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Ed25519Signature.prototype);
    obj.__wbg_ptr = ptr;
    Ed25519SignatureFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    Ed25519SignatureFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_ed25519signature_free(ptr, 0);
  }
  /**
   * Try to create an Ed25519 signature from an unpadded base64
   * representation.
   * @param {string} signature
   */
  constructor(signature) {
    const ptr0 = passStringToWasm0(signature, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ed25519signature_new(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    Ed25519SignatureFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Serialize a Ed25519 signature to an unpadded base64
   * representation.
   * @returns {string}
   */
  toBase64() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.ed25519signature_toBase64(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const EmojiFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_emoji_free(ptr >>> 0, 1));
class Emoji {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Emoji.prototype);
    obj.__wbg_ptr = ptr;
    EmojiFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    EmojiFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_emoji_free(ptr, 0);
  }
  /**
   * The emoji symbol that represents a part of the short auth
   * string, for example: 🐶
   * @returns {string}
   */
  get symbol() {
    const ret = wasm.emoji_symbol(this.__wbg_ptr);
    return ret;
  }
  /**
   * The description of the emoji, for example ‘Dog’.
   * @returns {string}
   */
  get description() {
    const ret = wasm.emoji_description(this.__wbg_ptr);
    return ret;
  }
}
const EncryptedAttachmentFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_encryptedattachment_free(ptr >>> 0, 1));
class EncryptedAttachment {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(EncryptedAttachment.prototype);
    obj.__wbg_ptr = ptr;
    EncryptedAttachmentFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    EncryptedAttachmentFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_encryptedattachment_free(ptr, 0);
  }
  /**
   * Create a new encrypted attachment manually.
   *
   * It needs encrypted data, stored in an `Uint8Array`, and a
   * [media encryption
   * information](https://docs.rs/matrix-sdk-crypto/latest/matrix_sdk_crypto/struct.MediaEncryptionInfo.html),
   * as a JSON-encoded string.
   *
   * The media encryption information aren't stored as a string:
   * they are parsed, validated and fully deserialized.
   *
   * See [the specification to learn
   * more](https://spec.matrix.org/unstable/client-server-api/#extensions-to-mroommessage-msgtypes).
   * @param {Uint8Array} encrypted_data
   * @param {string} media_encryption_info
   */
  constructor(encrypted_data, media_encryption_info) {
    const ptr0 = passArray8ToWasm0(encrypted_data, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(media_encryption_info, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.encryptedattachment_new(ptr0, len0, ptr1, len1);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    EncryptedAttachmentFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * The actual encrypted data.
   *
   * **Warning**: It returns a **copy** of the entire encrypted
   * data; be nice with your memory.
   * @returns {Uint8Array}
   */
  get encryptedData() {
    const ret = wasm.encryptedattachment_encryptedData(this.__wbg_ptr);
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
  }
  /**
   * Return the media encryption info as a JSON-encoded string. The
   * structure is fully valid.
   *
   * If the media encryption info have been consumed already, it
   * will return `null`.
   * @returns {string | undefined}
   */
  get mediaEncryptionInfo() {
    const ret = wasm.encryptedattachment_mediaEncryptionInfo(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * Check whether the media encryption info has been consumed by
   * `Attachment.decrypt` already.
   * @returns {boolean}
   */
  get hasMediaEncryptionInfoBeenConsumed() {
    const ret = wasm.encryptedattachment_hasMediaEncryptionInfoBeenConsumed(this.__wbg_ptr);
    return ret !== 0;
  }
}
const EncryptionInfoFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_encryptioninfo_free(ptr >>> 0, 1));
class EncryptionInfo {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(EncryptionInfo.prototype);
    obj.__wbg_ptr = ptr;
    EncryptionInfoFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    EncryptionInfoFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_encryptioninfo_free(ptr, 0);
  }
  /**
   * The user ID of the event sender. Note this is untrusted data
   * unless `verification_state` is also trusted.
   * @returns {UserId}
   */
  get sender() {
    const ret = wasm.encryptioninfo_sender(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * The device ID of the device that sent us the event. Note this
   * is untrusted data unless `verification_state` is also
   * trusted.
   * @returns {DeviceId | undefined}
   */
  get senderDevice() {
    const ret = wasm.encryptioninfo_senderDevice(this.__wbg_ptr);
    return ret === 0 ? void 0 : DeviceId.__wrap(ret);
  }
  /**
   * The Curve25519 key of the device that created the megolm
   * decryption key originally.
   * @returns {string | undefined}
   */
  get senderCurve25519Key() {
    const ret = wasm.encryptioninfo_senderCurve25519Key(this.__wbg_ptr);
    return ret;
  }
  /**
   * The signing Ed25519 key that created the megolm key that
   * was used to decrypt this session.
   * @returns {string | undefined}
   */
  get senderClaimedEd25519Key() {
    const ret = wasm.encryptioninfo_senderClaimedEd25519Key(this.__wbg_ptr);
    return ret;
  }
  /**
   * The verification state of the device that sent us the event.
   * Note this is the state of the device at the time of
   * decryption. It may change in the future if a device gets
   * verified or deleted.
   *
   * # Arguments
   *
   * * `strict` - whether to enable "strict mode" verification. In non-strict
   *   mode, unverified users are given no shield, and keys that have been
   *   forwarded or restored from an insecure backup are given a grey shield
   *   (both get a red shield in strict mode).
   * @param {boolean} strict
   * @returns {ShieldState}
   */
  shieldState(strict) {
    const ret = wasm.encryptioninfo_shieldState(this.__wbg_ptr, strict);
    return ShieldState.__wrap(ret);
  }
}
const EncryptionSettingsFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_encryptionsettings_free(ptr >>> 0, 1));
class EncryptionSettings {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    EncryptionSettingsFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_encryptionsettings_free(ptr, 0);
  }
  /**
   * The encryption algorithm that should be used in the room.
   * @returns {EncryptionAlgorithm}
   */
  get algorithm() {
    const ret = wasm.__wbg_get_encryptionsettings_algorithm(this.__wbg_ptr);
    return ret;
  }
  /**
   * The encryption algorithm that should be used in the room.
   * @param {EncryptionAlgorithm} arg0
   */
  set algorithm(arg0) {
    wasm.__wbg_set_encryptionsettings_algorithm(this.__wbg_ptr, arg0);
  }
  /**
   * How long the session should be used before changing it,
   * expressed in microseconds.
   * @returns {bigint}
   */
  get rotationPeriod() {
    const ret = wasm.__wbg_get_encryptionsettings_rotationPeriod(this.__wbg_ptr);
    return BigInt.asUintN(64, ret);
  }
  /**
   * How long the session should be used before changing it,
   * expressed in microseconds.
   * @param {bigint} arg0
   */
  set rotationPeriod(arg0) {
    wasm.__wbg_set_encryptionsettings_rotationPeriod(this.__wbg_ptr, arg0);
  }
  /**
   * How many messages should be sent before changing the session.
   * @returns {bigint}
   */
  get rotationPeriodMessages() {
    const ret = wasm.__wbg_get_encryptionsettings_rotationPeriodMessages(this.__wbg_ptr);
    return BigInt.asUintN(64, ret);
  }
  /**
   * How many messages should be sent before changing the session.
   * @param {bigint} arg0
   */
  set rotationPeriodMessages(arg0) {
    wasm.__wbg_set_encryptionsettings_rotationPeriodMessages(this.__wbg_ptr, arg0);
  }
  /**
   * The history visibility of the room when the session was
   * created.
   * @returns {HistoryVisibility}
   */
  get historyVisibility() {
    const ret = wasm.__wbg_get_encryptionsettings_historyVisibility(this.__wbg_ptr);
    return ret;
  }
  /**
   * The history visibility of the room when the session was
   * created.
   * @param {HistoryVisibility} arg0
   */
  set historyVisibility(arg0) {
    wasm.__wbg_set_encryptionsettings_historyVisibility(this.__wbg_ptr, arg0);
  }
  /**
   * Should untrusted devices receive the room key, or should they be
   * excluded from the conversation.
   * @returns {CollectStrategy}
   */
  get sharingStrategy() {
    const ret = wasm.__wbg_get_encryptionsettings_sharingStrategy(this.__wbg_ptr);
    return CollectStrategy.__wrap(ret);
  }
  /**
   * Should untrusted devices receive the room key, or should they be
   * excluded from the conversation.
   * @param {CollectStrategy} arg0
   */
  set sharingStrategy(arg0) {
    _assertClass(arg0, CollectStrategy);
    var ptr0 = arg0.__destroy_into_raw();
    wasm.__wbg_set_encryptionsettings_sharingStrategy(this.__wbg_ptr, ptr0);
  }
  /**
   * Create a new `EncryptionSettings` with default values.
   */
  constructor() {
    const ret = wasm.encryptionsettings_new();
    this.__wbg_ptr = ret >>> 0;
    EncryptionSettingsFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
}
const EstablishedEciesFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_establishedecies_free(ptr >>> 0, 1));
class EstablishedEcies {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(EstablishedEcies.prototype);
    obj.__wbg_ptr = ptr;
    EstablishedEciesFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    EstablishedEciesFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_establishedecies_free(ptr, 0);
  }
  /**
   * Get our [`Curve25519PublicKey`].
   *
   * This public key needs to be sent to the other side so that it can
   * complete the ECIES channel establishment.
   * @returns {Curve25519PublicKey}
   */
  public_key() {
    const ret = wasm.establishedecies_public_key(this.__wbg_ptr);
    return Curve25519PublicKey.__wrap(ret);
  }
  /**
   * Encrypt the given plaintext using this [`EstablishedEcies`] session.
   * @param {string} message
   * @returns {string}
   */
  encrypt(message) {
    let deferred2_0;
    let deferred2_1;
    try {
      const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len0 = WASM_VECTOR_LEN;
      const ret = wasm.establishedecies_encrypt(this.__wbg_ptr, ptr0, len0);
      deferred2_0 = ret[0];
      deferred2_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
  }
  /**
   * Decrypt the given message using this [`EstablishedEcies`] session.
   * @param {string} message
   * @returns {string}
   */
  decrypt(message) {
    let deferred3_0;
    let deferred3_1;
    try {
      const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len0 = WASM_VECTOR_LEN;
      const ret = wasm.establishedecies_decrypt(this.__wbg_ptr, ptr0, len0);
      var ptr2 = ret[0];
      var len2 = ret[1];
      if (ret[3]) {
        ptr2 = 0;
        len2 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred3_0 = ptr2;
      deferred3_1 = len2;
      return getStringFromWasm0(ptr2, len2);
    } finally {
      wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
  }
  /**
   * Get the [`CheckCode`] which uniquely identifies this
   * [`EstablishedEcies`] session.
   *
   * This check code can be used to verify and confirm that both sides of the
   * session are indeed using the same shared secret.
   * @returns {CheckCode}
   */
  check_code() {
    const ret = wasm.establishedecies_check_code(this.__wbg_ptr);
    return CheckCode.__wrap(ret);
  }
}
const EventIdFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_eventid_free(ptr >>> 0, 1));
class EventId {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    EventIdFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_eventid_free(ptr, 0);
  }
  /**
   * Parse/validate and create a new `EventId`.
   * @param {string} id
   */
  constructor(id) {
    const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.eventid_new(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    EventIdFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Returns the event's localpart.
   * @returns {string}
   */
  get localpart() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.eventid_localpart(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Returns the server name of the event ID.
   * @returns {ServerName | undefined}
   */
  get serverName() {
    const ret = wasm.eventid_serverName(this.__wbg_ptr);
    return ret === 0 ? void 0 : ServerName.__wrap(ret);
  }
  /**
   * Return the event ID as a string.
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.eventid_toString(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const IdentityKeysFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_identitykeys_free(ptr >>> 0, 1));
class IdentityKeys {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(IdentityKeys.prototype);
    obj.__wbg_ptr = ptr;
    IdentityKeysFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    IdentityKeysFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_identitykeys_free(ptr, 0);
  }
  /**
   * The Ed25519 public key, used for signing.
   * @returns {Ed25519PublicKey}
   */
  get ed25519() {
    const ret = wasm.__wbg_get_identitykeys_ed25519(this.__wbg_ptr);
    return Ed25519PublicKey.__wrap(ret);
  }
  /**
   * The Ed25519 public key, used for signing.
   * @param {Ed25519PublicKey} arg0
   */
  set ed25519(arg0) {
    _assertClass(arg0, Ed25519PublicKey);
    var ptr0 = arg0.__destroy_into_raw();
    wasm.__wbg_set_identitykeys_ed25519(this.__wbg_ptr, ptr0);
  }
  /**
   * The Curve25519 public key, used for establish shared secrets.
   * @returns {Curve25519PublicKey}
   */
  get curve25519() {
    const ret = wasm.__wbg_get_identitykeys_curve25519(this.__wbg_ptr);
    return Curve25519PublicKey.__wrap(ret);
  }
  /**
   * The Curve25519 public key, used for establish shared secrets.
   * @param {Curve25519PublicKey} arg0
   */
  set curve25519(arg0) {
    _assertClass(arg0, Curve25519PublicKey);
    var ptr0 = arg0.__destroy_into_raw();
    wasm.__wbg_set_identitykeys_curve25519(this.__wbg_ptr, ptr0);
  }
}
const InboundCreationResultFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_inboundcreationresult_free(ptr >>> 0, 1));
class InboundCreationResult {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(InboundCreationResult.prototype);
    obj.__wbg_ptr = ptr;
    InboundCreationResultFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    InboundCreationResultFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_inboundcreationresult_free(ptr, 0);
  }
  /**
   * The established ECIES channel.
   * @returns {EstablishedEcies}
   */
  get channel() {
    const ret = wasm.__wbg_get_inboundcreationresult_channel(this.__wbg_ptr);
    return EstablishedEcies.__wrap(ret);
  }
  /**
   * The established ECIES channel.
   * @param {EstablishedEcies} arg0
   */
  set channel(arg0) {
    _assertClass(arg0, EstablishedEcies);
    var ptr0 = arg0.__destroy_into_raw();
    wasm.__wbg_set_inboundcreationresult_channel(this.__wbg_ptr, ptr0);
  }
  /**
   * The plaintext of the initial message.
   * @returns {string}
   */
  get message() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_inboundcreationresult_message(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The plaintext of the initial message.
   * @param {string} arg0
   */
  set message(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_key(this.__wbg_ptr, ptr0, len0);
  }
}
const InboundGroupSessionFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_inboundgroupsession_free(ptr >>> 0, 1));
class InboundGroupSession {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(InboundGroupSession.prototype);
    obj.__wbg_ptr = ptr;
    InboundGroupSessionFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    InboundGroupSessionFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_inboundgroupsession_free(ptr, 0);
  }
  /**
   * The room where this session is used in.
   * @returns {RoomId}
   */
  get roomId() {
    const ret = wasm.inboundgroupsession_roomId(this.__wbg_ptr);
    return RoomId.__wrap(ret);
  }
  /**
   * The Curve25519 key of the sender of this session, as a
   * [Curve25519PublicKey].
   * @returns {Curve25519PublicKey}
   */
  get senderKey() {
    const ret = wasm.inboundgroupsession_senderKey(this.__wbg_ptr);
    return Curve25519PublicKey.__wrap(ret);
  }
  /**
   * Returns the unique identifier for this session.
   * @returns {string}
   */
  get sessionId() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.inboundgroupsession_sessionId(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Has the session been imported from a file or server-side backup? As
   * opposed to being directly received as an `m.room_key` event.
   * @returns {boolean}
   */
  hasBeenImported() {
    const ret = wasm.inboundgroupsession_hasBeenImported(this.__wbg_ptr);
    return ret !== 0;
  }
}
const KeysBackupRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_keysbackuprequest_free(ptr >>> 0, 1));
class KeysBackupRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(KeysBackupRequest.prototype);
    obj.__wbg_ptr = ptr;
    KeysBackupRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    KeysBackupRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_keysbackuprequest_free(ptr, 0);
  }
  /**
   * The request ID.
   * @returns {string}
   */
  get id() {
    const ret = wasm.__wbg_get_keysbackuprequest_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A JSON-encoded string containing the rest of the payload: `rooms`.
   *
   * It represents the body of the HTTP request.
   * @returns {string}
   */
  get body() {
    const ret = wasm.__wbg_get_keysbackuprequest_body(this.__wbg_ptr);
    return ret;
  }
  /**
   * The backup version that these room keys should be part of.
   * @returns {string}
   */
  get version() {
    const ret = wasm.__wbg_get_keysbackuprequest_version(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a new `KeysBackupRequest`.
   * @param {string} id
   * @param {string} body
   * @param {string} version
   */
  constructor(id, body, version) {
    const ret = wasm.keysbackuprequest_new(id, body, version);
    this.__wbg_ptr = ret >>> 0;
    KeysBackupRequestFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Get its request type.
   * @returns {RequestType}
   */
  get type() {
    const ret = wasm.keysbackuprequest_type(this.__wbg_ptr);
    return ret;
  }
}
const KeysClaimRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_keysclaimrequest_free(ptr >>> 0, 1));
class KeysClaimRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(KeysClaimRequest.prototype);
    obj.__wbg_ptr = ptr;
    KeysClaimRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    KeysClaimRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_keysclaimrequest_free(ptr, 0);
  }
  /**
   * The request ID.
   * @returns {string}
   */
  get id() {
    const ret = wasm.__wbg_get_keysclaimrequest_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A JSON-encoded string containing the rest of the payload: `timeout`,
   * `one_time_keys`.
   *
   * It represents the body of the HTTP request.
   * @returns {string}
   */
  get body() {
    const ret = wasm.__wbg_get_keysclaimrequest_body(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a new `KeysClaimRequest`.
   * @param {string} id
   * @param {string} body
   */
  constructor(id, body) {
    const ret = wasm.keysclaimrequest_new(id, body);
    this.__wbg_ptr = ret >>> 0;
    KeysClaimRequestFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Get its request type.
   * @returns {RequestType}
   */
  get type() {
    const ret = wasm.keysclaimrequest_type(this.__wbg_ptr);
    return ret;
  }
}
const KeysQueryRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_keysqueryrequest_free(ptr >>> 0, 1));
class KeysQueryRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(KeysQueryRequest.prototype);
    obj.__wbg_ptr = ptr;
    KeysQueryRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    KeysQueryRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_keysqueryrequest_free(ptr, 0);
  }
  /**
   * The request ID.
   * @returns {string}
   */
  get id() {
    const ret = wasm.__wbg_get_keysqueryrequest_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A JSON-encoded string containing the rest of the payload: `timeout`,
   * `device_keys`, `token`.
   *
   * It represents the body of the HTTP request.
   * @returns {string}
   */
  get body() {
    const ret = wasm.__wbg_get_keysqueryrequest_body(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a new `KeysQueryRequest`.
   * @param {string} id
   * @param {string} body
   */
  constructor(id, body) {
    const ret = wasm.keysqueryrequest_new(id, body);
    this.__wbg_ptr = ret >>> 0;
    KeysQueryRequestFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Get its request type.
   * @returns {RequestType}
   */
  get type() {
    const ret = wasm.keysqueryrequest_type(this.__wbg_ptr);
    return ret;
  }
}
const KeysUploadRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_keysuploadrequest_free(ptr >>> 0, 1));
class KeysUploadRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(KeysUploadRequest.prototype);
    obj.__wbg_ptr = ptr;
    KeysUploadRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    KeysUploadRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_keysuploadrequest_free(ptr, 0);
  }
  /**
   * The request ID.
   * @returns {string}
   */
  get id() {
    const ret = wasm.__wbg_get_keysuploadrequest_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A JSON-encoded string containing the rest of the payload: `device_keys`,
   * `one_time_keys`, `fallback_keys`.
   *
   * It represents the body of the HTTP request.
   * @returns {string}
   */
  get body() {
    const ret = wasm.__wbg_get_keysuploadrequest_body(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a new `KeysUploadRequest`.
   * @param {string} id
   * @param {string} body
   */
  constructor(id, body) {
    const ret = wasm.keysuploadrequest_new(id, body);
    this.__wbg_ptr = ret >>> 0;
    KeysUploadRequestFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Get its request type.
   * @returns {RequestType}
   */
  get type() {
    const ret = wasm.keysuploadrequest_type(this.__wbg_ptr);
    return ret;
  }
}
const MaybeSignatureFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_maybesignature_free(ptr >>> 0, 1));
class MaybeSignature {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(MaybeSignature.prototype);
    obj.__wbg_ptr = ptr;
    MaybeSignatureFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    MaybeSignatureFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_maybesignature_free(ptr, 0);
  }
  /**
   * Check whether the signature has been successfully decoded.
   * @returns {boolean}
   */
  isValid() {
    const ret = wasm.maybesignature_isValid(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Check whether the signature could not be successfully decoded.
   * @returns {boolean}
   */
  isInvalid() {
    const ret = wasm.maybesignature_isInvalid(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * The signature, if successfully decoded.
   * @returns {Signature | undefined}
   */
  get signature() {
    const ret = wasm.maybesignature_signature(this.__wbg_ptr);
    return ret === 0 ? void 0 : Signature.__wrap(ret);
  }
  /**
   * The base64 encoded string that is claimed to contain a
   * signature but could not be decoded, if any.
   * @returns {string | undefined}
   */
  get invalidSignatureSource() {
    const ret = wasm.maybesignature_invalidSignatureSource(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
}
const MegolmDecryptionErrorFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_megolmdecryptionerror_free(ptr >>> 0, 1));
class MegolmDecryptionError {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(MegolmDecryptionError.prototype);
    obj.__wbg_ptr = ptr;
    MegolmDecryptionErrorFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    MegolmDecryptionErrorFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_megolmdecryptionerror_free(ptr, 0);
  }
  /**
   * Description code for the error. See `DecryptionErrorCode`
   * @returns {DecryptionErrorCode}
   */
  get code() {
    const ret = wasm.__wbg_get_megolmdecryptionerror_code(this.__wbg_ptr);
    return ret;
  }
  /**
   * detailed description
   * @returns {string}
   */
  get description() {
    const ret = wasm.__wbg_get_megolmdecryptionerror_description(this.__wbg_ptr);
    return ret;
  }
  /**
   * Withheld code if any. Only for `UnknownMessageIndex` error code
   * @returns {string | undefined}
   */
  get maybe_withheld() {
    const ret = wasm.__wbg_get_megolmdecryptionerror_maybe_withheld(this.__wbg_ptr);
    return ret;
  }
}
const MegolmV1BackupKeyFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_megolmv1backupkey_free(ptr >>> 0, 1));
class MegolmV1BackupKey {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(MegolmV1BackupKey.prototype);
    obj.__wbg_ptr = ptr;
    MegolmV1BackupKeyFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    MegolmV1BackupKeyFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_megolmv1backupkey_free(ptr, 0);
  }
  /**
   * The actual base64 encoded public key.
   * @returns {string}
   */
  get publicKeyBase64() {
    const ret = wasm.megolmv1backupkey_publicKeyBase64(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the full name of the backup algorithm this backup key supports.
   * @returns {string}
   */
  get algorithm() {
    const ret = wasm.megolmv1backupkey_algorithm(this.__wbg_ptr);
    return ret;
  }
}
const MigrationFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_migration_free(ptr >>> 0, 1));
class Migration {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    MigrationFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_migration_free(ptr, 0);
  }
  /**
   * Import the base dataset from a libolm-based setup to a vodozemac-based
   * setup stored in IndexedDB.
   *
   * Populates the user credentials, Olm account, backup data, etc. This is
   * the first step in the migration process. Once this base data is
   * imported, further data can be imported with {@link
   * migrateOlmSessions}, {@link migrateMegolmSessions}, and TODO room
   * settings.
   *
   * # Arguments
   *
   * * `data` - The data to be migrated
   * * `pickle_key` - The libolm pickle key that was used to pickle the olm
   *   account objects.
   * * `store_handle` - A connection to the CryptoStore which will be used to
   *   store the vodozemac data.
   * @param {BaseMigrationData} data
   * @param {Uint8Array} pickle_key
   * @param {StoreHandle} store_handle
   * @returns {Promise<any>}
   */
  static migrateBaseData(data, pickle_key, store_handle) {
    _assertClass(data, BaseMigrationData);
    _assertClass(store_handle, StoreHandle);
    const ret = wasm.migration_migrateBaseData(data.__wbg_ptr, pickle_key, store_handle.__wbg_ptr);
    return ret;
  }
  /**
   * Migrate Olm sessions of a libolm-based setup to a vodozemac-based setup
   * stored in an indexedDB crypto store.
   *
   * Before this method can be used, {@link migrateBaseData} must be used to
   * import the base data into the crypto store.
   *
   * This method should be called a number of times, with separate batches of
   * `sessions`. If a progress display is given, it can be updated after
   * each batch is successfully imported.
   *
   * # Arguments
   *
   * * `sessions` - An `Array` of {@link PickledSession}s to import. Items
   *   inside `sessions` will be invalidated by this method.
   * * `pickle_key` - The libolm pickle key that was used to pickle the olm
   *   session objects.
   * * `store_handle` - A connection to the CryptoStore which will be used to
   *   store the vodozemac data.
   * @param {PickledSession[]} sessions
   * @param {Uint8Array} pickle_key
   * @param {StoreHandle} store_handle
   * @returns {Promise<any>}
   */
  static migrateOlmSessions(sessions, pickle_key, store_handle) {
    const ptr0 = passArrayJsValueToWasm0(sessions, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(store_handle, StoreHandle);
    const ret = wasm.migration_migrateOlmSessions(ptr0, len0, pickle_key, store_handle.__wbg_ptr);
    return ret;
  }
  /**
   * Migrate Megolm sessions of a libolm-based setup to a vodozemac-based
   * setup stored in an indexedDB crypto store.
   *
   * Before this method can be used, {@link migrateBaseData} must be used to
   * import the base data into the crypto store.
   *
   * This method should be called a number of times, with separate batches of
   * `sessions`. If a progress display is given, it can be updated after
   * each batch is successfully imported.
   *
   * # Arguments
   *
   * * `sessions` - An `Array` of {@link PickledInboundGroupSession}s to
   *   import. Items inside `sessions` will be invalidated by this method.
   * * `pickle_key` - The libolm pickle key that was used to pickle the
   *   megolm session objects.
   * * `store_handle` - A connection to the CryptoStore which will be used to
   *   store the vodozemac data.
   * @param {PickledInboundGroupSession[]} sessions
   * @param {Uint8Array} pickle_key
   * @param {StoreHandle} store_handle
   * @returns {Promise<any>}
   */
  static migrateMegolmSessions(sessions, pickle_key, store_handle) {
    const ptr0 = passArrayJsValueToWasm0(sessions, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(store_handle, StoreHandle);
    const ret = wasm.migration_migrateMegolmSessions(ptr0, len0, pickle_key, store_handle.__wbg_ptr);
    return ret;
  }
}
const OlmMachineFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_olmmachine_free(ptr >>> 0, 1));
class OlmMachine {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(OlmMachine.prototype);
    obj.__wbg_ptr = ptr;
    OlmMachineFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    OlmMachineFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_olmmachine_free(ptr, 0);
  }
  /**
   * Constructor will always fail. To create a new `OlmMachine`, please use
   * the `initialize` method.
   *
   * Why this pattern? `initialize` returns a `Promise`. Returning a
   */
  constructor() {
    const ret = wasm.olmmachine_new();
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    OlmMachineFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Create a new `OlmMachine`.
   *
   * The created machine will keep the encryption keys either in a IndexedDB
   * based store, or in a memory store and once the objects is dropped,
   * the keys will be lost.
   *
   * # Arguments
   *
   * * `user_id` - represents the unique ID of the user that owns this
   * machine.
   *
   * * `device_id` - represents the unique ID of the device
   * that owns this machine.
   *
   * * `store_name` - The name that should be used to open the IndexedDB
   *   based database. If this isn't provided, a memory-only store will be
   *   used. *Note* the memory-only store will lose your E2EE keys when the
   *   `OlmMachine` gets dropped.
   *
   * * `store_passphrase` - The passphrase that should be used to encrypt the
   *   IndexedDB-based store.
   * @param {UserId} user_id
   * @param {DeviceId} device_id
   * @param {string | null} [store_name]
   * @param {string | null} [store_passphrase]
   * @returns {Promise<any>}
   */
  static initialize(user_id, device_id, store_name, store_passphrase) {
    _assertClass(user_id, UserId);
    _assertClass(device_id, DeviceId);
    var ptr0 = isLikeNone(store_name) ? 0 : passStringToWasm0(store_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(store_passphrase) ? 0 : passStringToWasm0(store_passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_initialize(user_id.__wbg_ptr, device_id.__wbg_ptr, ptr0, len0, ptr1, len1);
    return ret;
  }
  /**
   * Create a new `OlmMachine` backed by an existing store.
   *
   * # Arguments
   *
   * * `user_id` - represents the unique ID of the user that owns this
   * machine.
   *
   * * `device_id` - represents the unique ID of the device
   * that owns this machine.
   *
   * * `store_handle` - the connection to the crypto store to be used for
   *   this machine.
   * @param {UserId} user_id
   * @param {DeviceId} device_id
   * @param {StoreHandle} store_handle
   * @returns {Promise<any>}
   */
  static initFromStore(user_id, device_id, store_handle) {
    _assertClass(user_id, UserId);
    _assertClass(device_id, DeviceId);
    _assertClass(store_handle, StoreHandle);
    const ret = wasm.olmmachine_initFromStore(user_id.__wbg_ptr, device_id.__wbg_ptr, store_handle.__wbg_ptr);
    return ret;
  }
  /**
   * The unique user ID that owns this `OlmMachine` instance.
   * @returns {UserId}
   */
  get userId() {
    const ret = wasm.olmmachine_userId(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * The unique device ID that identifies this `OlmMachine`.
   * @returns {DeviceId}
   */
  get deviceId() {
    const ret = wasm.olmmachine_deviceId(this.__wbg_ptr);
    return DeviceId.__wrap(ret);
  }
  /**
   * The time, in milliseconds since the unix epoch, at which the `Account`
   * backing this `OlmMachine` was created.
   *
   * An `Account` is created when an `OlmMachine` is first instantiated
   * against a given `Store`, at which point it creates identity keys etc.
   * This method returns the timestamp, according to the local clock, at
   * which that happened.
   * @returns {number}
   */
  get deviceCreationTimeMs() {
    const ret = wasm.olmmachine_deviceCreationTimeMs(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the public parts of our Olm identity keys.
   * @returns {IdentityKeys}
   */
  get identityKeys() {
    const ret = wasm.olmmachine_identityKeys(this.__wbg_ptr);
    return IdentityKeys.__wrap(ret);
  }
  /**
   * Get the display name of our own device.
   * @returns {Promise<any>}
   */
  get displayName() {
    const ret = wasm.olmmachine_displayName(this.__wbg_ptr);
    return ret;
  }
  /**
   * Whether automatic transmission of room key requests is enabled.
   *
   * Room key requests allow the device to request room keys that it might
   * have missed in the original share using `m.room_key_request`
   * events.
   * @returns {boolean}
   */
  get roomKeyRequestsEnabled() {
    const ret = wasm.olmmachine_roomKeyRequestsEnabled(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Enable or disable automatic transmission of room key requests.
   * @param {boolean} enabled
   */
  set roomKeyRequestsEnabled(enabled) {
    wasm.olmmachine_set_roomKeyRequestsEnabled(this.__wbg_ptr, enabled);
  }
  /**
   * Whether room key forwarding is enabled.
   *
   * If room key forwarding is enabled, we will automatically reply to
   * incoming `m.room_key_request` messages from verified devices by
   * forwarding the requested key (if we have it).
   * @returns {boolean}
   */
  get roomKeyForwardingEnabled() {
    const ret = wasm.olmmachine_roomKeyForwardingEnabled(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Enable or disable room key forwarding.
   * @param {boolean} enabled
   */
  set roomKeyForwardingEnabled(enabled) {
    wasm.olmmachine_set_roomKeyForwardingEnabled(this.__wbg_ptr, enabled);
  }
  /**
   * Get the list of users whose devices we are currently tracking.
   *
   * A user can be marked for tracking using the
   * [`update_tracked_users`](#method.update_tracked_users) method.
   *
   * Returns a `Set<UserId>`.
   * @returns {Promise<any>}
   */
  trackedUsers() {
    const ret = wasm.olmmachine_trackedUsers(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Update the list of tracked users.
   *
   * The OlmMachine maintains a list of users whose devices we are keeping
   * track of: these are known as "tracked users". These must be users
   * that we share a room with, so that the server sends us updates for
   * their device lists.
   *
   * # Arguments
   *
   * * `users` - An array of user ids that should be added to the list of
   *   tracked users
   *
   * Any users that hadn't been seen before will be flagged for a key query
   * immediately, and whenever `receive_sync_changes` receives a
   * "changed" notification for that user in the future.
   *
   * Users that were already in the list are unaffected.
   *
   * Items inside `users` will be invalidated by this method. Be careful not
   * to use the `UserId`s after this method has been called.
   * @param {UserId[]} users
   * @returns {Promise<any>}
   */
  updateTrackedUsers(users) {
    const ptr0 = passArrayJsValueToWasm0(users, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_updateTrackedUsers(this.__wbg_ptr, ptr0, len0);
    return ret;
  }
  /**
   * Mark all tracked users as dirty.
   *
   * All users *whose device lists we are tracking* are flagged as needing a
   * key query. Users whose devices we are not tracking are ignored.
   * @returns {Promise<void>}
   */
  markAllTrackedUsersAsDirty() {
    const ret = wasm.olmmachine_markAllTrackedUsersAsDirty(this.__wbg_ptr);
    return ret;
  }
  /**
   * Handle to-device events and one-time key counts from a sync
   * response.
   *
   * This will decrypt and handle to-device events returning the
   * decrypted versions of them.
   *
   * To decrypt an event from the room timeline call
   * `decrypt_room_event`.
   *
   * # Arguments
   *
   * * `to_device_events`: the JSON-encoded to-device evens from the `/sync`
   *   response
   * * `changed_devices`: the mapping of changed and left devices, from the
   *   `/sync` response
   * * `one_time_keys_counts`: The number of one-time keys on the server,
   *   from the `/sync` response. A `Map` from string (encryption algorithm)
   *   to number (number of keys).
   * * `unused_fallback_keys`: Optionally, a `Set` of unused fallback keys on
   *   the server, from the `/sync` response. If this is set, it is used to
   *   determine if new fallback keys should be uploaded.
   *
   * # Returns
   *
   * A list of JSON strings, containing the decrypted to-device events.
   * @param {string} to_device_events
   * @param {DeviceLists} changed_devices
   * @param {Map<any, any>} one_time_keys_counts
   * @param {Set<any> | null} [unused_fallback_keys]
   * @returns {Promise<any>}
   */
  receiveSyncChanges(to_device_events, changed_devices, one_time_keys_counts, unused_fallback_keys) {
    const ptr0 = passStringToWasm0(to_device_events, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(changed_devices, DeviceLists);
    const ret = wasm.olmmachine_receiveSyncChanges(this.__wbg_ptr, ptr0, len0, changed_devices.__wbg_ptr, one_time_keys_counts, isLikeNone(unused_fallback_keys) ? 0 : addToExternrefTable0(unused_fallback_keys));
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Get the outgoing requests that need to be sent out.
   *
   * This returns a list of values, each of which can be any of:
   *   * {@link KeysUploadRequest},
   *   * {@link KeysQueryRequest},
   *   * {@link KeysClaimRequest},
   *   * {@link ToDeviceRequest},
   *   * {@link SignatureUploadRequest},
   *   * {@link RoomMessageRequest}, or
   *   * {@link KeysBackupRequest}.
   *
   * Those requests need to be sent out to the server and the
   * responses need to be passed back to the state machine
   * using {@link OlmMachine.markRequestAsSent}.
   * @returns {Promise<any>}
   */
  outgoingRequests() {
    const ret = wasm.olmmachine_outgoingRequests(this.__wbg_ptr);
    return ret;
  }
  /**
   * Mark the request with the given request ID as sent (see
   * `outgoing_requests`).
   *
   * Arguments are:
   *
   * * `request_id` represents the unique ID of the request that was sent
   *   out. This is needed to couple the response with the now sent out
   *   request.
   * * `response_type` represents the type of the request that was sent out.
   * * `response` represents the response that was received from the server
   *   after the outgoing request was sent out.
   * @param {string} request_id
   * @param {RequestType} request_type
   * @param {string} response
   * @returns {Promise<any>}
   */
  markRequestAsSent(request_id, request_type, response) {
    const ptr0 = passStringToWasm0(request_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(response, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_markRequestAsSent(this.__wbg_ptr, ptr0, len0, request_type, ptr1, len1);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Encrypt a room message for the given room.
   *
   * **Note**: A room key needs to be shared with the group of users that are
   * members in the given room. If this is not done this method will panic.
   *
   * The usual flow to encrypt an event using this state machine is as
   * follows:
   *
   * 1. Get the one-time key claim request to establish 1:1 Olm sessions for
   *    the room members of the room we wish to participate in. This is done
   *    using the [`get_missing_sessions()`](Self::get_missing_sessions)
   *    method. This method call should be locked per call.
   *
   * 2. Share a room key with all the room members using the
   *    [`share_room_key()`](Self::share_room_key). This method call should
   *    be locked per room.
   *
   * 3. Encrypt the event using this method.
   *
   * 4. Send the encrypted event to the server.
   *
   * After the room key is shared steps 1 and 2 will become noops, unless
   * there's some changes in the room membership or in the list of devices a
   * member has.
   *
   *
   * `room_id` is the ID of the room for which the message should
   * be encrypted. `event_type` is the type of the event. `content`
   * is the plaintext content of the message that should be
   * encrypted.
   *
   * # Panics
   *
   * Panics if a group session for the given room wasn't shared
   * beforehand.
   * @param {RoomId} room_id
   * @param {string} event_type
   * @param {string} content
   * @returns {Promise<any>}
   */
  encryptRoomEvent(room_id, event_type, content) {
    _assertClass(room_id, RoomId);
    const ptr0 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(content, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_encryptRoomEvent(this.__wbg_ptr, room_id.__wbg_ptr, ptr0, len0, ptr1, len1);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Decrypt an event from a room timeline.
   *
   * # Arguments
   *
   * * `event`, the event that should be decrypted.
   * * `room_id`, the ID of the room where the event was sent to.
   *
   * # Returns
   *
   * A `Promise` which resolves to a {@link DecryptedRoomEvent} instance, or
   * rejects with a {@link MegolmDecryptionError} instance.
   * @param {string} event
   * @param {RoomId} room_id
   * @param {DecryptionSettings} decryption_settings
   * @returns {Promise<any>}
   */
  decryptRoomEvent(event, room_id, decryption_settings) {
    const ptr0 = passStringToWasm0(event, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(room_id, RoomId);
    _assertClass(decryption_settings, DecryptionSettings);
    const ret = wasm.olmmachine_decryptRoomEvent(this.__wbg_ptr, ptr0, len0, room_id.__wbg_ptr, decryption_settings.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Get encryption info for a decrypted timeline event.
   *
   * This recalculates the `EncryptionInfo` data that is returned by
   * `decryptRoomEvent`, based on the current
   * verification status of the sender, etc.
   *
   * Returns an error for an unencrypted event.
   *
   * # Arguments
   *
   * * `event` - The event to get information for.
   * * `room_id` - The ID of the room where the event was sent to.
   *
   * # Returns
   *
   * {@link EncryptionInfo}
   * @param {string} event
   * @param {RoomId} room_id
   * @returns {Promise<any>}
   */
  getRoomEventEncryptionInfo(event, room_id) {
    const ptr0 = passStringToWasm0(event, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(room_id, RoomId);
    const ret = wasm.olmmachine_getRoomEventEncryptionInfo(this.__wbg_ptr, ptr0, len0, room_id.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Get the status of the private cross signing keys.
   *
   * This can be used to check which private cross signing keys we
   * have stored locally.
   * @returns {Promise<any>}
   */
  crossSigningStatus() {
    const ret = wasm.olmmachine_crossSigningStatus(this.__wbg_ptr);
    return ret;
  }
  /**
   * Export all the secrets we have in the store into a {@link
   * SecretsBundle}.
   *
   * This method will export all the private cross-signing keys and, if
   * available, the private part of a backup key and its accompanying
   * version.
   *
   * The method will fail if we don't have all three private cross-signing
   * keys available.
   *
   * **Warning**: Only export this and share it with a trusted recipient,
   * i.e. if an existing device is sharing this with a new device.
   * @returns {Promise<SecretsBundle>}
   */
  exportSecretsBundle() {
    const ret = wasm.olmmachine_exportSecretsBundle(this.__wbg_ptr);
    return ret;
  }
  /**
   * Import and persists secrets from a {@link SecretsBundle}.
   *
   * This method will import all the private cross-signing keys and, if
   * available, the private part of a backup key and its accompanying
   * version into the store.
   *
   * **Warning**: Only import this from a trusted source, i.e. if an existing
   * device is sharing this with a new device. The imported cross-signing
   * keys will create a {@link OwnUserIdentity} and mark it as verified.
   *
   * The backup key will be persisted in the store and can be enabled using
   * the BackupMachine.
   *
   * The provided `SecretsBundle` is freed by this method; be careful not to
   * use it once this method has been called.
   * @param {SecretsBundle} bundle
   * @returns {Promise<void>}
   */
  importSecretsBundle(bundle) {
    _assertClass(bundle, SecretsBundle);
    var ptr0 = bundle.__destroy_into_raw();
    const ret = wasm.olmmachine_importSecretsBundle(this.__wbg_ptr, ptr0);
    return ret;
  }
  /**
   * Export all the private cross signing keys we have.
   *
   * The export will contain the seeds for the ed25519 keys as
   * unpadded base64 encoded strings.
   *
   * Returns `null` if we don’t have any private cross signing keys;
   * otherwise returns a `CrossSigningKeyExport`.
   * @returns {Promise<any>}
   */
  exportCrossSigningKeys() {
    const ret = wasm.olmmachine_exportCrossSigningKeys(this.__wbg_ptr);
    return ret;
  }
  /**
   * Import our private cross signing keys.
   *
   * The keys should be provided as unpadded-base64-encoded strings.
   *
   * Returns a `CrossSigningStatus`.
   * @param {string | null} [master_key]
   * @param {string | null} [self_signing_key]
   * @param {string | null} [user_signing_key]
   * @returns {Promise<any>}
   */
  importCrossSigningKeys(master_key, self_signing_key, user_signing_key) {
    var ptr0 = isLikeNone(master_key) ? 0 : passStringToWasm0(master_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(self_signing_key) ? 0 : passStringToWasm0(self_signing_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(user_signing_key) ? 0 : passStringToWasm0(user_signing_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len2 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_importCrossSigningKeys(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
  }
  /**
   * Create a new cross signing identity and get the upload request
   * to push the new public keys to the server.
   *
   * Warning: This will delete any existing cross signing keys that
   * might exist on the server and thus will reset the trust
   * between all the devices.
   *
   * Uploading these keys will require user interactive auth.
   *
   * # Arguments
   *
   * * `reset`, whether the method should create a new identity or use the
   *   existing one during the request. If set to true, the request will
   *   attempt to upload a new identity. If set to false, the request will
   *   attempt to upload the existing identity. Since the uploading process
   *   requires user interactive authentication, which involves sending out
   *   the same request multiple times, setting this argument to false
   *   enables you to reuse the same request.
   *
   * Returns a {@link CrossSigningBootstrapRequests}.
   * @param {boolean} reset
   * @returns {Promise<any>}
   */
  bootstrapCrossSigning(reset) {
    const ret = wasm.olmmachine_bootstrapCrossSigning(this.__wbg_ptr, reset);
    return ret;
  }
  /**
   * Get the cross signing user identity of a user.
   *
   * Returns a promise for an {@link OwnUserIdentity}, a
   * {@link OtherUserIdentity}, or `undefined`.
   * @param {UserId} user_id
   * @returns {Promise<any>}
   */
  getIdentity(user_id) {
    _assertClass(user_id, UserId);
    const ret = wasm.olmmachine_getIdentity(this.__wbg_ptr, user_id.__wbg_ptr);
    return ret;
  }
  /**
   * Sign the given message using our device key and if available
   * cross-signing master key.
   * @param {string} message
   * @returns {Promise<any>}
   */
  sign(message) {
    const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_sign(this.__wbg_ptr, ptr0, len0);
    return ret;
  }
  /**
   * Invalidate the currently active outbound group session for the
   * given room.
   *
   * Returns true if a session was invalidated, false if there was
   * no session to invalidate.
   * @param {RoomId} room_id
   * @returns {Promise<any>}
   */
  invalidateGroupSession(room_id) {
    _assertClass(room_id, RoomId);
    const ret = wasm.olmmachine_invalidateGroupSession(this.__wbg_ptr, room_id.__wbg_ptr);
    return ret;
  }
  /**
   * Get to-device requests to share a room key with users in a room.
   *
   * `room_id` is the room ID. `users` is an array of `UserId`
   * objects. `encryption_settings` are an `EncryptionSettings`
   * object.
   *
   * Note: Care should be taken that only one such request at a
   * time is in flight for the same room, e.g. using a lock.
   *
   * Returns an array of `ToDeviceRequest`s.
   *
   * Items inside `users` will be invalidated by this method. Be careful not
   * to use the `UserId`s after this method has been called.
   * @param {RoomId} room_id
   * @param {UserId[]} users
   * @param {EncryptionSettings} encryption_settings
   * @returns {Promise<any>}
   */
  shareRoomKey(room_id, users, encryption_settings) {
    _assertClass(room_id, RoomId);
    const ptr0 = passArrayJsValueToWasm0(users, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(encryption_settings, EncryptionSettings);
    const ret = wasm.olmmachine_shareRoomKey(this.__wbg_ptr, room_id.__wbg_ptr, ptr0, len0, encryption_settings.__wbg_ptr);
    return ret;
  }
  /**
   * Generate an "out-of-band" key query request for the given set of users.
   *
   * This can be useful if we need the results from `getIdentity` or
   * `getUserDevices` to be as up-to-date as possible.
   *
   * Returns a `KeysQueryRequest` object. The response of the request should
   * be passed to the `OlmMachine` with the `mark_request_as_sent`.
   *
   * Items inside `users` will be invalidated by this method. Be careful not
   * to use the `UserId`s after this method has been called.
   * @param {UserId[]} users
   * @returns {KeysQueryRequest}
   */
  queryKeysForUsers(users) {
    const ptr0 = passArrayJsValueToWasm0(users, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_queryKeysForUsers(this.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return KeysQueryRequest.__wrap(ret[0]);
  }
  /**
   * Get the a key claiming request for the user/device pairs that
   * we are missing Olm sessions for.
   *
   * Returns `null` if no key claiming request needs to be sent
   * out, otherwise it returns a `KeysClaimRequest` object.
   *
   * Sessions need to be established between devices so group
   * sessions for a room can be shared with them.
   *
   * This should be called every time a group session needs to be
   * shared as well as between sync calls. After a sync some
   * devices may request room keys without us having a valid Olm
   * session with them, making it impossible to server the room key
   * request, thus it’s necessary to check for missing sessions
   * between sync as well.
   *
   * Note: Care should be taken that only one such request at a
   * time is in flight, e.g. using a lock.
   *
   * The response of a successful key claiming requests needs to be
   * passed to the `OlmMachine` with the `mark_request_as_sent`.
   *
   * `users` represents the list of users that we should check if
   * we lack a session with one of their devices. This can be an
   * empty iterator when calling this method between sync requests.
   *
   * Items inside `users` will be invalidated by this method. Be careful not
   * to use the `UserId`s after this method has been called.
   * @param {UserId[]} users
   * @returns {Promise<any>}
   */
  getMissingSessions(users) {
    const ptr0 = passArrayJsValueToWasm0(users, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_getMissingSessions(this.__wbg_ptr, ptr0, len0);
    return ret;
  }
  /**
   * Get a map holding all the devices of a user.
   *
   * ### Parameters
   *
   * * `user_id` - The unique ID of the user that the device belongs to.
   *
   * * `timeout_secs` - The amount of time we should wait for a `/keys/query`
   *   response before returning if the user's device list has been marked as
   *   stale. **Note**, this assumes that the requests from {@link
   *   OlmMachine.outgoingRequests} are being processed and sent out.
   *
   *   If unset, we will return immediately even if the device list is stale.
   *
   * ### Returns
   *
   * A {@link UserDevices} object.
   * @param {UserId} user_id
   * @param {number | null} [timeout_secs]
   * @returns {Promise<any>}
   */
  getUserDevices(user_id, timeout_secs) {
    _assertClass(user_id, UserId);
    const ret = wasm.olmmachine_getUserDevices(this.__wbg_ptr, user_id.__wbg_ptr, !isLikeNone(timeout_secs), isLikeNone(timeout_secs) ? 0 : timeout_secs);
    return ret;
  }
  /**
   * Get a specific device of a user.
   *
   * ### Parameters
   *
   * * `user_id` - The unique ID of the user that the device belongs to.
   *
   * * `device_id` - The unique ID of the device.
   *
   * * `timeout_secs` - The amount of time we should wait for a `/keys/query`
   *   response before returning if the user's device list has been marked as
   *   stale. **Note**, this assumes that the requests from {@link
   *   OlmMachine.outgoingRequests} are being processed and sent out.
   *
   *   If unset, we will return immediately even if the device list is stale.
   *
   * ### Returns
   *
   * If the device is known, a {@link Device}. Otherwise, `undefined`.
   * @param {UserId} user_id
   * @param {DeviceId} device_id
   * @param {number | null} [timeout_secs]
   * @returns {Promise<any>}
   */
  getDevice(user_id, device_id, timeout_secs) {
    _assertClass(user_id, UserId);
    _assertClass(device_id, DeviceId);
    const ret = wasm.olmmachine_getDevice(this.__wbg_ptr, user_id.__wbg_ptr, device_id.__wbg_ptr, !isLikeNone(timeout_secs), isLikeNone(timeout_secs) ? 0 : timeout_secs);
    return ret;
  }
  /**
   * Get a verification object for the given user ID with the given
   * flow ID (a to-device request ID if the verification has been
   * requested by a to-device request, or a room event ID if the
   * verification has been requested by a room event).
   *
   * It returns a “`Verification` object”, which is either a `Sas`
   * or `Qr` object.
   * @param {UserId} user_id
   * @param {string} flow_id
   * @returns {any}
   */
  getVerification(user_id, flow_id) {
    _assertClass(user_id, UserId);
    const ptr0 = passStringToWasm0(flow_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_getVerification(this.__wbg_ptr, user_id.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Get a verification request object with the given flow ID.
   * @param {UserId} user_id
   * @param {string} flow_id
   * @returns {VerificationRequest | undefined}
   */
  getVerificationRequest(user_id, flow_id) {
    _assertClass(user_id, UserId);
    const ptr0 = passStringToWasm0(flow_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_getVerificationRequest(this.__wbg_ptr, user_id.__wbg_ptr, ptr0, len0);
    return ret === 0 ? void 0 : VerificationRequest.__wrap(ret);
  }
  /**
   * Get all the verification requests of a given user.
   * @param {UserId} user_id
   * @returns {Array<any>}
   */
  getVerificationRequests(user_id) {
    _assertClass(user_id, UserId);
    const ret = wasm.olmmachine_getVerificationRequests(this.__wbg_ptr, user_id.__wbg_ptr);
    return ret;
  }
  /**
   * Receive a verification event.
   *
   * This method can be used to pass verification events that are happening
   * in rooms to the `OlmMachine`. The event should be in the decrypted form.
   * @param {string} event
   * @param {RoomId} room_id
   * @returns {Promise<any>}
   */
  receiveVerificationEvent(event, room_id) {
    const ptr0 = passStringToWasm0(event, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(room_id, RoomId);
    const ret = wasm.olmmachine_receiveVerificationEvent(this.__wbg_ptr, ptr0, len0, room_id.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Export the keys that match the given predicate.
   *
   * `predicate` is a closure that will be called for every known
   * `InboundGroupSession`, which represents a room key. If the closure
   * returns `true`, the `InboundGroupSession` will be included in the
   * export; otherwise it won't.
   *
   * Returns a Promise containing a Result containing a String which is a
   * JSON-encoded array of ExportedRoomKey objects.
   * @param {Function} predicate
   * @returns {Promise<any>}
   */
  exportRoomKeys(predicate) {
    const ret = wasm.olmmachine_exportRoomKeys(this.__wbg_ptr, predicate);
    return ret;
  }
  /**
   * Import the given room keys into our store.
   *
   * Mostly, a deprecated alias for `importExportedRoomKeys`, though the
   * return type is different.
   *
   * Returns a String containing a JSON-encoded object, holding three
   * properties:
   *  * `total_count` (the total number of keys found in the export data).
   *  * `imported_count` (the number of keys that were imported).
   *  * `keys` (the keys that were imported; a map from room id to a map of
   *    the sender key to a list of session ids).
   *
   * @deprecated Use `importExportedRoomKeys` or `importBackedUpRoomKeys`.
   * @param {string} exported_room_keys
   * @param {Function} progress_listener
   * @returns {Promise<any>}
   */
  importRoomKeys(exported_room_keys, progress_listener) {
    const ptr0 = passStringToWasm0(exported_room_keys, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_importRoomKeys(this.__wbg_ptr, ptr0, len0, progress_listener);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Import the given room keys into our store.
   *
   * `exported_keys` is a JSON-encoded list of previously exported keys that
   * should be imported into our store. If we already have a better
   * version of a key, the key will _not_ be imported.
   *
   * `progress_listener` is a closure that takes 2 `BigInt` arguments:
   * `progress` and `total`, and returns nothing.
   *
   * Returns a {@link RoomKeyImportResult}.
   * @param {string} exported_room_keys
   * @param {Function} progress_listener
   * @returns {Promise<any>}
   */
  importExportedRoomKeys(exported_room_keys, progress_listener) {
    const ptr0 = passStringToWasm0(exported_room_keys, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_importExportedRoomKeys(this.__wbg_ptr, ptr0, len0, progress_listener);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Import the given room keys into our store.
   *
   * # Arguments
   *
   * * `backed_up_room_keys`: keys that were retrieved from backup and that
   *   should be added to our store (provided they are better than our
   *   current versions of those keys). Specifically, it should be a Map from
   *   {@link RoomId}, to a Map from session ID to a (decrypted) session data
   *   structure.
   *
   * * `progress_listener`: an optional callback that takes 3 arguments:
   *   `progress` (the number of keys that have successfully been imported),
   *   `total` (the total number of keys), and `failures` (the number of keys
   *   that failed to import), and returns nothing.
   *
   * # Returns
   *
   * A {@link RoomKeyImportResult}.
   * @param {Map<any, any>} backed_up_room_keys
   * @param {Function | null | undefined} progress_listener
   * @param {string} backup_version
   * @returns {Promise<any>}
   */
  importBackedUpRoomKeys(backed_up_room_keys, progress_listener, backup_version) {
    const ptr0 = passStringToWasm0(backup_version, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_importBackedUpRoomKeys(this.__wbg_ptr, backed_up_room_keys, isLikeNone(progress_listener) ? 0 : addToExternrefTable0(progress_listener), ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Store the backup decryption key in the crypto store.
   *
   * This is useful if the client wants to support gossiping of the backup
   * key.
   *
   * Returns `Promise<void>`.
   * @param {BackupDecryptionKey} decryption_key
   * @param {string} version
   * @returns {Promise<any>}
   */
  saveBackupDecryptionKey(decryption_key, version) {
    _assertClass(decryption_key, BackupDecryptionKey);
    const ptr0 = passStringToWasm0(version, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_saveBackupDecryptionKey(this.__wbg_ptr, decryption_key.__wbg_ptr, ptr0, len0);
    return ret;
  }
  /**
   * Get the backup keys we have saved in our store.
   * Returns a `Promise` for {@link BackupKeys}.
   * @returns {Promise<any>}
   */
  getBackupKeys() {
    const ret = wasm.olmmachine_getBackupKeys(this.__wbg_ptr);
    return ret;
  }
  /**
   * Check if the given backup has been verified by us or by another of our
   * devices that we trust.
   *
   * The `backup_info` should be a Javascript object with the following
   * format:
   *
   * ```json
   * {
   *     "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
   *     "auth_data": {
   *         "public_key":"XjhWTCjW7l59pbfx9tlCBQolfnIQWARoKOzjTOPSlWM",
   *         "signatures": {}
   *     }
   * }
   * ```
   *
   * Returns a {@link SignatureVerification} object.
   * @param {any} backup_info
   * @returns {Promise<any>}
   */
  verifyBackup(backup_info) {
    const ret = wasm.olmmachine_verifyBackup(this.__wbg_ptr, backup_info);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Activate the given backup key to be used with the given backup version.
   *
   * **Warning**: The caller needs to make sure that the given `BackupKey` is
   * trusted, otherwise we might be encrypting room keys that a malicious
   * party could decrypt.
   *
   * The {@link verifyBackup} method can be used to do so.
   *
   * Returns `Promise<void>`.
   * @param {string} public_key_base_64
   * @param {string} version
   * @returns {Promise<any>}
   */
  enableBackupV1(public_key_base_64, version) {
    const ptr0 = passStringToWasm0(public_key_base_64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(version, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_enableBackupV1(this.__wbg_ptr, ptr0, len0, ptr1, len1);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Are we able to encrypt room keys.
   *
   * This returns true if we have an active `BackupKey` and backup version
   * registered with the state machine.
   *
   * Returns `Promise<bool>`.
   * @returns {Promise<any>}
   */
  isBackupEnabled() {
    const ret = wasm.olmmachine_isBackupEnabled(this.__wbg_ptr);
    return ret;
  }
  /**
   * Disable and reset our backup state.
   *
   * This will remove any pending backup request, remove the backup key and
   * reset the backup state of each room key we have.
   *
   * Returns `Promise<void>`.
   * @returns {Promise<any>}
   */
  disableBackup() {
    const ret = wasm.olmmachine_disableBackup(this.__wbg_ptr);
    return ret;
  }
  /**
   * Encrypt a batch of room keys and return a request that needs to be sent
   * out to backup the room keys.
   *
   * Returns an optional {@link KeysBackupRequest}.
   * @returns {Promise<any>}
   */
  backupRoomKeys() {
    const ret = wasm.olmmachine_backupRoomKeys(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the number of backed up room keys and the total number of room keys.
   * Returns a {@link RoomKeyCounts}.
   * @returns {Promise<any>}
   */
  roomKeyCounts() {
    const ret = wasm.olmmachine_roomKeyCounts(this.__wbg_ptr);
    return ret;
  }
  /**
   * Encrypt the list of exported room keys using the given passphrase.
   *
   * `exported_room_keys` is a list of sessions that should be encrypted
   * (it's generally returned by `export_room_keys`). `passphrase` is the
   * passphrase that will be used to encrypt the exported room keys. And
   * `rounds` is the number of rounds that should be used for the key
   * derivation when the passphrase gets turned into an AES key. More rounds
   * are increasingly computationnally intensive and as such help against
   * brute-force attacks. Should be at least `10_000`, while values in the
   * `100_000` ranges should be preferred.
   * @param {string} exported_room_keys
   * @param {string} passphrase
   * @param {number} rounds
   * @returns {string}
   */
  static encryptExportedRoomKeys(exported_room_keys, passphrase, rounds) {
    let deferred4_0;
    let deferred4_1;
    try {
      const ptr0 = passStringToWasm0(exported_room_keys, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len0 = WASM_VECTOR_LEN;
      const ptr1 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len1 = WASM_VECTOR_LEN;
      const ret = wasm.olmmachine_encryptExportedRoomKeys(ptr0, len0, ptr1, len1, rounds);
      var ptr3 = ret[0];
      var len3 = ret[1];
      if (ret[3]) {
        ptr3 = 0;
        len3 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred4_0 = ptr3;
      deferred4_1 = len3;
      return getStringFromWasm0(ptr3, len3);
    } finally {
      wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
  }
  /**
   * Try to decrypt a reader into a list of exported room keys.
   *
   * `encrypted_exported_room_keys` is the result from
   * `encrypt_exported_room_keys`. `passphrase` is the passphrase that was
   * used when calling `encrypt_exported_room_keys`.
   * @param {string} encrypted_exported_room_keys
   * @param {string} passphrase
   * @returns {string}
   */
  static decryptExportedRoomKeys(encrypted_exported_room_keys, passphrase) {
    let deferred4_0;
    let deferred4_1;
    try {
      const ptr0 = passStringToWasm0(encrypted_exported_room_keys, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len0 = WASM_VECTOR_LEN;
      const ptr1 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len1 = WASM_VECTOR_LEN;
      const ret = wasm.olmmachine_decryptExportedRoomKeys(ptr0, len0, ptr1, len1);
      var ptr3 = ret[0];
      var len3 = ret[1];
      if (ret[3]) {
        ptr3 = 0;
        len3 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred4_0 = ptr3;
      deferred4_1 = len3;
      return getStringFromWasm0(ptr3, len3);
    } finally {
      wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
  }
  /**
   * Register a callback which will be called whenever there is an update to
   * a room key.
   *
   * `callback` should be a function that takes a single argument (an array
   * of {@link RoomKeyInfo}) and returns a Promise.
   * @param {Function} callback
   * @returns {Promise<void>}
   */
  registerRoomKeyUpdatedCallback(callback) {
    const ret = wasm.olmmachine_registerRoomKeyUpdatedCallback(this.__wbg_ptr, callback);
    return ret;
  }
  /**
   * Register a callback which will be called whenever we receive a
   * notification that some room keys have been withheld.
   *
   * `callback` should be a function that takes a single argument (an array
   * of {@link RoomKeyWithheldInfo}) and returns a Promise.
   * @param {Function} callback
   * @returns {Promise<void>}
   */
  registerRoomKeysWithheldCallback(callback) {
    const ret = wasm.olmmachine_registerRoomKeysWithheldCallback(this.__wbg_ptr, callback);
    return ret;
  }
  /**
   * Register a callback which will be called whenever there is an update to
   * a user identity.
   *
   * `callback` should be a function that takes a single argument (a {@link
   * UserId}) and returns a Promise.
   * @param {Function} callback
   * @returns {Promise<void>}
   */
  registerUserIdentityUpdatedCallback(callback) {
    const ret = wasm.olmmachine_registerUserIdentityUpdatedCallback(this.__wbg_ptr, callback);
    return ret;
  }
  /**
   * Register a callback which will be called whenever there is an update to
   * a device.
   *
   * `callback` should be a function that takes a single argument (an array
   * of user IDs as strings) and returns a Promise.
   * @param {Function} callback
   * @returns {Promise<void>}
   */
  registerDevicesUpdatedCallback(callback) {
    const ret = wasm.olmmachine_registerDevicesUpdatedCallback(this.__wbg_ptr, callback);
    return ret;
  }
  /**
   * Register a callback which will be called whenever a secret
   * (`m.secret.send`) is received.
   *
   * The only secret this will currently broadcast is the
   * `m.megolm_backup.v1` (the cross signing secrets are handled internally).
   *
   * To request a secret from other devices, a client sends an
   * `m.secret.request` device event with `action` set to `request` and
   * `name` set to the identifier of the secret. A device that wishes to
   * share the secret will reply with an `m.secret.send` event, encrypted
   * using olm.
   *
   * The secrets are guaranteed to have been received over a 1-to-1 encrypted
   * to_device message from a one of the user's own verified devices.
   *
   * See https://matrix-org.github.io/matrix-rust-sdk/matrix_sdk_crypto/store/struct.Store.html#method.secrets_stream for more information.
   *
   * `callback` should be a function that takes 2 arguments: the secret name
   * (string) and value (string).
   *
   * **Note**: if the secret is valid and handled on the javascript side, the
   * secret inbox should be cleared by calling
   * `delete_secrets_from_inbox`.
   * @param {Function} callback
   * @returns {Promise<void>}
   */
  registerReceiveSecretCallback(callback) {
    const ret = wasm.olmmachine_registerReceiveSecretCallback(this.__wbg_ptr, callback);
    return ret;
  }
  /**
   * Get all the secrets with the given secret_name we have currently
   * stored.
   * The only secret this will currently return is the
   * `m.megolm_backup.v1` secret.
   *
   * Usually you would just register a callback with
   * [`register_receive_secret_callback`], but if the client is shut down
   * before handling them, this method can be used to retrieve them.
   * This method should therefore be called at client startup to retrieve any
   * secrets received during the previous session.
   *
   * The secrets are guaranteed to have been received over a 1-to-1 encrypted
   * to_device message from one of the user's own verified devices.
   *
   * Returns a `Promise` for a `Set` of `String` corresponding to the secret
   * values.
   *
   * If the secret is valid and handled, the secret inbox should be cleared
   * by calling `delete_secrets_from_inbox`.
   * @param {string} secret_name
   * @returns {Promise<Promise<any>>}
   */
  getSecretsFromInbox(secret_name) {
    const ptr0 = passStringToWasm0(secret_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_getSecretsFromInbox(this.__wbg_ptr, ptr0, len0);
    return ret;
  }
  /**
   * Delete all secrets with the given secret name from the inbox.
   *
   * Should be called after handling the secrets with
   * `get_secrets_from_inbox`.
   *
   * # Arguments
   *
   * * `secret_name` - The name of the secret to delete.
   * @param {string} secret_name
   * @returns {Promise<Promise<any>>}
   */
  deleteSecretsFromInbox(secret_name) {
    const ptr0 = passStringToWasm0(secret_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.olmmachine_deleteSecretsFromInbox(this.__wbg_ptr, ptr0, len0);
    return ret;
  }
  /**
   * Request missing local secrets from our other trusted devices.
   *
   * "Local secrets" refers to secrets which can be shared between trusted
   * devices, such as private cross-signing keys, and the megolm backup
   * decryption key.
   *
   * This method will cause the sdk to generated outgoing secret requests
   * (`m.secret.request`) to get the missing secrets. These requests will
   * then be returned by a future call to {@link
   * OlmMachine#outgoingRequests}.
   *
   * # Returns
   *
   * A `Promise` for a `bool` result, which will be true if  secrets were
   * missing, and a request was generated.
   * @returns {Promise<Promise<any>>}
   */
  requestMissingSecretsIfNeeded() {
    const ret = wasm.olmmachine_requestMissingSecretsIfNeeded(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the stored room settings, such as the encryption algorithm or
   * whether to encrypt only for trusted devices.
   *
   * These settings can be modified via {@link setRoomSettings}.
   *
   * # Returns
   *
   * `Promise<RoomSettings|undefined>`
   * @param {RoomId} room_id
   * @returns {Promise<any>}
   */
  getRoomSettings(room_id) {
    _assertClass(room_id, RoomId);
    const ret = wasm.olmmachine_getRoomSettings(this.__wbg_ptr, room_id.__wbg_ptr);
    return ret;
  }
  /**
   * Store encryption settings for the given room.
   *
   * This method checks if the new settings are "safe" -- ie, that they do
   * not represent a downgrade in encryption security from any previous
   * settings. Attempts to downgrade security will result in an error.
   *
   * If the settings are valid, they will be persisted to the crypto store.
   * These settings are not used directly by this library, but the saved
   * settings can be retrieved via {@link getRoomSettings}.
   * @param {RoomId} room_id
   * @param {RoomSettings} room_settings
   * @returns {Promise<void>}
   */
  setRoomSettings(room_id, room_settings) {
    _assertClass(room_id, RoomId);
    _assertClass(room_settings, RoomSettings);
    const ret = wasm.olmmachine_setRoomSettings(this.__wbg_ptr, room_id.__wbg_ptr, room_settings.__wbg_ptr);
    return ret;
  }
  /**
   * Manage dehydrated devices
   * @returns {DehydratedDevices}
   */
  dehydratedDevices() {
    const ret = wasm.olmmachine_dehydratedDevices(this.__wbg_ptr);
    return DehydratedDevices.__wrap(ret);
  }
  /**
   * Shut down the `OlmMachine`.
   *
   * The `OlmMachine` cannot be used after this method has been called.
   *
   * All associated resources will be closed too, like IndexedDB
   * connections.
   */
  close() {
    const ptr = this.__destroy_into_raw();
    wasm.olmmachine_close(ptr);
  }
}
const OtherUserIdentityFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_otheruseridentity_free(ptr >>> 0, 1));
class OtherUserIdentity {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(OtherUserIdentity.prototype);
    obj.__wbg_ptr = ptr;
    OtherUserIdentityFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    OtherUserIdentityFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_otheruseridentity_free(ptr, 0);
  }
  /**
   * Is this user identity verified?
   * @returns {boolean}
   */
  isVerified() {
    const ret = wasm.otheruseridentity_isVerified(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Manually verify this user.
   *
   * This method will attempt to sign the user identity using our private
   * cross signing key.
   *
   * This method fails if we don't have the private part of our user-signing
   * key.
   *
   * Returns a request that needs to be sent out for the user to be marked as
   * verified.
   * @returns {Promise<any>}
   */
  verify() {
    const ret = wasm.otheruseridentity_verify(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a `VerificationRequest` object after the verification
   * request content has been sent out.
   * @param {RoomId} room_id
   * @param {EventId} request_event_id
   * @param {any[] | null} [methods]
   * @returns {VerificationRequest}
   */
  requestVerification(room_id, request_event_id, methods) {
    _assertClass(room_id, RoomId);
    _assertClass(request_event_id, EventId);
    var ptr0 = isLikeNone(methods) ? 0 : passArrayJsValueToWasm0(methods, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    const ret = wasm.otheruseridentity_requestVerification(this.__wbg_ptr, room_id.__wbg_ptr, request_event_id.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return VerificationRequest.__wrap(ret[0]);
  }
  /**
   * Send a verification request to the given user.
   *
   * The returned content needs to be sent out into a DM room with the given
   * user.
   *
   * After the content has been sent out a VerificationRequest can be started
   * with the `request_verification` method.
   * @param {any[] | null} [methods]
   * @returns {string}
   */
  verificationRequestContent(methods) {
    let deferred3_0;
    let deferred3_1;
    try {
      var ptr0 = isLikeNone(methods) ? 0 : passArrayJsValueToWasm0(methods, wasm.__wbindgen_malloc);
      var len0 = WASM_VECTOR_LEN;
      const ret = wasm.otheruseridentity_verificationRequestContent(this.__wbg_ptr, ptr0, len0);
      var ptr2 = ret[0];
      var len2 = ret[1];
      if (ret[3]) {
        ptr2 = 0;
        len2 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred3_0 = ptr2;
      deferred3_1 = len2;
      return getStringFromWasm0(ptr2, len2);
    } finally {
      wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
  }
  /**
   * Get the master key of the identity.
   * @returns {string}
   */
  get masterKey() {
    let deferred2_0;
    let deferred2_1;
    try {
      const ret = wasm.otheruseridentity_masterKey(this.__wbg_ptr);
      var ptr1 = ret[0];
      var len1 = ret[1];
      if (ret[3]) {
        ptr1 = 0;
        len1 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred2_0 = ptr1;
      deferred2_1 = len1;
      return getStringFromWasm0(ptr1, len1);
    } finally {
      wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
  }
  /**
   * Get the self-signing key of the identity.
   * @returns {string}
   */
  get selfSigningKey() {
    let deferred2_0;
    let deferred2_1;
    try {
      const ret = wasm.otheruseridentity_selfSigningKey(this.__wbg_ptr);
      var ptr1 = ret[0];
      var len1 = ret[1];
      if (ret[3]) {
        ptr1 = 0;
        len1 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred2_0 = ptr1;
      deferred2_1 = len1;
      return getStringFromWasm0(ptr1, len1);
    } finally {
      wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
  }
  /**
   * Pin the current identity (public part of the master signing key).
   * @returns {Promise<any>}
   */
  pinCurrentMasterKey() {
    const ret = wasm.otheruseridentity_pinCurrentMasterKey(this.__wbg_ptr);
    return ret;
  }
  /**
   * Has the identity changed in a way that requires approval from the user?
   *
   * A user identity needs approval if it changed after the crypto machine
   * has already observed ("pinned") a different identity for that user,
   * unless it is an explicitly verified identity (using for example
   * interactive verification).
   *
   * This situation can be resolved by:
   *
   * - Verifying the new identity with {@link requestVerification}, or:
   * - Updating the pin to the new identity with {@link pinCurrentMasterKey}.
   * @returns {boolean}
   */
  identityNeedsUserApproval() {
    const ret = wasm.otheruseridentity_identityNeedsUserApproval(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * True if we verified this identity (with any own identity, at any
   * point).
   *
   * To set this latch back to false, call {@link withdrawVerification}.
   * @returns {boolean}
   */
  wasPreviouslyVerified() {
    const ret = wasm.otheruseridentity_wasPreviouslyVerified(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Remove the requirement for this identity to be verified.
   *
   * If an identity was previously verified and is not anymore it will be
   * reported to the user. In order to remove this notice users have to
   * verify again or to withdraw the verification requirement.
   * @returns {Promise<any>}
   */
  withdrawVerification() {
    const ret = wasm.otheruseridentity_withdrawVerification(this.__wbg_ptr);
    return ret;
  }
  /**
   * Was this identity verified since initial observation and is not anymore?
   *
   * Such a violation should be reported to the local user by the
   * application, and resolved by
   *
   * - Verifying the new identity with {@link requestVerification}, or:
   * - Withdrawing the verification requirement with {@link
   *   withdrawVerification}.
   * @returns {boolean}
   */
  hasVerificationViolation() {
    const ret = wasm.otheruseridentity_hasVerificationViolation(this.__wbg_ptr);
    return ret !== 0;
  }
}
const OutboundCreationResultFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_outboundcreationresult_free(ptr >>> 0, 1));
class OutboundCreationResult {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(OutboundCreationResult.prototype);
    obj.__wbg_ptr = ptr;
    OutboundCreationResultFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    OutboundCreationResultFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_outboundcreationresult_free(ptr, 0);
  }
  /**
   * The established ECIES channel.
   * @returns {EstablishedEcies}
   */
  get channel() {
    const ret = wasm.__wbg_get_inboundcreationresult_channel(this.__wbg_ptr);
    return EstablishedEcies.__wrap(ret);
  }
  /**
   * The established ECIES channel.
   * @param {EstablishedEcies} arg0
   */
  set channel(arg0) {
    _assertClass(arg0, EstablishedEcies);
    var ptr0 = arg0.__destroy_into_raw();
    wasm.__wbg_set_inboundcreationresult_channel(this.__wbg_ptr, ptr0);
  }
  /**
   * The initial encrypted message.
   * @returns {string}
   */
  get initial_message() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_outboundcreationresult_initial_message(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The initial encrypted message.
   * @param {string} arg0
   */
  set initial_message(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_key(this.__wbg_ptr, ptr0, len0);
  }
}
const OwnUserIdentityFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_ownuseridentity_free(ptr >>> 0, 1));
class OwnUserIdentity {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(OwnUserIdentity.prototype);
    obj.__wbg_ptr = ptr;
    OwnUserIdentityFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    OwnUserIdentityFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_ownuseridentity_free(ptr, 0);
  }
  /**
   * Is this user identity verified?
   * @returns {boolean}
   */
  isVerified() {
    const ret = wasm.ownuseridentity_isVerified(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Mark our user identity as verified.
   *
   * This will mark the identity locally as verified and sign it with our own
   * device.
   *
   * Returns a signature upload request that needs to be sent out.
   * @returns {Promise<any>}
   */
  verify() {
    const ret = wasm.ownuseridentity_verify(this.__wbg_ptr);
    return ret;
  }
  /**
   * Send a verification request to our other devices.
   * @param {any[] | null} [methods]
   * @returns {Promise<any>}
   */
  requestVerification(methods) {
    var ptr0 = isLikeNone(methods) ? 0 : passArrayJsValueToWasm0(methods, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    const ret = wasm.ownuseridentity_requestVerification(this.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Does our user identity trust our own device, i.e. have we signed our own
   * device keys with our self-signing key?
   * @returns {Promise<any>}
   */
  trustsOurOwnDevice() {
    const ret = wasm.ownuseridentity_trustsOurOwnDevice(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the master key of the identity.
   * @returns {string}
   */
  get masterKey() {
    let deferred2_0;
    let deferred2_1;
    try {
      const ret = wasm.ownuseridentity_masterKey(this.__wbg_ptr);
      var ptr1 = ret[0];
      var len1 = ret[1];
      if (ret[3]) {
        ptr1 = 0;
        len1 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred2_0 = ptr1;
      deferred2_1 = len1;
      return getStringFromWasm0(ptr1, len1);
    } finally {
      wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
  }
  /**
   * Get the self-signing key of the identity.
   * @returns {string}
   */
  get selfSigningKey() {
    let deferred2_0;
    let deferred2_1;
    try {
      const ret = wasm.ownuseridentity_selfSigningKey(this.__wbg_ptr);
      var ptr1 = ret[0];
      var len1 = ret[1];
      if (ret[3]) {
        ptr1 = 0;
        len1 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred2_0 = ptr1;
      deferred2_1 = len1;
      return getStringFromWasm0(ptr1, len1);
    } finally {
      wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
  }
  /**
   * Get the user-signing key of the identity. This is only present for our
   * own user identity.
   * @returns {string}
   */
  get userSigningKey() {
    let deferred2_0;
    let deferred2_1;
    try {
      const ret = wasm.ownuseridentity_userSigningKey(this.__wbg_ptr);
      var ptr1 = ret[0];
      var len1 = ret[1];
      if (ret[3]) {
        ptr1 = 0;
        len1 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred2_0 = ptr1;
      deferred2_1 = len1;
      return getStringFromWasm0(ptr1, len1);
    } finally {
      wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
  }
  /**
   * True if we verified our own identity at some point in the past.
   *
   * To reset this latch back to `false`, call {@link withdrawVerification}.
   * @returns {boolean}
   */
  wasPreviouslyVerified() {
    const ret = wasm.ownuseridentity_wasPreviouslyVerified(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Remove the requirement for this identity to be verified.
   *
   * If an identity was previously verified and is not any longer, it will be
   * reported to the user. In order to remove this notice users have to
   * verify again or to withdraw the verification requirement.
   * @returns {Promise<any>}
   */
  withdrawVerification() {
    const ret = wasm.ownuseridentity_withdrawVerification(this.__wbg_ptr);
    return ret;
  }
  /**
   * Was this identity verified since initial observation and is not anymore?
   *
   * Such a violation should be reported to the local user by the
   * application, and resolved by
   *
   * - Verifying the new identity with {@link requestVerification}, or:
   * - Withdrawing the verification requirement with {@link
   *   withdrawVerification}.
   * @returns {boolean}
   */
  hasVerificationViolation() {
    const ret = wasm.ownuseridentity_hasVerificationViolation(this.__wbg_ptr);
    return ret !== 0;
  }
}
const PickledInboundGroupSessionFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_pickledinboundgroupsession_free(ptr >>> 0, 1));
class PickledInboundGroupSession {
  static __unwrap(jsValue) {
    if (!(jsValue instanceof PickledInboundGroupSession)) {
      return 0;
    }
    return jsValue.__destroy_into_raw();
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    PickledInboundGroupSessionFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_pickledinboundgroupsession_free(ptr, 0);
  }
  /**
   * The pickle string holding the Megolm Session, as returned by
   * `olm_pickle_inbound_group_session` in libolm.
   * @returns {string}
   */
  get pickle() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_pickledinboundgroupsession_pickle(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The pickle string holding the Megolm Session, as returned by
   * `olm_pickle_inbound_group_session` in libolm.
   * @param {string} arg0
   */
  set pickle(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_key(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The public curve25519 key of the account that sent us the session.
   * @returns {string}
   */
  get senderKey() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_pickledinboundgroupsession_senderKey(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The public curve25519 key of the account that sent us the session.
   * @param {string} arg0
   */
  set senderKey(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_backup_version(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The public ed25519 key of the account that is believed to have initiated
   * the session, if known.
   *
   * If the session was received directly from the creator via an
   * Olm-encrypted `m.room_key` event, this value is taken from the `keys`
   * property of the plaintext payload of that event (see
   * [`m.olm.v1.curve25519-aes-sha2`]).
   *
   * If the session was forwarded to us using an [`m.forwarded_room_key`],
   * this value is a copy of the `sender_claimed_ed25519_key` from the
   * content of the event.
   *
   * [`m.olm.v1.curve25519-aes-sha2`]: https://spec.matrix.org/v1.9/client-server-api/#molmv1curve25519-aes-sha2
   * [`m.forwarded_room_key`]: https://spec.matrix.org/v1.9/client-server-api/#mforwarded_room_key
   * @returns {string | undefined}
   */
  get senderSigningKey() {
    const ret = wasm.__wbg_get_pickledinboundgroupsession_senderSigningKey(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * The public ed25519 key of the account that is believed to have initiated
   * the session, if known.
   *
   * If the session was received directly from the creator via an
   * Olm-encrypted `m.room_key` event, this value is taken from the `keys`
   * property of the plaintext payload of that event (see
   * [`m.olm.v1.curve25519-aes-sha2`]).
   *
   * If the session was forwarded to us using an [`m.forwarded_room_key`],
   * this value is a copy of the `sender_claimed_ed25519_key` from the
   * content of the event.
   *
   * [`m.olm.v1.curve25519-aes-sha2`]: https://spec.matrix.org/v1.9/client-server-api/#molmv1curve25519-aes-sha2
   * [`m.forwarded_room_key`]: https://spec.matrix.org/v1.9/client-server-api/#mforwarded_room_key
   * @param {string | null} [arg0]
   */
  set senderSigningKey(arg0) {
    var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_basemigrationdata_backupRecoveryKey(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The id of the room that the session is used in.
   *
   * Nullable so that a `PickledInboundGroupSession` can be constructed
   * incrementally. Must be populated!
   * @returns {RoomId | undefined}
   */
  get roomId() {
    const ret = wasm.__wbg_get_pickledinboundgroupsession_roomId(this.__wbg_ptr);
    return ret === 0 ? void 0 : RoomId.__wrap(ret);
  }
  /**
   * The id of the room that the session is used in.
   *
   * Nullable so that a `PickledInboundGroupSession` can be constructed
   * incrementally. Must be populated!
   * @param {RoomId | null} [arg0]
   */
  set roomId(arg0) {
    let ptr0 = 0;
    if (!isLikeNone(arg0)) {
      _assertClass(arg0, RoomId);
      ptr0 = arg0.__destroy_into_raw();
    }
    wasm.__wbg_set_pickledinboundgroupsession_roomId(this.__wbg_ptr, ptr0);
  }
  /**
   * Flag remembering if the session was directly sent to us by the sender
   * or if it was imported.
   * @returns {boolean}
   */
  get imported() {
    const ret = wasm.__wbg_get_pickledinboundgroupsession_imported(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Flag remembering if the session was directly sent to us by the sender
   * or if it was imported.
   * @param {boolean} arg0
   */
  set imported(arg0) {
    wasm.__wbg_set_pickledinboundgroupsession_imported(this.__wbg_ptr, arg0);
  }
  /**
   * Flag remembering if the session has been backed up.
   * @returns {boolean}
   */
  get backedUp() {
    const ret = wasm.__wbg_get_pickledinboundgroupsession_backedUp(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Flag remembering if the session has been backed up.
   * @param {boolean} arg0
   */
  set backedUp(arg0) {
    wasm.__wbg_set_pickledinboundgroupsession_backedUp(this.__wbg_ptr, arg0);
  }
  /**
   * Construct a new `PickledInboundGroupSession`, with default values.
   */
  constructor() {
    const ret = wasm.pickledinboundgroupsession_new();
    this.__wbg_ptr = ret >>> 0;
    PickledInboundGroupSessionFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
}
const PickledSessionFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_pickledsession_free(ptr >>> 0, 1));
class PickledSession {
  static __unwrap(jsValue) {
    if (!(jsValue instanceof PickledSession)) {
      return 0;
    }
    return jsValue.__destroy_into_raw();
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    PickledSessionFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_pickledsession_free(ptr, 0);
  }
  /**
   * The pickle string holding the Olm Session, as returned by
   * `olm_pickle_session` in libolm.
   * @returns {string}
   */
  get pickle() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_pickledsession_pickle(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The pickle string holding the Olm Session, as returned by
   * `olm_pickle_session` in libolm.
   * @param {string} arg0
   */
  set pickle(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_key(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * The base64-encoded public curve25519 key of the other user that we share
   * this session with.
   * @returns {string}
   */
  get senderKey() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.__wbg_get_pickledsession_senderKey(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The base64-encoded public curve25519 key of the other user that we share
   * this session with.
   * @param {string} arg0
   */
  set senderKey(arg0) {
    const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.__wbg_set_backupsecretsbundle_backup_version(this.__wbg_ptr, ptr0, len0);
  }
  /**
   * Was the session created using a fallback key?
   * @returns {boolean}
   */
  get createdUsingFallbackKey() {
    const ret = wasm.__wbg_get_pickledsession_createdUsingFallbackKey(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Was the session created using a fallback key?
   * @param {boolean} arg0
   */
  set createdUsingFallbackKey(arg0) {
    wasm.__wbg_set_pickledsession_createdUsingFallbackKey(this.__wbg_ptr, arg0);
  }
  /**
   * When the session was created.
   * @returns {Date}
   */
  get creationTime() {
    const ret = wasm.__wbg_get_pickledsession_creationTime(this.__wbg_ptr);
    return ret;
  }
  /**
   * When the session was created.
   * @param {Date} arg0
   */
  set creationTime(arg0) {
    wasm.__wbg_set_pickledsession_creationTime(this.__wbg_ptr, arg0);
  }
  /**
   * When the session was last used.
   * @returns {Date}
   */
  get lastUseTime() {
    const ret = wasm.__wbg_get_pickledsession_lastUseTime(this.__wbg_ptr);
    return ret;
  }
  /**
   * When the session was last used.
   * @param {Date} arg0
   */
  set lastUseTime(arg0) {
    wasm.__wbg_set_pickledsession_lastUseTime(this.__wbg_ptr, arg0);
  }
  /**
   * Construct a new `PickledSession`, with default values.
   */
  constructor() {
    const ret = wasm.pickledsession_new();
    this.__wbg_ptr = ret >>> 0;
    PickledSessionFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
}
const PkDecryptionFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_pkdecryption_free(ptr >>> 0, 1));
class PkDecryption {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(PkDecryption.prototype);
    obj.__wbg_ptr = ptr;
    PkDecryptionFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    PkDecryptionFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_pkdecryption_free(ptr, 0);
  }
  /**
   * Creates a new `PkDecryption` instance with a newly generated key pair.
   */
  constructor() {
    const ret = wasm.pkdecryption_new();
    this.__wbg_ptr = ret >>> 0;
    PkDecryptionFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Creates a `PkDecryption` instance from a secret key.
   * @param {Curve25519SecretKey} key
   * @returns {PkDecryption}
   */
  static fromKey(key) {
    _assertClass(key, Curve25519SecretKey);
    const ret = wasm.pkdecryption_fromKey(key.__wbg_ptr);
    return PkDecryption.__wrap(ret);
  }
  /**
   * Returns the secret key associated with this `PkDecryption` instance.
   * @returns {Curve25519SecretKey}
   */
  secretKey() {
    const ret = wasm.pkdecryption_secretKey(this.__wbg_ptr);
    return Curve25519SecretKey.__wrap(ret);
  }
  /**
   * Returns the public key associated with this decryption instance.
   *
   * This can be used to construct a {@link PkEncryption} object to encrypt a
   * message for this `PkDecryption` object.
   * @returns {Curve25519PublicKey}
   */
  publicKey() {
    const ret = wasm.pkdecryption_publicKey(this.__wbg_ptr);
    return Curve25519PublicKey.__wrap(ret);
  }
  /**
   * Decrypts an encrypted message and returns the plaintext as a UTF-8
   * string.
   * @param {PkMessage} message
   * @returns {string}
   */
  decryptString(message) {
    let deferred2_0;
    let deferred2_1;
    try {
      _assertClass(message, PkMessage);
      const ret = wasm.pkdecryption_decryptString(this.__wbg_ptr, message.__wbg_ptr);
      var ptr1 = ret[0];
      var len1 = ret[1];
      if (ret[3]) {
        ptr1 = 0;
        len1 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred2_0 = ptr1;
      deferred2_1 = len1;
      return getStringFromWasm0(ptr1, len1);
    } finally {
      wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
  }
  /**
   * Decrypts an encrypted message and returns the raw `Uint8Array`.
   * @param {PkMessage} message
   * @returns {Uint8Array}
   */
  decrypt(message) {
    _assertClass(message, PkMessage);
    const ret = wasm.pkdecryption_decrypt(this.__wbg_ptr, message.__wbg_ptr);
    if (ret[3]) {
      throw takeFromExternrefTable0(ret[2]);
    }
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
  }
}
const PkEncryptionFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_pkencryption_free(ptr >>> 0, 1));
class PkEncryption {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(PkEncryption.prototype);
    obj.__wbg_ptr = ptr;
    PkEncryptionFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    PkEncryptionFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_pkencryption_free(ptr, 0);
  }
  /**
   * Creates a new `PkEncryption` instance from a public key.
   * @param {Curve25519PublicKey} public_key
   * @returns {PkEncryption}
   */
  static fromKey(public_key) {
    _assertClass(public_key, Curve25519PublicKey);
    const ret = wasm.pkencryption_fromKey(public_key.__wbg_ptr);
    return PkEncryption.__wrap(ret);
  }
  /**
   * Encrypts a byte message and returns an encrypted {@link PkMessage}.
   * @param {Uint8Array} message
   * @returns {PkMessage}
   */
  encrypt(message) {
    const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.pkencryption_encrypt(this.__wbg_ptr, ptr0, len0);
    return PkMessage.__wrap(ret);
  }
  /**
   * Encrypts a string message and returns an encrypted {@link PkMessage}.
   * @param {string} message
   * @returns {PkMessage}
   */
  encryptString(message) {
    const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.pkencryption_encrypt(this.__wbg_ptr, ptr0, len0);
    return PkMessage.__wrap(ret);
  }
}
const PkMessageFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_pkmessage_free(ptr >>> 0, 1));
class PkMessage {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(PkMessage.prototype);
    obj.__wbg_ptr = ptr;
    PkMessageFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    PkMessageFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_pkmessage_free(ptr, 0);
  }
  /**
   * Returns the raw ciphertext as a `Uint8Array`.
   * @returns {Uint8Array}
   */
  ciphertext() {
    const ret = wasm.pkmessage_ciphertext(this.__wbg_ptr);
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
  }
  /**
   * Returns the raw message authentication code (MAC) as a `Uint8Array`.
   * @returns {Uint8Array}
   */
  mac() {
    const ret = wasm.pkmessage_mac(this.__wbg_ptr);
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
  }
  /**
   * Returns the ephemeral public key used during encryption.
   * @returns {Curve25519PublicKey}
   */
  ephemeralKey() {
    const ret = wasm.pkmessage_ephemeralKey(this.__wbg_ptr);
    return Curve25519PublicKey.__wrap(ret);
  }
  /**
   * Constructs a `PkMessage` from its parts: ciphertext, MAC, and ephemeral
   * key.
   * @param {Uint8Array} ciphertext
   * @param {Uint8Array} mac
   * @param {Curve25519PublicKey} ephemeral_key
   * @returns {PkMessage}
   */
  static fromParts(ciphertext, mac, ephemeral_key) {
    const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(mac, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    _assertClass(ephemeral_key, Curve25519PublicKey);
    const ret = wasm.pkmessage_fromParts(ptr0, len0, ptr1, len1, ephemeral_key.__wbg_ptr);
    return PkMessage.__wrap(ret);
  }
  /**
   * Constructs a `PkMessage` from a base64-encoded representation.
   * @param {Base64EncodedPkMessage} message
   * @returns {PkMessage}
   */
  static fromBase64(message) {
    _assertClass(message, Base64EncodedPkMessage);
    const ret = wasm.pkmessage_fromBase64(message.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return PkMessage.__wrap(ret[0]);
  }
  /**
   * Converts the `PkMessage` into a base64-encoded representation.
   * @returns {Base64EncodedPkMessage}
   */
  toBase64() {
    const ret = wasm.pkmessage_toBase64(this.__wbg_ptr);
    return Base64EncodedPkMessage.__wrap(ret);
  }
}
const PutDehydratedDeviceRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_putdehydrateddevicerequest_free(ptr >>> 0, 1));
class PutDehydratedDeviceRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(PutDehydratedDeviceRequest.prototype);
    obj.__wbg_ptr = ptr;
    PutDehydratedDeviceRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    PutDehydratedDeviceRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_putdehydrateddevicerequest_free(ptr, 0);
  }
  /**
   * A JSON-encoded string containing the rest of the payload: `rooms`.
   *
   * It represents the body of the HTTP request.
   * @returns {string}
   */
  get body() {
    const ret = wasm.__wbg_get_putdehydrateddevicerequest_body(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a new `PutDehydratedDeviceRequest`
   * @param {string} body
   */
  constructor(body) {
    const ret = wasm.putdehydrateddevicerequest_new(body);
    this.__wbg_ptr = ret >>> 0;
    PutDehydratedDeviceRequestFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
}
const QrFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_qr_free(ptr >>> 0, 1));
class Qr {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Qr.prototype);
    obj.__wbg_ptr = ptr;
    QrFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    QrFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_qr_free(ptr, 0);
  }
  /**
   * Get the current state of this request.
   *
   * Returns a `QrState`.
   * @returns {QrState}
   */
  state() {
    const ret = wasm.qr_state(this.__wbg_ptr);
    return ret;
  }
  /**
   * Has the QR verification been scanned by the other side.
   *
   * When the verification object is in this state it’s required
   * that the user confirms that the other side has scanned the QR
   * code.
   * @returns {boolean}
   */
  hasBeenScanned() {
    const ret = wasm.qr_hasBeenScanned(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Has the scanning of the QR code been confirmed by us?
   * @returns {boolean}
   */
  hasBeenConfirmed() {
    const ret = wasm.qr_hasBeenConfirmed(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Get our own user ID.
   * @returns {UserId}
   */
  get userId() {
    const ret = wasm.qr_userId(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * Get the user id of the other user that is participating in
   * this verification flow.
   * @returns {UserId}
   */
  get otherUserId() {
    const ret = wasm.qr_otherUserId(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * Get the device ID of the other side.
   * @returns {DeviceId}
   */
  get otherDeviceId() {
    const ret = wasm.qr_otherDeviceId(this.__wbg_ptr);
    return DeviceId.__wrap(ret);
  }
  /**
   * Did we initiate the verification request?
   * @returns {boolean}
   */
  weStarted() {
    const ret = wasm.qr_weStarted(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Get info about the cancellation if the verification flow has
   * been cancelled.
   * @returns {CancelInfo | undefined}
   */
  cancelInfo() {
    const ret = wasm.qr_cancelInfo(this.__wbg_ptr);
    return ret === 0 ? void 0 : CancelInfo.__wrap(ret);
  }
  /**
   * Has the verification flow completed?
   * @returns {boolean}
   */
  isDone() {
    const ret = wasm.qr_isDone(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Has the verification flow been cancelled?
   * @returns {boolean}
   */
  isCancelled() {
    const ret = wasm.qr_isCancelled(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Is this a verification that is verifying one of our own devices?
   * @returns {boolean}
   */
  isSelfVerification() {
    const ret = wasm.qr_isSelfVerification(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Have we successfully scanned the QR code and are able to send
   * a reciprocation event?
   * @returns {boolean}
   */
  reciprocated() {
    const ret = wasm.qr_reciprocated(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Get the unique ID that identifies this QR verification flow,
   * be either a to-device request ID or a room event ID.
   * @returns {string}
   */
  get flowId() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.qr_flowId(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Get the room id if the verification is happening inside a
   * room.
   * @returns {RoomId | undefined}
   */
  get roomId() {
    const ret = wasm.qr_roomId(this.__wbg_ptr);
    return ret === 0 ? void 0 : RoomId.__wrap(ret);
  }
  /**
   * Generate a QR code object that is representing this
   * verification flow.
   *
   * The QrCode can then be rendered as an image or as an unicode
   * string.
   *
   * The `to_bytes` method can be used to instead output the raw
   * bytes that should be encoded as a QR code.
   *
   * Returns a `QrCode`.
   * @returns {QrCode}
   */
  toQrCode() {
    const ret = wasm.qr_toQrCode(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return QrCode.__wrap(ret[0]);
  }
  /**
   * Generate a the raw bytes that should be encoded as a QR code
   * is representing this verification flow.
   *
   * The `to_qr_code` method can be used to instead output a QrCode
   * object that can be rendered.
   * @returns {Uint8ClampedArray}
   */
  toBytes() {
    const ret = wasm.qr_toBytes(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Notify the other side that we have successfully scanned the QR
   * code and that the QR verification flow can start.
   *
   * This will return some OutgoingContent if the object is in the
   * correct state to start the verification flow, otherwise None.
   * @returns {any}
   */
  reciprocate() {
    const ret = wasm.qr_reciprocate(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Confirm that the other side has scanned our QR code.
   *
   * Returns either an `OutgoingRequest` which should be sent out, or
   * `undefined` if the verification is already confirmed.
   * @returns {any}
   */
  confirmScanning() {
    const ret = wasm.qr_confirmScanning(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Cancel the verification flow.
   *
   * Returns either an `OutgoingRequest` which should be sent out, or
   * `undefined` if the verification is already cancelled.
   * @returns {any}
   */
  cancel() {
    const ret = wasm.qr_cancel(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Cancel the verification.
   *
   * This cancels the verification with given code (e.g. `m.user`).
   *
   * Returns either an `OutgoingRequest` which should be sent out, or
   * `undefined` if the verification is already cancelled.
   * @param {string} code
   * @returns {any}
   */
  cancelWithCode(code) {
    const ptr0 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.qr_cancelWithCode(this.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Register a callback which will be called whenever there is an update to
   * the request
   *
   * The `callback` is called with no parameters.
   * @param {Function} callback
   */
  registerChangesCallback(callback) {
    wasm.qr_registerChangesCallback(this.__wbg_ptr, callback);
  }
}
const QrCodeFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_qrcode_free(ptr >>> 0, 1));
class QrCode {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(QrCode.prototype);
    obj.__wbg_ptr = ptr;
    QrCodeFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    QrCodeFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_qrcode_free(ptr, 0);
  }
  /**
   * Render the QR code into a `Uint8ClampedArray` where 1 represents a
   * dark pixel and 0 a white pixel.
   * @returns {Uint8ClampedArray}
   */
  renderIntoBuffer() {
    const ret = wasm.qrcode_renderIntoBuffer(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
}
const QrCodeDataFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_qrcodedata_free(ptr >>> 0, 1));
class QrCodeData {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(QrCodeData.prototype);
    obj.__wbg_ptr = ptr;
    QrCodeDataFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    QrCodeDataFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_qrcodedata_free(ptr, 0);
  }
  /**
   * Create new {@link QrCodeData} from a given public key, a rendezvous URL
   * and, optionally, a server name for the homeserver.
   *
   * If a server name is given, then the {@link QrCodeData} mode will be
   * {@link QrCodeMode.Reciprocate}, i.e. the QR code will contain data for
   * the existing device to display the QR code.
   *
   * If no server name is given, the {@link QrCodeData} mode will be
   * {@link QrCodeMode.Login}, i.e. the QR code will contain data for the
   * new device to display the QR code.
   * @param {Curve25519PublicKey} public_key
   * @param {string} rendezvous_url
   * @param {string | null} [server_name]
   */
  constructor(public_key, rendezvous_url, server_name) {
    _assertClass(public_key, Curve25519PublicKey);
    var ptr0 = public_key.__destroy_into_raw();
    const ptr1 = passStringToWasm0(rendezvous_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(server_name) ? 0 : passStringToWasm0(server_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len2 = WASM_VECTOR_LEN;
    const ret = wasm.qrcodedata_new(ptr0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    QrCodeDataFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Attempt to decode a slice of bytes into a {@link QrCodeData} object.
   *
   * The slice of bytes would generally be returned by a QR code decoder.
   * @param {Uint8Array} bytes
   * @returns {QrCodeData}
   */
  static fromBytes(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.qrcodedata_fromBytes(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return QrCodeData.__wrap(ret[0]);
  }
  /**
   * Encode the {@link QrCodeData} into a list of bytes.
   *
   * The list of bytes can be used by a QR code generator to create an image
   * containing a QR code.
   * @returns {Uint8Array}
   */
  toBytes() {
    const ret = wasm.qrcodedata_toBytes(this.__wbg_ptr);
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
  }
  /**
   * Attempt to decode a base64 encoded string into a {@link QrCodeData}
   * object.
   * @param {string} data
   * @returns {QrCodeData}
   */
  static fromBase64(data) {
    const ptr0 = passStringToWasm0(data, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.qrcodedata_fromBase64(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return QrCodeData.__wrap(ret[0]);
  }
  /**
   * Encode the {@link QrCodeData} into a string using base64.
   *
   * This format can be used for debugging purposes and the
   * [`QrcodeData::from_base64()`] method can be used to parse the string
   * again.
   * @returns {string}
   */
  toBase64() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.qrcodedata_toBase64(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Get the Curve25519 public key embedded in the {@link QrCodeData}.
   *
   * This Curve25519 public key should be used to establish an
   * [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)
   * (Elliptic Curve Integrated Encryption Scheme) channel with the other
   * device.
   * @returns {Curve25519PublicKey}
   */
  get publicKey() {
    const ret = wasm.qrcodedata_publicKey(this.__wbg_ptr);
    return Curve25519PublicKey.__wrap(ret);
  }
  /**
   * Get the URL of the rendezvous server which will be used to exchange
   * messages between the two devices.
   * @returns {string}
   */
  get rendezvousUrl() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.qrcodedata_rendezvousUrl(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Get the server name of the homeserver which the new device will be
   * logged in to.
   *
   * This will be only available if the existing device has generated the QR
   * code and the new device is the one scanning the QR code.
   * @returns {string | undefined}
   */
  get serverName() {
    const ret = wasm.qrcodedata_serverName(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * Get the mode of this {@link QrCodeData} instance.
   * @returns {QrCodeMode}
   */
  get mode() {
    const ret = wasm.qrcodedata_mode(this.__wbg_ptr);
    return ret;
  }
}
const QrCodeScanFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_qrcodescan_free(ptr >>> 0, 1));
class QrCodeScan {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(QrCodeScan.prototype);
    obj.__wbg_ptr = ptr;
    QrCodeScanFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    QrCodeScanFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_qrcodescan_free(ptr, 0);
  }
  /**
   * Parse the decoded payload of a QR code in byte slice form.
   *
   * This method is useful if you would like to do your own custom QR code
   * decoding.
   * @param {Uint8ClampedArray} buffer
   * @returns {QrCodeScan}
   */
  static fromBytes(buffer) {
    const ret = wasm.qrcodescan_fromBytes(buffer);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return QrCodeScan.__wrap(ret[0]);
  }
}
const RehydratedDeviceFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_rehydrateddevice_free(ptr >>> 0, 1));
class RehydratedDevice {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(RehydratedDevice.prototype);
    obj.__wbg_ptr = ptr;
    RehydratedDeviceFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    RehydratedDeviceFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_rehydrateddevice_free(ptr, 0);
  }
  /**
   * Receive the to-device events that sent to the dehydrated device
   *
   * The rehydrated device will decrypt the events and pass the room keys
   * into the `OlmMachine`.
   *
   * `to_device_events` is a JSON-encoded result of the `events` array from
   * `/dehydrated_device/{device_id}/events`.
   *
   * Returns an array of `RoomKeyInfo`, indicating the room keys that were
   * received.
   * @param {string} to_device_events
   * @returns {Promise<Array<any>>}
   */
  receiveEvents(to_device_events) {
    const ptr0 = passStringToWasm0(to_device_events, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.rehydrateddevice_receiveEvents(this.__wbg_ptr, ptr0, len0);
    return ret;
  }
}
const RoomIdFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_roomid_free(ptr >>> 0, 1));
class RoomId {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(RoomId.prototype);
    obj.__wbg_ptr = ptr;
    RoomIdFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  static __unwrap(jsValue) {
    if (!(jsValue instanceof RoomId)) {
      return 0;
    }
    return jsValue.__destroy_into_raw();
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    RoomIdFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_roomid_free(ptr, 0);
  }
  /**
   * Parse/validate and create a new `RoomId`.
   * @param {string} id
   */
  constructor(id) {
    const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.roomid_new(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    RoomIdFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Return the room ID as a string.
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.roomid_toString(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const RoomKeyCountsFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_roomkeycounts_free(ptr >>> 0, 1));
class RoomKeyCounts {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(RoomKeyCounts.prototype);
    obj.__wbg_ptr = ptr;
    RoomKeyCountsFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    RoomKeyCountsFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_roomkeycounts_free(ptr, 0);
  }
  /**
   * The total number of room keys.
   * @returns {number}
   */
  get total() {
    const ret = wasm.__wbg_get_roomkeycounts_total(this.__wbg_ptr);
    return ret;
  }
  /**
   * The total number of room keys.
   * @param {number} arg0
   */
  set total(arg0) {
    wasm.__wbg_set_roomkeycounts_total(this.__wbg_ptr, arg0);
  }
  /**
   * The number of backed up room keys.
   * @returns {number}
   */
  get backedUp() {
    const ret = wasm.__wbg_get_roomkeycounts_backedUp(this.__wbg_ptr);
    return ret;
  }
  /**
   * The number of backed up room keys.
   * @param {number} arg0
   */
  set backedUp(arg0) {
    wasm.__wbg_set_roomkeycounts_backedUp(this.__wbg_ptr, arg0);
  }
}
const RoomKeyImportResultFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_roomkeyimportresult_free(ptr >>> 0, 1));
class RoomKeyImportResult {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(RoomKeyImportResult.prototype);
    obj.__wbg_ptr = ptr;
    RoomKeyImportResultFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    RoomKeyImportResultFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_roomkeyimportresult_free(ptr, 0);
  }
  /**
   * The number of room keys that were imported.
   * @returns {number}
   */
  get importedCount() {
    const ret = wasm.__wbg_get_roomkeyimportresult_importedCount(this.__wbg_ptr);
    return ret >>> 0;
  }
  /**
   * The total number of room keys that were found in the export.
   * @returns {number}
   */
  get totalCount() {
    const ret = wasm.__wbg_get_roomkeyimportresult_totalCount(this.__wbg_ptr);
    return ret >>> 0;
  }
  /**
   * The keys that were imported.
   *
   * A Map from room id to a Map of the sender key to a Set of session ids.
   *
   * Typescript type: `Map<string, Map<string, Set<string>>`.
   * @returns {Map<any, any>}
   */
  keys() {
    const ret = wasm.roomkeyimportresult_keys(this.__wbg_ptr);
    return ret;
  }
}
const RoomKeyInfoFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_roomkeyinfo_free(ptr >>> 0, 1));
class RoomKeyInfo {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(RoomKeyInfo.prototype);
    obj.__wbg_ptr = ptr;
    RoomKeyInfoFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    RoomKeyInfoFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_roomkeyinfo_free(ptr, 0);
  }
  /**
   * The {@link EncryptionAlgorithm} that this key is used for. Will be one
   * of the `m.megolm.*` algorithms.
   * @returns {EncryptionAlgorithm}
   */
  get algorithm() {
    const ret = wasm.roomkeyinfo_algorithm(this.__wbg_ptr);
    return ret;
  }
  /**
   * The room where the key is used.
   * @returns {RoomId}
   */
  get roomId() {
    const ret = wasm.roomkeyinfo_roomId(this.__wbg_ptr);
    return RoomId.__wrap(ret);
  }
  /**
   * The Curve25519 key of the device which initiated the session originally.
   * @returns {Curve25519PublicKey}
   */
  get senderKey() {
    const ret = wasm.roomkeyinfo_senderKey(this.__wbg_ptr);
    return Curve25519PublicKey.__wrap(ret);
  }
  /**
   * The ID of the session that the key is for.
   * @returns {string}
   */
  get sessionId() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.roomkeyinfo_sessionId(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const RoomKeyWithheldInfoFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_roomkeywithheldinfo_free(ptr >>> 0, 1));
class RoomKeyWithheldInfo {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(RoomKeyWithheldInfo.prototype);
    obj.__wbg_ptr = ptr;
    RoomKeyWithheldInfoFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    RoomKeyWithheldInfoFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_roomkeywithheldinfo_free(ptr, 0);
  }
  /**
   * The User ID of the user that sent us the `m.room_key.withheld` message.
   * @returns {UserId}
   */
  get sender() {
    const ret = wasm.roomkeywithheldinfo_sender(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * The encryption algorithm of the session that is being withheld.
   * @returns {EncryptionAlgorithm}
   */
  get algorithm() {
    const ret = wasm.roomkeywithheldinfo_algorithm(this.__wbg_ptr);
    return ret;
  }
  /**
   * The `code` from the `m.room_key.withheld` message, such as
   * `m.unverified`.
   * @returns {string}
   */
  get withheldCode() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.roomkeywithheldinfo_withheldCode(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The room ID of the session that is being withheld.
   * @returns {RoomId}
   */
  get roomId() {
    const ret = wasm.roomkeywithheldinfo_roomId(this.__wbg_ptr);
    return RoomId.__wrap(ret);
  }
  /**
   * The session ID of the session that is being withheld.
   * @returns {string}
   */
  get sessionId() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.roomkeywithheldinfo_sessionId(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const RoomMessageRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_roommessagerequest_free(ptr >>> 0, 1));
class RoomMessageRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(RoomMessageRequest.prototype);
    obj.__wbg_ptr = ptr;
    RoomMessageRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    RoomMessageRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_roommessagerequest_free(ptr, 0);
  }
  /**
   * The request ID.
   * @returns {string}
   */
  get id() {
    const ret = wasm.__wbg_get_roommessagerequest_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A string representing the room to send the event to.
   * @returns {string}
   */
  get room_id() {
    const ret = wasm.__wbg_get_roommessagerequest_room_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A string representing the transaction ID for this event.
   *
   * Clients should generate an ID unique across requests with the same
   * access token; it will be used by the server to ensure idempotency of
   * requests.
   * @returns {string}
   */
  get txn_id() {
    const ret = wasm.__wbg_get_roommessagerequest_txn_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A string representing the type of event to be sent.
   * @returns {string}
   */
  get event_type() {
    const ret = wasm.__wbg_get_roommessagerequest_event_type(this.__wbg_ptr);
    return ret;
  }
  /**
   * A JSON-encoded string containing the message's content.
   * @returns {string}
   */
  get body() {
    const ret = wasm.__wbg_get_roommessagerequest_body(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a new `RoomMessageRequest`.
   * @param {string} id
   * @param {string} room_id
   * @param {string} txn_id
   * @param {string} event_type
   * @param {string} content
   */
  constructor(id, room_id, txn_id, event_type, content) {
    const ret = wasm.roommessagerequest_new(id, room_id, txn_id, event_type, content);
    this.__wbg_ptr = ret >>> 0;
    RoomMessageRequestFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Get its request type.
   * @returns {RequestType}
   */
  get type() {
    const ret = wasm.roommessagerequest_type(this.__wbg_ptr);
    return ret;
  }
}
const RoomSettingsFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_roomsettings_free(ptr >>> 0, 1));
class RoomSettings {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(RoomSettings.prototype);
    obj.__wbg_ptr = ptr;
    RoomSettingsFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    RoomSettingsFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_roomsettings_free(ptr, 0);
  }
  /**
   * The encryption algorithm that should be used in the room.
   *
   * Should be one of the members of {@link EncryptionAlgorithm}.
   * @returns {EncryptionAlgorithm}
   */
  get algorithm() {
    const ret = wasm.__wbg_get_roomsettings_algorithm(this.__wbg_ptr);
    return ret;
  }
  /**
   * The encryption algorithm that should be used in the room.
   *
   * Should be one of the members of {@link EncryptionAlgorithm}.
   * @param {EncryptionAlgorithm} arg0
   */
  set algorithm(arg0) {
    wasm.__wbg_set_roomsettings_algorithm(this.__wbg_ptr, arg0);
  }
  /**
   * Whether untrusted devices should receive room keys. If this is `false`,
   * they will be excluded from the conversation.
   * @returns {boolean}
   */
  get onlyAllowTrustedDevices() {
    const ret = wasm.__wbg_get_roomsettings_onlyAllowTrustedDevices(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Whether untrusted devices should receive room keys. If this is `false`,
   * they will be excluded from the conversation.
   * @param {boolean} arg0
   */
  set onlyAllowTrustedDevices(arg0) {
    wasm.__wbg_set_roomsettings_onlyAllowTrustedDevices(this.__wbg_ptr, arg0);
  }
  /**
   * The maximum time, in milliseconds, that an encryption session should be
   * used for, before it is rotated.
   * @returns {number | undefined}
   */
  get sessionRotationPeriodMs() {
    const ret = wasm.__wbg_get_roomsettings_sessionRotationPeriodMs(this.__wbg_ptr);
    return ret[0] === 0 ? void 0 : ret[1];
  }
  /**
   * The maximum time, in milliseconds, that an encryption session should be
   * used for, before it is rotated.
   * @param {number | null} [arg0]
   */
  set sessionRotationPeriodMs(arg0) {
    wasm.__wbg_set_roomsettings_sessionRotationPeriodMs(this.__wbg_ptr, !isLikeNone(arg0), isLikeNone(arg0) ? 0 : arg0);
  }
  /**
   * The maximum number of messages an encryption session should be used for,
   * before it is rotated.
   * @returns {number | undefined}
   */
  get sessionRotationPeriodMessages() {
    const ret = wasm.__wbg_get_roomsettings_sessionRotationPeriodMessages(this.__wbg_ptr);
    return ret[0] === 0 ? void 0 : ret[1];
  }
  /**
   * The maximum number of messages an encryption session should be used for,
   * before it is rotated.
   * @param {number | null} [arg0]
   */
  set sessionRotationPeriodMessages(arg0) {
    wasm.__wbg_set_roomsettings_sessionRotationPeriodMessages(this.__wbg_ptr, !isLikeNone(arg0), isLikeNone(arg0) ? 0 : arg0);
  }
  /**
   * Create a new `RoomSettings` with default values.
   */
  constructor() {
    const ret = wasm.roomsettings_new();
    this.__wbg_ptr = ret >>> 0;
    RoomSettingsFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
}
const SasFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_sas_free(ptr >>> 0, 1));
class Sas {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Sas.prototype);
    obj.__wbg_ptr = ptr;
    SasFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    SasFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_sas_free(ptr, 0);
  }
  /**
   * Get our own user ID.
   * @returns {UserId}
   */
  get userId() {
    const ret = wasm.sas_userId(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * Get our own device ID.
   * @returns {DeviceId}
   */
  get deviceId() {
    const ret = wasm.sas_deviceId(this.__wbg_ptr);
    return DeviceId.__wrap(ret);
  }
  /**
   * Get the user id of the other side.
   * @returns {UserId}
   */
  get otherUserId() {
    const ret = wasm.sas_otherUserId(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * Get the device ID of the other side.
   * @returns {DeviceId}
   */
  get otherDeviceId() {
    const ret = wasm.sas_otherDeviceId(this.__wbg_ptr);
    return DeviceId.__wrap(ret);
  }
  /**
   * Get the unique ID that identifies this SAS verification flow,
   * be either a to-device request ID or a room event ID.
   * @returns {string}
   */
  get flowId() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.sas_flowId(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Get the room ID if the verification is happening inside a
   * room.
   * @returns {RoomId | undefined}
   */
  get roomId() {
    const ret = wasm.sas_roomId(this.__wbg_ptr);
    return ret === 0 ? void 0 : RoomId.__wrap(ret);
  }
  /**
   * Does this verification flow support displaying emoji for the
   * short authentication string?
   * @returns {boolean}
   */
  supportsEmoji() {
    const ret = wasm.sas_supportsEmoji(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Did this verification flow start from a verification request?
   * @returns {boolean}
   */
  startedFromRequest() {
    const ret = wasm.sas_startedFromRequest(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Is this a verification that is verifying one of our own
   * devices?
   * @returns {boolean}
   */
  isSelfVerification() {
    const ret = wasm.sas_isSelfVerification(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Have we confirmed that the short auth string matches?
   * @returns {boolean}
   */
  haveWeConfirmed() {
    const ret = wasm.sas_haveWeConfirmed(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Has the verification been accepted by both parties?
   * @returns {boolean}
   */
  hasBeenAccepted() {
    const ret = wasm.sas_hasBeenAccepted(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Get info about the cancellation if the verification flow has
   * been cancelled.
   * @returns {CancelInfo | undefined}
   */
  cancelInfo() {
    const ret = wasm.sas_cancelInfo(this.__wbg_ptr);
    return ret === 0 ? void 0 : CancelInfo.__wrap(ret);
  }
  /**
   * True if we initiated the verification flow (ie, we sent the
   * `m.key.verification.request`).
   * @returns {boolean}
   */
  weStarted() {
    const ret = wasm.sas_weStarted(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Accept the SAS verification.
   *
   * This does nothing (and returns `undefined`) if the verification was
   * already accepted, otherwise it returns an `OutgoingRequest`
   * that needs to be sent out.
   * @returns {any}
   */
  accept() {
    const ret = wasm.sas_accept(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Confirm the SAS verification.
   *
   * This confirms that the short auth strings match on both sides.
   *
   * Does nothing if we’re not in a state where we can confirm the
   * short auth string.
   *
   * Returns a `Promise` for an array of `OutgoingRequest`s.
   * @returns {Promise<any>}
   */
  confirm() {
    const ret = wasm.sas_confirm(this.__wbg_ptr);
    return ret;
  }
  /**
   * Cancel the verification.
   *
   * Returns either an `OutgoingRequest` which should be sent out, or
   * `undefined` if the verification is already cancelled.
   * @returns {any}
   */
  cancel() {
    const ret = wasm.sas_cancel(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Cancel the verification.
   *
   * This cancels the verification with given code (e.g. `m.user`).
   *
   * Returns either an `OutgoingRequest` which should be sent out, or
   * `undefined` if the verification is already cancelled.
   * @param {string} code
   * @returns {any}
   */
  cancelWithCode(code) {
    const ptr0 = passStringToWasm0(code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sas_cancelWithCode(this.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Has the SAS verification flow timed out?
   * @returns {boolean}
   */
  timedOut() {
    const ret = wasm.sas_timedOut(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Are we in a state where we can show the short auth string?
   * @returns {boolean}
   */
  canBePresented() {
    const ret = wasm.sas_canBePresented(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Is the SAS flow done?
   * @returns {boolean}
   */
  isDone() {
    const ret = wasm.sas_isDone(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Is the SAS flow cancelled?
   * @returns {boolean}
   */
  isCancelled() {
    const ret = wasm.sas_isCancelled(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Get the emoji version of the short auth string.
   *
   * Returns `undefined` if we can't yet present the short auth string,
   * otherwise an array of seven `Emoji` objects.
   * @returns {Emoji[] | undefined}
   */
  emoji() {
    const ret = wasm.sas_emoji(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
    }
    return v1;
  }
  /**
   * Get the index of the emoji representing the short auth string
   *
   * Returns `undefined` if we can’t yet present the short auth
   * string, otherwise seven `u8` numbers in the range from 0 to 63
   * inclusive which can be converted to an emoji using [the
   * relevant specification
   * entry](https://spec.matrix.org/unstable/client-server-api/#sas-method-emoji).
   * @returns {Uint8Array | undefined}
   */
  emojiIndex() {
    const ret = wasm.sas_emojiIndex(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
  /**
   * Get the decimal version of the short auth string.
   *
   * Returns None if we can’t yet present the short auth string,
   * otherwise a tuple containing three 4-digit integers that
   * represent the short auth string.
   * @returns {Uint16Array | undefined}
   */
  decimals() {
    const ret = wasm.sas_decimals(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getArrayU16FromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 2, 2);
    }
    return v1;
  }
  /**
   * Register a callback which will be called whenever there is an update to
   * the request.
   *
   * The `callback` is called with no parameters.
   * @param {Function} callback
   */
  registerChangesCallback(callback) {
    wasm.sas_registerChangesCallback(this.__wbg_ptr, callback);
  }
}
const SecretsBundleFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_secretsbundle_free(ptr >>> 0, 1));
class SecretsBundle {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(SecretsBundle.prototype);
    obj.__wbg_ptr = ptr;
    SecretsBundleFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    SecretsBundleFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_secretsbundle_free(ptr, 0);
  }
  /**
   * The seed of the master key encoded as unpadded base64.
   * @returns {string}
   */
  get masterKey() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.secretsbundle_masterKey(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The seed of the self signing key encoded as unpadded base64.
   * @returns {string}
   */
  get selfSigningKey() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.secretsbundle_selfSigningKey(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The seed of the user signing key encoded as unpadded base64.
   * @returns {string}
   */
  get userSigningKey() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.secretsbundle_userSigningKey(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * The bundle of the backup decryption key and backup version if any.
   * @returns {BackupSecretsBundle | undefined}
   */
  get backupBundle() {
    const ret = wasm.secretsbundle_backupBundle(this.__wbg_ptr);
    return ret === 0 ? void 0 : BackupSecretsBundle.__wrap(ret);
  }
  /**
   * Serialize the [`SecretsBundle`] to a JSON object.
   * @returns {any}
   */
  to_json() {
    const ret = wasm.secretsbundle_to_json(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Deserialize the [`SecretsBundle`] from a JSON object.
   * @param {any} json
   * @returns {SecretsBundle}
   */
  static from_json(json) {
    const ret = wasm.secretsbundle_from_json(json);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return SecretsBundle.__wrap(ret[0]);
  }
}
const ServerNameFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_servername_free(ptr >>> 0, 1));
class ServerName {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(ServerName.prototype);
    obj.__wbg_ptr = ptr;
    ServerNameFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    ServerNameFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_servername_free(ptr, 0);
  }
  /**
   * Parse/validate and create a new `ServerName`.
   * @param {string} name
   */
  constructor(name) {
    const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.servername_new(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    ServerNameFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Returns the host of the server name.
   *
   * That is: Return the part of the server before `:<port>` or the
   * full server name if there is no port.
   * @returns {string}
   */
  get host() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.servername_host(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Returns the port of the server name if any.
   * @returns {number | undefined}
   */
  get port() {
    const ret = wasm.servername_port(this.__wbg_ptr);
    return ret === 16777215 ? void 0 : ret;
  }
  /**
   * Returns true if and only if the server name is an IPv4 or IPv6
   * address.
   * @returns {boolean}
   */
  isIpLiteral() {
    const ret = wasm.servername_isIpLiteral(this.__wbg_ptr);
    return ret !== 0;
  }
}
const ShieldStateFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_shieldstate_free(ptr >>> 0, 1));
class ShieldState {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(ShieldState.prototype);
    obj.__wbg_ptr = ptr;
    ShieldStateFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    ShieldStateFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_shieldstate_free(ptr, 0);
  }
  /**
   * The shield color
   * @returns {ShieldColor}
   */
  get color() {
    const ret = wasm.__wbg_get_shieldstate_color(this.__wbg_ptr);
    return ret;
  }
  /**
   * The shield color
   * @param {ShieldColor} arg0
   */
  set color(arg0) {
    wasm.__wbg_set_shieldstate_color(this.__wbg_ptr, arg0);
  }
  /**
   * A machine-readable representation of the authenticity for a
   * `ShieldState`.
   * @returns {ShieldStateCode | undefined}
   */
  get code() {
    const ret = wasm.__wbg_get_shieldstate_code(this.__wbg_ptr);
    return ret === 6 ? void 0 : ret;
  }
  /**
   * A machine-readable representation of the authenticity for a
   * `ShieldState`.
   * @param {ShieldStateCode | null} [arg0]
   */
  set code(arg0) {
    wasm.__wbg_set_shieldstate_code(this.__wbg_ptr, isLikeNone(arg0) ? 6 : arg0);
  }
  /**
   * Error message that can be displayed as a tooltip
   * @returns {string | undefined}
   */
  get message() {
    const ret = wasm.shieldstate_message(this.__wbg_ptr);
    let v1;
    if (ret[0] !== 0) {
      v1 = getStringFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v1;
  }
}
const SignatureFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_signature_free(ptr >>> 0, 1));
class Signature {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Signature.prototype);
    obj.__wbg_ptr = ptr;
    SignatureFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    SignatureFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_signature_free(ptr, 0);
  }
  /**
   * Get the Ed25519 signature, if this is one.
   * @returns {Ed25519Signature | undefined}
   */
  get ed25519() {
    const ret = wasm.signature_ed25519(this.__wbg_ptr);
    return ret === 0 ? void 0 : Ed25519Signature.__wrap(ret);
  }
  /**
   * Convert the signature to a base64 encoded string.
   * @returns {string}
   */
  toBase64() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.signature_toBase64(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
const SignatureUploadRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_signatureuploadrequest_free(ptr >>> 0, 1));
class SignatureUploadRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(SignatureUploadRequest.prototype);
    obj.__wbg_ptr = ptr;
    SignatureUploadRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    SignatureUploadRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_signatureuploadrequest_free(ptr, 0);
  }
  /**
   * The request ID.
   * Some signature upload will have to an `id` field, some won't.
   * They have one when they are created automatically during an interactive
   * verification, otherwise they don't.
   * @returns {string | undefined}
   */
  get id() {
    const ret = wasm.__wbg_get_signatureuploadrequest_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A JSON-encoded string containing the payload of the request
   *
   * It represents the body of the HTTP request.
   * @returns {string}
   */
  get body() {
    const ret = wasm.__wbg_get_signatureuploadrequest_body(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a new `SignatureUploadRequest`.
   * @param {string} id
   * @param {string} signed_keys
   */
  constructor(id, signed_keys) {
    const ret = wasm.signatureuploadrequest_new(id, signed_keys);
    this.__wbg_ptr = ret >>> 0;
    SignatureUploadRequestFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Get its request type.
   * @returns {RequestType}
   */
  get type() {
    const ret = wasm.signatureuploadrequest_type(this.__wbg_ptr);
    return ret;
  }
}
const SignatureVerificationFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_signatureverification_free(ptr >>> 0, 1));
class SignatureVerification {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(SignatureVerification.prototype);
    obj.__wbg_ptr = ptr;
    SignatureVerificationFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    SignatureVerificationFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_signatureverification_free(ptr, 0);
  }
  /**
   * Give the backup signature state from the current device.
   * See SignatureState for values
   * @returns {SignatureState}
   */
  get deviceState() {
    const ret = wasm.signatureverification_deviceState(this.__wbg_ptr);
    return ret;
  }
  /**
   * Give the backup signature state from the current user identity.
   * See SignatureState for values
   * @returns {SignatureState}
   */
  get userState() {
    const ret = wasm.signatureverification_userState(this.__wbg_ptr);
    return ret;
  }
  /**
   * Is the result considered to be trusted?
   *
   * This tells us if the result has a valid signature from any of the
   * following:
   *
   * * Our own device
   * * Our own user identity, provided the identity is trusted as well
   * * Any of our own devices, provided the device is trusted as well
   * @returns {boolean}
   */
  trusted() {
    const ret = wasm.signatureverification_trusted(this.__wbg_ptr);
    return ret !== 0;
  }
}
const SignaturesFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_signatures_free(ptr >>> 0, 1));
class Signatures {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Signatures.prototype);
    obj.__wbg_ptr = ptr;
    SignaturesFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    SignaturesFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_signatures_free(ptr, 0);
  }
  /**
   * Creates a new, empty, signatures collection.
   */
  constructor() {
    const ret = wasm.signatures_new();
    this.__wbg_ptr = ret >>> 0;
    SignaturesFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Add the given signature from the given signer and the given key ID to
   * the collection.
   * @param {UserId} signer
   * @param {DeviceKeyId} key_id
   * @param {Ed25519Signature} signature
   * @returns {MaybeSignature | undefined}
   */
  addSignature(signer, key_id, signature) {
    _assertClass(signer, UserId);
    _assertClass(key_id, DeviceKeyId);
    _assertClass(signature, Ed25519Signature);
    const ret = wasm.signatures_addSignature(this.__wbg_ptr, signer.__wbg_ptr, key_id.__wbg_ptr, signature.__wbg_ptr);
    return ret === 0 ? void 0 : MaybeSignature.__wrap(ret);
  }
  /**
   * Try to find an Ed25519 signature from the given signer with
   * the given key ID.
   * @param {UserId} signer
   * @param {DeviceKeyId} key_id
   * @returns {Ed25519Signature | undefined}
   */
  getSignature(signer, key_id) {
    _assertClass(signer, UserId);
    _assertClass(key_id, DeviceKeyId);
    const ret = wasm.signatures_getSignature(this.__wbg_ptr, signer.__wbg_ptr, key_id.__wbg_ptr);
    return ret === 0 ? void 0 : Ed25519Signature.__wrap(ret);
  }
  /**
   * Get the map of signatures that belong to the given user.
   * @param {UserId} signer
   * @returns {Map<any, any> | undefined}
   */
  get(signer) {
    _assertClass(signer, UserId);
    const ret = wasm.signatures_get(this.__wbg_ptr, signer.__wbg_ptr);
    return ret;
  }
  /**
   * Remove all the signatures we currently hold.
   */
  clear() {
    wasm.signatures_clear(this.__wbg_ptr);
  }
  /**
   * Do we hold any signatures or is our collection completely
   * empty.
   * @returns {boolean}
   */
  isEmpty() {
    const ret = wasm.signatures_isEmpty(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * How many signatures do we currently hold.
   * @returns {number}
   */
  get count() {
    const ret = wasm.signatures_count(this.__wbg_ptr);
    return ret >>> 0;
  }
  /**
   * Get the json with all signatures
   * @returns {string}
   */
  asJSON() {
    const ret = wasm.signatures_asJSON(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
}
const StoreHandleFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_storehandle_free(ptr >>> 0, 1));
class StoreHandle {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(StoreHandle.prototype);
    obj.__wbg_ptr = ptr;
    StoreHandleFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    StoreHandleFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_storehandle_free(ptr, 0);
  }
  /**
   * Open a crypto store.
   *
   * The created store will be based on IndexedDB if a `store_name` is
   * provided; otherwise it will be based on a memory store and once the
   * objects is dropped, the keys will be lost.
   *
   * # Arguments
   *
   * * `store_name` - The name that should be used to open the IndexedDB
   *   based database. If this isn't provided, a memory-only store will be
   *   used. *Note* the memory-only store will lose your E2EE keys when the
   *   `StoreHandle` gets dropped.
   *
   * * `store_passphrase` - The passphrase that should be used to encrypt the
   *   store, for IndexedDB-based stores
   * @param {string | null} [store_name]
   * @param {string | null} [store_passphrase]
   * @returns {Promise<StoreHandle>}
   */
  static open(store_name, store_passphrase) {
    var ptr0 = isLikeNone(store_name) ? 0 : passStringToWasm0(store_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(store_passphrase) ? 0 : passStringToWasm0(store_passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    const ret = wasm.storehandle_open(ptr0, len0, ptr1, len1);
    return ret;
  }
  /**
   * Open a crypto store based on IndexedDB, using the given key for
   * encryption.
   *
   * # Arguments
   *
   * * `store_name` - The name that should be used to open the IndexedDB
   *   based database.
   *
   * * `store_key` - The key that should be used to encrypt the store, for
   *   IndexedDB-based stores. Must be a 32-byte array.
   * @param {string} store_name
   * @param {Uint8Array} store_key
   * @returns {Promise<StoreHandle>}
   */
  static openWithKey(store_name, store_key) {
    const ptr0 = passStringToWasm0(store_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(store_key, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.storehandle_openWithKey(ptr0, len0, ptr1, len1);
    return ret;
  }
}
const ToDeviceRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_todevicerequest_free(ptr >>> 0, 1));
class ToDeviceRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(ToDeviceRequest.prototype);
    obj.__wbg_ptr = ptr;
    ToDeviceRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    ToDeviceRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_todevicerequest_free(ptr, 0);
  }
  /**
   * The request ID.
   * For to-device request this would be the same value as `txn_id`. It is
   * exposed also as `id` so that the js bindings are consistent with the
   * other request types by using this field to mark as sent.
   * @returns {string}
   */
  get id() {
    const ret = wasm.__wbg_get_todevicerequest_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A string representing the type of event being sent to each devices.
   * @returns {string}
   */
  get event_type() {
    const ret = wasm.__wbg_get_todevicerequest_event_type(this.__wbg_ptr);
    return ret;
  }
  /**
   * A string representing a request identifier unique to the access token
   * used to send the request.
   * @returns {string}
   */
  get txn_id() {
    const ret = wasm.__wbg_get_todevicerequest_txn_id(this.__wbg_ptr);
    return ret;
  }
  /**
   * A JSON-encoded string containing the rest of the payload: `messages`.
   *
   * It represents the body of the HTTP request.
   * @returns {string}
   */
  get body() {
    const ret = wasm.__wbg_get_todevicerequest_body(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a new `ToDeviceRequest`.
   * @param {string} id
   * @param {string} event_type
   * @param {string} txn_id
   * @param {string} body
   */
  constructor(id, event_type, txn_id, body) {
    const ret = wasm.todevicerequest_new(id, event_type, txn_id, body);
    this.__wbg_ptr = ret >>> 0;
    ToDeviceRequestFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Get its request type.
   * @returns {RequestType}
   */
  get type() {
    const ret = wasm.todevicerequest_type(this.__wbg_ptr);
    return ret;
  }
}
const TracingFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_tracing_free(ptr >>> 0, 1));
class Tracing {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    TracingFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_tracing_free(ptr, 0);
  }
  /**
   * Check whether the `tracing` feature has been enabled.
   *
   * @deprecated: `tracing` is now always enabled.
   * @returns {boolean}
   */
  static isAvailable() {
    const ret = wasm.tracing_isAvailable();
    return ret !== 0;
  }
  /**
   * Install the tracing layer.
   * @param {LoggerLevel} min_level
   */
  constructor(min_level) {
    const ret = wasm.tracing_new(min_level);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    TracingFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Re-define the minimum logger level.
   * @param {LoggerLevel} min_level
   */
  set minLevel(min_level) {
    const ret = wasm.tracing_set_minLevel(this.__wbg_ptr, min_level);
    if (ret[1]) {
      throw takeFromExternrefTable0(ret[0]);
    }
  }
  /**
   * Turn the logger on, i.e. it emits logs again if it was turned
   * off.
   */
  turnOn() {
    const ret = wasm.tracing_turnOn(this.__wbg_ptr);
    if (ret[1]) {
      throw takeFromExternrefTable0(ret[0]);
    }
  }
  /**
   * Turn the logger off, i.e. it no longer emits logs.
   */
  turnOff() {
    const ret = wasm.tracing_turnOff(this.__wbg_ptr);
    if (ret[1]) {
      throw takeFromExternrefTable0(ret[0]);
    }
  }
}
const UploadSigningKeysRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_uploadsigningkeysrequest_free(ptr >>> 0, 1));
class UploadSigningKeysRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(UploadSigningKeysRequest.prototype);
    obj.__wbg_ptr = ptr;
    UploadSigningKeysRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    UploadSigningKeysRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_uploadsigningkeysrequest_free(ptr, 0);
  }
  /**
   * A JSON-encoded string containing the rest of the payload: `master_key`,
   * `self_signing_key`, `user_signing_key`.
   *
   * It represents the body of the HTTP request.
   * @returns {string}
   */
  get body() {
    const ret = wasm.__wbg_get_uploadsigningkeysrequest_body(this.__wbg_ptr);
    return ret;
  }
  /**
   * Create a new `UploadSigningKeysRequest`.
   * @param {string} body
   */
  constructor(body) {
    const ret = wasm.uploadsigningkeysrequest_new(body);
    this.__wbg_ptr = ret >>> 0;
    UploadSigningKeysRequestFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
}
const UserDevicesFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_userdevices_free(ptr >>> 0, 1));
class UserDevices {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(UserDevices.prototype);
    obj.__wbg_ptr = ptr;
    UserDevicesFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    UserDevicesFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_userdevices_free(ptr, 0);
  }
  /**
   * Get the specific device with the given device ID.
   * @param {DeviceId} device_id
   * @returns {Device | undefined}
   */
  get(device_id) {
    _assertClass(device_id, DeviceId);
    const ret = wasm.userdevices_get(this.__wbg_ptr, device_id.__wbg_ptr);
    return ret === 0 ? void 0 : Device.__wrap(ret);
  }
  /**
   * Returns true if there is at least one devices of this user
   * that is considered to be verified, false otherwise.
   *
   * This won't consider your own device as verified, as your own
   * device is always implicitly verified.
   * @returns {boolean}
   */
  isAnyVerified() {
    const ret = wasm.userdevices_isAnyVerified(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Array over all the device IDs of the user devices.
   * @returns {Array<any>}
   */
  keys() {
    const ret = wasm.userdevices_keys(this.__wbg_ptr);
    return ret;
  }
  /**
   * Iterator over all the devices of the user devices.
   * @returns {Array<any>}
   */
  devices() {
    const ret = wasm.userdevices_devices(this.__wbg_ptr);
    return ret;
  }
}
const UserIdFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_userid_free(ptr >>> 0, 1));
class UserId {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(UserId.prototype);
    obj.__wbg_ptr = ptr;
    UserIdFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  static __unwrap(jsValue) {
    if (!(jsValue instanceof UserId)) {
      return 0;
    }
    return jsValue.__destroy_into_raw();
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    UserIdFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_userid_free(ptr, 0);
  }
  /**
   * Parse/validate and create a new `UserId`.
   * @param {string} id
   */
  constructor(id) {
    const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.userid_new(ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    UserIdFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
  /**
   * Returns the user's localpart.
   * @returns {string}
   */
  get localpart() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.userid_localpart(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Returns the server name of the user ID.
   * @returns {ServerName}
   */
  get serverName() {
    const ret = wasm.userid_serverName(this.__wbg_ptr);
    return ServerName.__wrap(ret);
  }
  /**
   * Whether this user ID is a historical one.
   *
   * A historical user ID is one that doesn't conform to the latest
   * specification of the user ID grammar but is still accepted
   * because it was previously allowed.
   * @returns {boolean}
   */
  isHistorical() {
    const ret = wasm.userid_isHistorical(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Return the user ID as a string.
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.userid_toString(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Create a clone of this `UserId`.
   *
   * This can be useful when passing a `UserId` instance to methods such as
   * {@link OlmMachine.updateTrackedUsers} which destroy the instance.
   * @returns {UserId}
   */
  clone() {
    const ret = wasm.userid_clone(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
}
const VerificationRequestFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_verificationrequest_free(ptr >>> 0, 1));
class VerificationRequest {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(VerificationRequest.prototype);
    obj.__wbg_ptr = ptr;
    VerificationRequestFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    VerificationRequestFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_verificationrequest_free(ptr, 0);
  }
  /**
   * Create an event content that can be sent as a room event to
   * request verification from the other side. This should be used
   * only for verifications of other users and it should be sent to
   * a room we consider to be a DM with the other user.
   * @param {UserId} own_user_id
   * @param {DeviceId} own_device_id
   * @param {UserId} other_user_id
   * @param {any[] | null} [methods]
   * @returns {string}
   */
  static request(own_user_id, own_device_id, other_user_id, methods) {
    let deferred3_0;
    let deferred3_1;
    try {
      _assertClass(own_user_id, UserId);
      _assertClass(own_device_id, DeviceId);
      _assertClass(other_user_id, UserId);
      var ptr0 = isLikeNone(methods) ? 0 : passArrayJsValueToWasm0(methods, wasm.__wbindgen_malloc);
      var len0 = WASM_VECTOR_LEN;
      const ret = wasm.verificationrequest_request(own_user_id.__wbg_ptr, own_device_id.__wbg_ptr, other_user_id.__wbg_ptr, ptr0, len0);
      var ptr2 = ret[0];
      var len2 = ret[1];
      if (ret[3]) {
        ptr2 = 0;
        len2 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred3_0 = ptr2;
      deferred3_1 = len2;
      return getStringFromWasm0(ptr2, len2);
    } finally {
      wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
  }
  /**
   * Our own user id.
   * @returns {UserId}
   */
  get ownUserId() {
    const ret = wasm.verificationrequest_ownUserId(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * The ID of the other user that is participating in this
   * verification request.
   * @returns {UserId}
   */
  get otherUserId() {
    const ret = wasm.verificationrequest_otherUserId(this.__wbg_ptr);
    return UserId.__wrap(ret);
  }
  /**
   * The ID of the other device that is participating in this
   * verification.
   * @returns {DeviceId | undefined}
   */
  get otherDeviceId() {
    const ret = wasm.verificationrequest_otherDeviceId(this.__wbg_ptr);
    return ret === 0 ? void 0 : DeviceId.__wrap(ret);
  }
  /**
   * Get the room ID if the verification is happening inside a
   * room.
   * @returns {RoomId | undefined}
   */
  get roomId() {
    const ret = wasm.verificationrequest_roomId(this.__wbg_ptr);
    return ret === 0 ? void 0 : RoomId.__wrap(ret);
  }
  /**
   * Get info about the cancellation if the verification request
   * has been cancelled.
   * @returns {CancelInfo | undefined}
   */
  get cancelInfo() {
    const ret = wasm.verificationrequest_cancelInfo(this.__wbg_ptr);
    return ret === 0 ? void 0 : CancelInfo.__wrap(ret);
  }
  /**
   * Has the verification request been answered by another device?
   * @returns {boolean}
   */
  isPassive() {
    const ret = wasm.verificationrequest_isPassive(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Is the verification request ready to start a verification flow?
   * @returns {boolean}
   */
  isReady() {
    const ret = wasm.verificationrequest_isReady(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Has the verification flow timed out?
   * @returns {boolean}
   */
  timedOut() {
    const ret = wasm.verificationrequest_timedOut(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * The number of milliseconds remaining before this verification flow times
   * out.
   *
   * Returns zero if the time has already passed.
   * @returns {number}
   */
  timeRemainingMillis() {
    const ret = wasm.verificationrequest_timeRemainingMillis(this.__wbg_ptr);
    return ret;
  }
  /**
   * Get the supported verification methods of the other side.
   *
   * Will be present only if the other side requested the
   * verification or if we’re in the ready state.
   *
   * # Returns
   *
   * `undefined` if we do not yet know the supported methods; otherwise, an
   * array of `VerificationMethod`s.
   * @returns {any[] | undefined}
   */
  get theirSupportedMethods() {
    const ret = wasm.verificationrequest_theirSupportedMethods(this.__wbg_ptr);
    if (ret[3]) {
      throw takeFromExternrefTable0(ret[2]);
    }
    let v1;
    if (ret[0] !== 0) {
      v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
    }
    return v1;
  }
  /**
   * Get our own supported verification methods that we advertised.
   *
   * Will be present only we requested the verification or if we’re
   * in the ready state.
   * @returns {any[] | undefined}
   */
  get ourSupportedMethods() {
    const ret = wasm.verificationrequest_ourSupportedMethods(this.__wbg_ptr);
    if (ret[3]) {
      throw takeFromExternrefTable0(ret[2]);
    }
    let v1;
    if (ret[0] !== 0) {
      v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
      wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
    }
    return v1;
  }
  /**
   * Get the unique ID of this verification request.
   * @returns {string}
   */
  get flowId() {
    let deferred1_0;
    let deferred1_1;
    try {
      const ret = wasm.verificationrequest_flowId(this.__wbg_ptr);
      deferred1_0 = ret[0];
      deferred1_1 = ret[1];
      return getStringFromWasm0(ret[0], ret[1]);
    } finally {
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * Is this a verification that is verifying one of our own
   * devices?
   * @returns {boolean}
   */
  isSelfVerification() {
    const ret = wasm.verificationrequest_isSelfVerification(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Did we initiate the verification request?
   * @returns {boolean}
   */
  weStarted() {
    const ret = wasm.verificationrequest_weStarted(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Has the verification flow that was started with this request
   * finished?
   * @returns {boolean}
   */
  isDone() {
    const ret = wasm.verificationrequest_isDone(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Get the current phase of this request.
   *
   * Returns a `VerificationRequestPhase`.
   * @returns {VerificationRequestPhase}
   */
  phase() {
    const ret = wasm.verificationrequest_phase(this.__wbg_ptr);
    return ret;
  }
  /**
   * If this request has transitioned into a concrete verification
   * flow (and not yet been completed or cancelled), returns a `Verification`
   * object.
   *
   * Returns: a `Sas`, a `Qr`, or `undefined`.
   * @returns {any}
   */
  getVerification() {
    const ret = wasm.verificationrequest_getVerification(this.__wbg_ptr);
    return ret;
  }
  /**
   * Register a callback which will be called whenever there is an update to
   * the request.
   *
   * The `callback` is called with no parameters.
   * @param {Function} callback
   */
  registerChangesCallback(callback) {
    wasm.verificationrequest_registerChangesCallback(this.__wbg_ptr, callback);
  }
  /**
   * Has the verification flow that was started with this request
   * been cancelled?
   * @returns {boolean}
   */
  isCancelled() {
    const ret = wasm.verificationrequest_isCancelled(this.__wbg_ptr);
    return ret !== 0;
  }
  /**
   * Accept the verification request signaling that our client
   * supports the given verification methods.
   *
   * `methods` represents the methods that we should advertise as
   * supported by us.
   *
   * It returns either a `ToDeviceRequest`, a `RoomMessageRequest`
   * or `undefined`.
   * @param {any[]} methods
   * @returns {any}
   */
  acceptWithMethods(methods) {
    const ptr0 = passArrayJsValueToWasm0(methods, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.verificationrequest_acceptWithMethods(this.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Accept the verification request.
   *
   * This method will accept the request and signal that it
   * supports the `m.sas.v1`, the `m.qr_code.show.v1`, and
   * `m.reciprocate.v1` method.
   *
   * `m.qr_code.show.v1` will only be signaled if the `qrcode`
   * feature is enabled. This feature is disabled by default. If
   * it's enabled and QR code scanning should be supported or QR
   * code showing shouldn't be supported the `accept_with_methods`
   * method should be used instead.
   *
   * It returns either a `ToDeviceRequest`, a `RoomMessageRequest`
   * or `undefined`.
   * @returns {any}
   */
  accept() {
    const ret = wasm.verificationrequest_accept(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Cancel the verification request.
   *
   * It returns either a `ToDeviceRequest`, a `RoomMessageRequest`
   * or `undefined`.
   * @returns {any}
   */
  cancel() {
    const ret = wasm.verificationrequest_cancel(this.__wbg_ptr);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Transition from this verification request into a SAS verification flow.
   *
   * Returns `Promise<[Sas, RoomMessageRequest|ToDeviceRequest] | undefined>`
   * @returns {Promise<any>}
   */
  startSas() {
    const ret = wasm.verificationrequest_startSas(this.__wbg_ptr);
    return ret;
  }
  /**
   * Generate a QR code that can be used by another client to start
   * a QR code based verification.
   *
   * Returns a `Qr` or `undefined`.
   * @returns {Promise<any>}
   */
  generateQrCode() {
    const ret = wasm.verificationrequest_generateQrCode(this.__wbg_ptr);
    return ret;
  }
  /**
   * Start a QR code verification by providing a scanned QR code
   * for this verification flow.
   * @param {QrCodeScan} data
   * @returns {Promise<any>}
   */
  scanQrCode(data) {
    _assertClass(data, QrCodeScan);
    const ret = wasm.verificationrequest_scanQrCode(this.__wbg_ptr, data.__wbg_ptr);
    return ret;
  }
}
const VersionsFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_versions_free(ptr >>> 0, 1));
class Versions {
  static __wrap(ptr) {
    ptr = ptr >>> 0;
    const obj = Object.create(Versions.prototype);
    obj.__wbg_ptr = ptr;
    VersionsFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    VersionsFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_versions_free(ptr, 0);
  }
  /**
   * The version of the vodozemac crate.
   * @returns {string}
   */
  get vodozemac() {
    const ret = wasm.__wbg_get_versions_vodozemac(this.__wbg_ptr);
    return ret;
  }
  /**
   * The version of the matrix-sdk-crypto crate.
   * @returns {string}
   */
  get matrix_sdk_crypto() {
    const ret = wasm.__wbg_get_versions_matrix_sdk_crypto(this.__wbg_ptr);
    return ret;
  }
  /**
   * The Git commit hash of the crate's source tree at build time.
   * @returns {string}
   */
  get git_sha() {
    const ret = wasm.__wbg_get_versions_git_sha(this.__wbg_ptr);
    return ret;
  }
  /**
   * The build-time output of the `git describe` command of the source tree
   * of crate.
   * @returns {string}
   */
  get git_description() {
    const ret = wasm.__wbg_get_versions_git_description(this.__wbg_ptr);
    return ret;
  }
}
function __wbg_String_8f0eb39a4a4c2f66(arg0, arg1) {
  const ret = String(arg1);
  const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len1 = WASM_VECTOR_LEN;
  getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}
function __wbg_Window_b0044ac7db258535(arg0) {
  const ret = arg0.Window;
  return ret;
}
function __wbg_WorkerGlobalScope_b74cefefc62a37da(arg0) {
  const ret = arg0.WorkerGlobalScope;
  return ret;
}
function __wbg_add_883d9432f9188ef2(arg0, arg1) {
  const ret = arg0.add(arg1);
  return ret;
}
function __wbg_add_9338901b80183e0f() {
  return handleError(function(arg0, arg1, arg2) {
    const ret = arg0.add(arg1, arg2);
    return ret;
  }, arguments);
}
function __wbg_at_7d852dd9f194d43e(arg0, arg1) {
  const ret = arg0.at(arg1);
  return ret;
}
function __wbg_backupkeys_new(arg0) {
  const ret = BackupKeys.__wrap(arg0);
  return ret;
}
function __wbg_bound_55a8d08e0491e17a() {
  return handleError(function(arg0, arg1) {
    const ret = IDBKeyRange.bound(arg0, arg1);
    return ret;
  }, arguments);
}
function __wbg_bound_f2afc3766d4545cf() {
  return handleError(function(arg0, arg1, arg2, arg3) {
    const ret = IDBKeyRange.bound(arg0, arg1, arg2 !== 0, arg3 !== 0);
    return ret;
  }, arguments);
}
function __wbg_buffer_609cc3eee51ed158(arg0) {
  const ret = arg0.buffer;
  return ret;
}
function __wbg_call_672a4d21634d4a24() {
  return handleError(function(arg0, arg1) {
    const ret = arg0.call(arg1);
    return ret;
  }, arguments);
}
function __wbg_call_7cccdd69e0791ae2() {
  return handleError(function(arg0, arg1, arg2) {
    const ret = arg0.call(arg1, arg2);
    return ret;
  }, arguments);
}
function __wbg_call_833bed5770ea2041() {
  return handleError(function(arg0, arg1, arg2, arg3) {
    const ret = arg0.call(arg1, arg2, arg3);
    return ret;
  }, arguments);
}
function __wbg_call_b8adc8b1d0a0d8eb() {
  return handleError(function(arg0, arg1, arg2, arg3, arg4) {
    const ret = arg0.call(arg1, arg2, arg3, arg4);
    return ret;
  }, arguments);
}
function __wbg_clearTimeout_5a54f8841c30079a(arg0) {
  const ret = clearTimeout(arg0);
  return ret;
}
function __wbg_clear_f450db7eeb71163f() {
  return handleError(function(arg0) {
    const ret = arg0.clear();
    return ret;
  }, arguments);
}
function __wbg_close_26fc2e6856d8567a(arg0) {
  arg0.close();
}
function __wbg_code_cfd8f6868bdaed9b(arg0) {
  const ret = arg0.code;
  return ret;
}
function __wbg_continue_c46c11d3dbe1b030() {
  return handleError(function(arg0) {
    arg0.continue();
  }, arguments);
}
function __wbg_count_613cb921d67a4f26() {
  return handleError(function(arg0) {
    const ret = arg0.count();
    return ret;
  }, arguments);
}
function __wbg_count_ea1a2987dff7759e() {
  return handleError(function(arg0) {
    const ret = arg0.count();
    return ret;
  }, arguments);
}
function __wbg_createIndex_873ac48adc772309() {
  return handleError(function(arg0, arg1, arg2, arg3, arg4) {
    const ret = arg0.createIndex(getStringFromWasm0(arg1, arg2), arg3, arg4);
    return ret;
  }, arguments);
}
function __wbg_createIndex_fcfd513cf4581834() {
  return handleError(function(arg0, arg1, arg2, arg3) {
    const ret = arg0.createIndex(getStringFromWasm0(arg1, arg2), arg3);
    return ret;
  }, arguments);
}
function __wbg_createObjectStore_e566459f7161f82f() {
  return handleError(function(arg0, arg1, arg2) {
    const ret = arg0.createObjectStore(getStringFromWasm0(arg1, arg2));
    return ret;
  }, arguments);
}
function __wbg_crosssigningbootstraprequests_new(arg0) {
  const ret = CrossSigningBootstrapRequests.__wrap(arg0);
  return ret;
}
function __wbg_crosssigningkeyexport_new(arg0) {
  const ret = CrossSigningKeyExport.__wrap(arg0);
  return ret;
}
function __wbg_crosssigningstatus_new(arg0) {
  const ret = CrossSigningStatus.__wrap(arg0);
  return ret;
}
function __wbg_crypto_574e78ad8b13b65f(arg0) {
  const ret = arg0.crypto;
  return ret;
}
function __wbg_debug_3cb59063b29f58c1(arg0) {
  console.debug(arg0);
}
function __wbg_debug_f41e47509e8e4e36(arg0, arg1) {
  arg0.debug(arg1);
}
function __wbg_decryptedroomevent_new(arg0) {
  const ret = DecryptedRoomEvent.__wrap(arg0);
  return ret;
}
function __wbg_dehydrateddevice_new(arg0) {
  const ret = DehydratedDevice.__wrap(arg0);
  return ret;
}
function __wbg_dehydrateddevicekey_new(arg0) {
  const ret = DehydratedDeviceKey.__wrap(arg0);
  return ret;
}
function __wbg_deleteObjectStore_3f08ae00cd288224() {
  return handleError(function(arg0, arg1, arg2) {
    arg0.deleteObjectStore(getStringFromWasm0(arg1, arg2));
  }, arguments);
}
function __wbg_delete_200677093b4cf756() {
  return handleError(function(arg0, arg1) {
    const ret = arg0.delete(arg1);
    return ret;
  }, arguments);
}
function __wbg_delete_2ecf7cf20900b3a2() {
  return handleError(function(arg0) {
    const ret = arg0.delete();
    return ret;
  }, arguments);
}
function __wbg_device_new(arg0) {
  const ret = Device.__wrap(arg0);
  return ret;
}
function __wbg_deviceid_new(arg0) {
  const ret = DeviceId.__wrap(arg0);
  return ret;
}
function __wbg_devicekey_new(arg0) {
  const ret = DeviceKey.__wrap(arg0);
  return ret;
}
function __wbg_devicekeyid_new(arg0) {
  const ret = DeviceKeyId.__wrap(arg0);
  return ret;
}
function __wbg_done_769e5ede4b31c67b(arg0) {
  const ret = arg0.done;
  return ret;
}
function __wbg_emoji_new(arg0) {
  const ret = Emoji.__wrap(arg0);
  return ret;
}
function __wbg_encryptioninfo_new(arg0) {
  const ret = EncryptionInfo.__wrap(arg0);
  return ret;
}
function __wbg_entries_3265d4158b33e5dc(arg0) {
  const ret = Object.entries(arg0);
  return ret;
}
function __wbg_entries_c8a90a7ed73e84ce(arg0) {
  const ret = arg0.entries();
  return ret;
}
function __wbg_error_524f506f44df1645(arg0) {
  console.error(arg0);
}
function __wbg_error_7534b8e9a36f1ab4(arg0, arg1) {
  let deferred0_0;
  let deferred0_1;
  try {
    deferred0_0 = arg0;
    deferred0_1 = arg1;
    console.error(getStringFromWasm0(arg0, arg1));
  } finally {
    wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
  }
}
function __wbg_error_76286673af64a31f(arg0, arg1) {
  arg0.error(arg1);
}
function __wbg_error_ff4ddaabdfc5dbb3() {
  return handleError(function(arg0) {
    const ret = arg0.error;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
  }, arguments);
}
function __wbg_from_2a5d3e218e67aa85(arg0) {
  const ret = Array.from(arg0);
  return ret;
}
function __wbg_getAllKeys_b11d8835dc4be0e8() {
  return handleError(function(arg0) {
    const ret = arg0.getAllKeys();
    return ret;
  }, arguments);
}
function __wbg_getAll_304e868beec2021f() {
  return handleError(function(arg0) {
    const ret = arg0.getAll();
    return ret;
  }, arguments);
}
function __wbg_getAll_d1e60c13c0073374() {
  return handleError(function(arg0, arg1, arg2) {
    const ret = arg0.getAll(arg1, arg2 >>> 0);
    return ret;
  }, arguments);
}
function __wbg_getAll_e6903c610babcd42() {
  return handleError(function(arg0, arg1) {
    const ret = arg0.getAll(arg1);
    return ret;
  }, arguments);
}
function __wbg_getRandomValues_3d90134a348e46b3() {
  return handleError(function(arg0, arg1) {
    globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
  }, arguments);
}
function __wbg_getRandomValues_b8f5dbd5f3995a9e() {
  return handleError(function(arg0, arg1) {
    arg0.getRandomValues(arg1);
  }, arguments);
}
function __wbg_getTime_46267b1c24877e30(arg0) {
  const ret = arg0.getTime();
  return ret;
}
function __wbg_get_67b2ba62fc30de12() {
  return handleError(function(arg0, arg1) {
    const ret = Reflect.get(arg0, arg1);
    return ret;
  }, arguments);
}
function __wbg_get_8da03f81f6a1111e() {
  return handleError(function(arg0, arg1) {
    const ret = arg0.get(arg1);
    return ret;
  }, arguments);
}
function __wbg_get_93e54e8e166fbcab() {
  return handleError(function(arg0, arg1) {
    const ret = arg0.get(arg1);
    return ret;
  }, arguments);
}
function __wbg_get_b9b93047fe3cf45b(arg0, arg1) {
  const ret = arg0[arg1 >>> 0];
  return ret;
}
function __wbg_getwithrefkey_1dc361bd10053bfe(arg0, arg1) {
  const ret = arg0[arg1];
  return ret;
}
function __wbg_global_b6f5c73312f62313(arg0) {
  const ret = arg0.global;
  return ret;
}
function __wbg_inboundgroupsession_new(arg0) {
  const ret = InboundGroupSession.__wrap(arg0);
  return ret;
}
function __wbg_index_e00ca5fff206ee3e() {
  return handleError(function(arg0, arg1, arg2) {
    const ret = arg0.index(getStringFromWasm0(arg1, arg2));
    return ret;
  }, arguments);
}
function __wbg_indexedDB_601ec26c63e333de() {
  return handleError(function(arg0) {
    const ret = arg0.indexedDB;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
  }, arguments);
}
function __wbg_indexedDB_b1f49280282046f8() {
  return handleError(function(arg0) {
    const ret = arg0.indexedDB;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
  }, arguments);
}
function __wbg_indexedDB_f6b47b0dc333fd2f() {
  return handleError(function(arg0) {
    const ret = arg0.indexedDB;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
  }, arguments);
}
function __wbg_info_3b4be85e0a44d2af(arg0, arg1) {
  arg0.info(arg1);
}
function __wbg_info_3daf2e093e091b66(arg0) {
  console.info(arg0);
}
function __wbg_instanceof_ArrayBuffer_e14585432e3737fc(arg0) {
  let result;
  try {
    result = arg0 instanceof ArrayBuffer;
  } catch (_) {
    result = false;
  }
  const ret = result;
  return ret;
}
function __wbg_instanceof_Map_f3469ce2244d2430(arg0) {
  let result;
  try {
    result = arg0 instanceof Map;
  } catch (_) {
    result = false;
  }
  const ret = result;
  return ret;
}
function __wbg_instanceof_Promise_935168b8f4b49db3(arg0) {
  let result;
  try {
    result = arg0 instanceof Promise;
  } catch (_) {
    result = false;
  }
  const ret = result;
  return ret;
}
function __wbg_instanceof_Uint8Array_17156bcf118086a9(arg0) {
  let result;
  try {
    result = arg0 instanceof Uint8Array;
  } catch (_) {
    result = false;
  }
  const ret = result;
  return ret;
}
function __wbg_isArray_a1eab7e0d067391b(arg0) {
  const ret = Array.isArray(arg0);
  return ret;
}
function __wbg_isSafeInteger_343e2beeeece1bb0(arg0) {
  const ret = Number.isSafeInteger(arg0);
  return ret;
}
function __wbg_item_c3c26b4103ad5aaf(arg0, arg1, arg2) {
  const ret = arg1.item(arg2 >>> 0);
  var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  var len1 = WASM_VECTOR_LEN;
  getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}
function __wbg_iterator_9a24c88df860dc65() {
  const ret = Symbol.iterator;
  return ret;
}
function __wbg_key_29fefecef430db96() {
  return handleError(function(arg0) {
    const ret = arg0.key;
    return ret;
  }, arguments);
}
function __wbg_keysbackuprequest_new(arg0) {
  const ret = KeysBackupRequest.__wrap(arg0);
  return ret;
}
function __wbg_keysclaimrequest_new(arg0) {
  const ret = KeysClaimRequest.__wrap(arg0);
  return ret;
}
function __wbg_keysqueryrequest_new(arg0) {
  const ret = KeysQueryRequest.__wrap(arg0);
  return ret;
}
function __wbg_keysuploadrequest_new(arg0) {
  const ret = KeysUploadRequest.__wrap(arg0);
  return ret;
}
function __wbg_length_238152a0aedbb6e7(arg0) {
  const ret = arg0.length;
  return ret;
}
function __wbg_length_a446193dc22c12f8(arg0) {
  const ret = arg0.length;
  return ret;
}
function __wbg_length_e2d2a49132c1b256(arg0) {
  const ret = arg0.length;
  return ret;
}
function __wbg_lowerBound_1872d19f5bcf83c6() {
  return handleError(function(arg0, arg1) {
    const ret = IDBKeyRange.lowerBound(arg0, arg1 !== 0);
    return ret;
  }, arguments);
}
function __wbg_maybesignature_new(arg0) {
  const ret = MaybeSignature.__wrap(arg0);
  return ret;
}
function __wbg_megolmdecryptionerror_new(arg0) {
  const ret = MegolmDecryptionError.__wrap(arg0);
  return ret;
}
function __wbg_message_5c5d919204d42400(arg0, arg1) {
  const ret = arg1.message;
  const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len1 = WASM_VECTOR_LEN;
  getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}
function __wbg_msCrypto_a61aeb35a24c1329(arg0) {
  const ret = arg0.msCrypto;
  return ret;
}
function __wbg_name_f2d27098bfd843e7(arg0, arg1) {
  const ret = arg1.name;
  const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len1 = WASM_VECTOR_LEN;
  getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}
function __wbg_new_23a2665fac83c611(arg0, arg1) {
  try {
    var state0 = { a: arg0, b: arg1 };
    var cb0 = (arg02, arg12) => {
      const a = state0.a;
      state0.a = 0;
      try {
        return __wbg_adapter_788(a, state0.b, arg02, arg12);
      } finally {
        state0.a = a;
      }
    };
    const ret = new Promise(cb0);
    return ret;
  } finally {
    state0.a = state0.b = 0;
  }
}
function __wbg_new_31a97dac4f10fab7(arg0) {
  const ret = new Date(arg0);
  return ret;
}
function __wbg_new_405e22f390576ce2() {
  const ret = new Object();
  return ret;
}
function __wbg_new_5e0be73521bc8c17() {
  const ret = /* @__PURE__ */ new Map();
  return ret;
}
function __wbg_new_78feb108b6472713() {
  const ret = new Array();
  return ret;
}
function __wbg_new_7a91e41fe43b3c92(arg0) {
  const ret = new Uint8ClampedArray(arg0);
  return ret;
}
function __wbg_new_8a6f238a6ece86ea() {
  const ret = new Error();
  return ret;
}
function __wbg_new_a12002a7f91c75be(arg0) {
  const ret = new Uint8Array(arg0);
  return ret;
}
function __wbg_new_a239edaa1dc2968f(arg0) {
  const ret = new Set(arg0);
  return ret;
}
function __wbg_newnoargs_105ed471475aaf50(arg0, arg1) {
  const ret = new Function(getStringFromWasm0(arg0, arg1));
  return ret;
}
function __wbg_newwithbyteoffsetandlength_6d34787141015158(arg0, arg1, arg2) {
  const ret = new Uint8ClampedArray(arg0, arg1 >>> 0, arg2 >>> 0);
  return ret;
}
function __wbg_newwithbyteoffsetandlength_d97e637ebe145a9a(arg0, arg1, arg2) {
  const ret = new Uint8Array(arg0, arg1 >>> 0, arg2 >>> 0);
  return ret;
}
function __wbg_newwithlength_a381634e90c276d4(arg0) {
  const ret = new Uint8Array(arg0 >>> 0);
  return ret;
}
function __wbg_newwithlength_ee8e1b95dea9d37c(arg0) {
  const ret = new Uint8ClampedArray(arg0 >>> 0);
  return ret;
}
function __wbg_newwithmessage_baedba94f03976fd() {
  return handleError(function(arg0, arg1) {
    const ret = new DOMException(getStringFromWasm0(arg0, arg1));
    return ret;
  }, arguments);
}
function __wbg_next_25feadfc0913fea9(arg0) {
  const ret = arg0.next;
  return ret;
}
function __wbg_next_6574e1a8a62d1055() {
  return handleError(function(arg0) {
    const ret = arg0.next();
    return ret;
  }, arguments);
}
function __wbg_node_905d3e251edff8a2(arg0) {
  const ret = arg0.node;
  return ret;
}
function __wbg_now_2c95c9de01293173(arg0) {
  const ret = arg0.now();
  return ret;
}
function __wbg_now_807e54c39636c349() {
  const ret = Date.now();
  return ret;
}
function __wbg_objectStoreNames_9bb1ab04a7012aaf(arg0) {
  const ret = arg0.objectStoreNames;
  return ret;
}
function __wbg_objectStore_21878d46d25b64b6() {
  return handleError(function(arg0, arg1, arg2) {
    const ret = arg0.objectStore(getStringFromWasm0(arg1, arg2));
    return ret;
  }, arguments);
}
function __wbg_oldVersion_e8337811e52861c6(arg0) {
  const ret = arg0.oldVersion;
  return ret;
}
function __wbg_olmmachine_new(arg0) {
  const ret = OlmMachine.__wrap(arg0);
  return ret;
}
function __wbg_openCursor_1adef2266972fb45() {
  return handleError(function(arg0) {
    const ret = arg0.openCursor();
    return ret;
  }, arguments);
}
function __wbg_openCursor_238e247d18bde2cd() {
  return handleError(function(arg0) {
    const ret = arg0.openCursor();
    return ret;
  }, arguments);
}
function __wbg_openCursor_f4b061aa6d804b93() {
  return handleError(function(arg0, arg1) {
    const ret = arg0.openCursor(arg1);
    return ret;
  }, arguments);
}
function __wbg_open_88b1390d99a7c691() {
  return handleError(function(arg0, arg1, arg2) {
    const ret = arg0.open(getStringFromWasm0(arg1, arg2));
    return ret;
  }, arguments);
}
function __wbg_open_e0c0b2993eb596e1() {
  return handleError(function(arg0, arg1, arg2, arg3) {
    const ret = arg0.open(getStringFromWasm0(arg1, arg2), arg3 >>> 0);
    return ret;
  }, arguments);
}
function __wbg_otheruseridentity_new(arg0) {
  const ret = OtherUserIdentity.__wrap(arg0);
  return ret;
}
function __wbg_ownuseridentity_new(arg0) {
  const ret = OwnUserIdentity.__wrap(arg0);
  return ret;
}
function __wbg_parse_def2e24ef1252aff() {
  return handleError(function(arg0, arg1) {
    const ret = JSON.parse(getStringFromWasm0(arg0, arg1));
    return ret;
  }, arguments);
}
function __wbg_performance_7a3ffd0b17f663ad(arg0) {
  const ret = arg0.performance;
  return ret;
}
function __wbg_pickledinboundgroupsession_unwrap(arg0) {
  const ret = PickledInboundGroupSession.__unwrap(arg0);
  return ret;
}
function __wbg_pickledsession_unwrap(arg0) {
  const ret = PickledSession.__unwrap(arg0);
  return ret;
}
function __wbg_process_dc0fbacc7c1c06f7(arg0) {
  const ret = arg0.process;
  return ret;
}
function __wbg_push_737cfc8c1432c2c6(arg0, arg1) {
  const ret = arg0.push(arg1);
  return ret;
}
function __wbg_put_066faa31a6a88f5b() {
  return handleError(function(arg0, arg1, arg2) {
    const ret = arg0.put(arg1, arg2);
    return ret;
  }, arguments);
}
function __wbg_putdehydrateddevicerequest_new(arg0) {
  const ret = PutDehydratedDeviceRequest.__wrap(arg0);
  return ret;
}
function __wbg_qr_new(arg0) {
  const ret = Qr.__wrap(arg0);
  return ret;
}
function __wbg_queueMicrotask_97d92b4fcc8a61c5(arg0) {
  queueMicrotask(arg0);
}
function __wbg_queueMicrotask_d3219def82552485(arg0) {
  const ret = arg0.queueMicrotask;
  return ret;
}
function __wbg_randomFillSync_ac0988aba3254290() {
  return handleError(function(arg0, arg1) {
    arg0.randomFillSync(arg1);
  }, arguments);
}
function __wbg_readyState_4013cfdf4f22afb0(arg0) {
  const ret = arg0.readyState;
  return (__wbindgen_enum_IdbRequestReadyState.indexOf(ret) + 1 || 3) - 1;
}
function __wbg_rehydrateddevice_new(arg0) {
  const ret = RehydratedDevice.__wrap(arg0);
  return ret;
}
function __wbg_require_60cc747a6bc5215a() {
  return handleError(function() {
    const ret = module.require;
    return ret;
  }, arguments);
}
function __wbg_resolve_4851785c9c5f573d(arg0) {
  const ret = Promise.resolve(arg0);
  return ret;
}
function __wbg_result_f29afabdf2c05826() {
  return handleError(function(arg0) {
    const ret = arg0.result;
    return ret;
  }, arguments);
}
function __wbg_roomid_unwrap(arg0) {
  const ret = RoomId.__unwrap(arg0);
  return ret;
}
function __wbg_roomkeycounts_new(arg0) {
  const ret = RoomKeyCounts.__wrap(arg0);
  return ret;
}
function __wbg_roomkeyimportresult_new(arg0) {
  const ret = RoomKeyImportResult.__wrap(arg0);
  return ret;
}
function __wbg_roomkeyinfo_new(arg0) {
  const ret = RoomKeyInfo.__wrap(arg0);
  return ret;
}
function __wbg_roomkeywithheldinfo_new(arg0) {
  const ret = RoomKeyWithheldInfo.__wrap(arg0);
  return ret;
}
function __wbg_roommessagerequest_new(arg0) {
  const ret = RoomMessageRequest.__wrap(arg0);
  return ret;
}
function __wbg_roomsettings_new(arg0) {
  const ret = RoomSettings.__wrap(arg0);
  return ret;
}
function __wbg_sas_new(arg0) {
  const ret = Sas.__wrap(arg0);
  return ret;
}
function __wbg_secretsbundle_new(arg0) {
  const ret = SecretsBundle.__wrap(arg0);
  return ret;
}
function __wbg_setTimeout_db2dbaeefb6f39c7() {
  return handleError(function(arg0, arg1) {
    const ret = setTimeout(arg0, arg1);
    return ret;
  }, arguments);
}
function __wbg_set_37837023f3d740e8(arg0, arg1, arg2) {
  arg0[arg1 >>> 0] = arg2;
}
function __wbg_set_3f1d0b984ed272ed(arg0, arg1, arg2) {
  arg0[arg1] = arg2;
}
function __wbg_set_65595bdd868b3009(arg0, arg1, arg2) {
  arg0.set(arg1, arg2 >>> 0);
}
function __wbg_set_6775f73144c2ef27(arg0, arg1, arg2) {
  arg0.set(arg1, arg2 >>> 0);
}
function __wbg_set_8fc6bf8a5b1071d1(arg0, arg1, arg2) {
  const ret = arg0.set(arg1, arg2);
  return ret;
}
function __wbg_setonabort_3bf4db6614fa98e9(arg0, arg1) {
  arg0.onabort = arg1;
}
function __wbg_setonblocked_aebf64bd39f1eca8(arg0, arg1) {
  arg0.onblocked = arg1;
}
function __wbg_setoncomplete_4d19df0dadb7c4d4(arg0, arg1) {
  arg0.oncomplete = arg1;
}
function __wbg_setonerror_b0d9d723b8fddbbb(arg0, arg1) {
  arg0.onerror = arg1;
}
function __wbg_setonerror_d7e3056cc6e56085(arg0, arg1) {
  arg0.onerror = arg1;
}
function __wbg_setonsuccess_afa464ee777a396d(arg0, arg1) {
  arg0.onsuccess = arg1;
}
function __wbg_setonupgradeneeded_fcf7ce4f2eb0cb5f(arg0, arg1) {
  arg0.onupgradeneeded = arg1;
}
function __wbg_setonversionchange_6ee07fa49ee1e3a5(arg0, arg1) {
  arg0.onversionchange = arg1;
}
function __wbg_setunique_dd24c422aa05df89(arg0, arg1) {
  arg0.unique = arg1 !== 0;
}
function __wbg_signatures_new(arg0) {
  const ret = Signatures.__wrap(arg0);
  return ret;
}
function __wbg_signatureuploadrequest_new(arg0) {
  const ret = SignatureUploadRequest.__wrap(arg0);
  return ret;
}
function __wbg_signatureverification_new(arg0) {
  const ret = SignatureVerification.__wrap(arg0);
  return ret;
}
function __wbg_stack_0ed75d68575b0f3c(arg0, arg1) {
  const ret = arg1.stack;
  const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len1 = WASM_VECTOR_LEN;
  getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}
function __wbg_static_accessor_GLOBAL_88a902d13a557d07() {
  const ret = typeof global === "undefined" ? null : global;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
function __wbg_static_accessor_GLOBAL_THIS_56578be7e9f832b0() {
  const ret = typeof globalThis === "undefined" ? null : globalThis;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
function __wbg_static_accessor_SELF_37c5d418e4bf5819() {
  const ret = typeof self === "undefined" ? null : self;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
function __wbg_static_accessor_WINDOW_5de37043a91a9c40() {
  const ret = typeof window === "undefined" ? null : window;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
function __wbg_storehandle_new(arg0) {
  const ret = StoreHandle.__wrap(arg0);
  return ret;
}
function __wbg_stringify_f7ed6987935b4a24() {
  return handleError(function(arg0) {
    const ret = JSON.stringify(arg0);
    return ret;
  }, arguments);
}
function __wbg_subarray_aa9065fa9dc5df96(arg0, arg1, arg2) {
  const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
  return ret;
}
function __wbg_target_0a62d9d79a2a1ede(arg0) {
  const ret = arg0.target;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
function __wbg_then_44b73946d2fb3e7d(arg0, arg1) {
  const ret = arg0.then(arg1);
  return ret;
}
function __wbg_then_48b406749878a531(arg0, arg1, arg2) {
  const ret = arg0.then(arg1, arg2);
  return ret;
}
function __wbg_todevicerequest_new(arg0) {
  const ret = ToDeviceRequest.__wrap(arg0);
  return ret;
}
function __wbg_transaction_babc423936946a37() {
  return handleError(function(arg0, arg1, arg2, arg3) {
    const ret = arg0.transaction(getStringFromWasm0(arg1, arg2), __wbindgen_enum_IdbTransactionMode[arg3]);
    return ret;
  }, arguments);
}
function __wbg_transaction_d6d07c3c9963c49e() {
  return handleError(function(arg0, arg1, arg2) {
    const ret = arg0.transaction(arg1, __wbindgen_enum_IdbTransactionMode[arg2]);
    return ret;
  }, arguments);
}
function __wbg_transaction_e713aa7b07ccaedd(arg0) {
  const ret = arg0.transaction;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
function __wbg_update_acd72607f506872a() {
  return handleError(function(arg0, arg1) {
    const ret = arg0.update(arg1);
    return ret;
  }, arguments);
}
function __wbg_userdevices_new(arg0) {
  const ret = UserDevices.__wrap(arg0);
  return ret;
}
function __wbg_userid_new(arg0) {
  const ret = UserId.__wrap(arg0);
  return ret;
}
function __wbg_userid_unwrap(arg0) {
  const ret = UserId.__unwrap(arg0);
  return ret;
}
function __wbg_value_68c4e9a54bb7fd5e() {
  return handleError(function(arg0) {
    const ret = arg0.value;
    return ret;
  }, arguments);
}
function __wbg_value_cd1ffa7b1ab794f1(arg0) {
  const ret = arg0.value;
  return ret;
}
function __wbg_values_53465c57fc8cd691(arg0) {
  const ret = arg0.values();
  return ret;
}
function __wbg_verificationrequest_new(arg0) {
  const ret = VerificationRequest.__wrap(arg0);
  return ret;
}
function __wbg_version_a70a33e5bbc6d6db(arg0) {
  const ret = arg0.version;
  return ret;
}
function __wbg_versions_c01dfd4722a88165(arg0) {
  const ret = arg0.versions;
  return ret;
}
function __wbg_warn_4ca3906c248c47c4(arg0) {
  console.warn(arg0);
}
function __wbg_warn_6ce7b8525f302b4c(arg0, arg1) {
  arg0.warn(arg1);
}
function __wbindgen_as_number(arg0) {
  const ret = +arg0;
  return ret;
}
function __wbindgen_bigint_from_i64(arg0) {
  const ret = arg0;
  return ret;
}
function __wbindgen_bigint_from_u64(arg0) {
  const ret = BigInt.asUintN(64, arg0);
  return ret;
}
function __wbindgen_bigint_get_as_i64(arg0, arg1) {
  const v = arg1;
  const ret = typeof v === "bigint" ? v : void 0;
  getDataViewMemory0().setBigInt64(arg0 + 8 * 1, isLikeNone(ret) ? BigInt(0) : ret, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
}
function __wbindgen_boolean_get(arg0) {
  const v = arg0;
  const ret = typeof v === "boolean" ? v ? 1 : 0 : 2;
  return ret;
}
function __wbindgen_cb_drop(arg0) {
  const obj = arg0.original;
  if (obj.cnt-- == 1) {
    obj.a = 0;
    return true;
  }
  const ret = false;
  return ret;
}
function __wbindgen_closure_wrapper1087(arg0, arg1, arg2) {
  const ret = makeMutClosure(arg0, arg1, 44, __wbg_adapter_58);
  return ret;
}
function __wbindgen_closure_wrapper2244(arg0, arg1, arg2) {
  const ret = makeMutClosure(arg0, arg1, 417, __wbg_adapter_61);
  return ret;
}
function __wbindgen_closure_wrapper5515(arg0, arg1, arg2) {
  const ret = makeMutClosure(arg0, arg1, 417, __wbg_adapter_64);
  return ret;
}
function __wbindgen_closure_wrapper7008(arg0, arg1, arg2) {
  const ret = makeClosure(arg0, arg1, 424, __wbg_adapter_67);
  return ret;
}
function __wbindgen_closure_wrapper7010(arg0, arg1, arg2) {
  const ret = makeClosure(arg0, arg1, 424, __wbg_adapter_70);
  return ret;
}
function __wbindgen_debug_string(arg0, arg1) {
  const ret = debugString(arg1);
  const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len1 = WASM_VECTOR_LEN;
  getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}
function __wbindgen_error_new(arg0, arg1) {
  const ret = new Error(getStringFromWasm0(arg0, arg1));
  return ret;
}
function __wbindgen_in(arg0, arg1) {
  const ret = arg0 in arg1;
  return ret;
}
function __wbindgen_init_externref_table() {
  const table = wasm.__wbindgen_export_4;
  const offset = table.grow(4);
  table.set(0, void 0);
  table.set(offset + 0, void 0);
  table.set(offset + 1, null);
  table.set(offset + 2, true);
  table.set(offset + 3, false);
}
function __wbindgen_is_array(arg0) {
  const ret = Array.isArray(arg0);
  return ret;
}
function __wbindgen_is_bigint(arg0) {
  const ret = typeof arg0 === "bigint";
  return ret;
}
function __wbindgen_is_function(arg0) {
  const ret = typeof arg0 === "function";
  return ret;
}
function __wbindgen_is_null(arg0) {
  const ret = arg0 === null;
  return ret;
}
function __wbindgen_is_object(arg0) {
  const val = arg0;
  const ret = typeof val === "object" && val !== null;
  return ret;
}
function __wbindgen_is_string(arg0) {
  const ret = typeof arg0 === "string";
  return ret;
}
function __wbindgen_is_undefined(arg0) {
  const ret = arg0 === void 0;
  return ret;
}
function __wbindgen_jsval_eq(arg0, arg1) {
  const ret = arg0 === arg1;
  return ret;
}
function __wbindgen_jsval_loose_eq(arg0, arg1) {
  const ret = arg0 == arg1;
  return ret;
}
function __wbindgen_memory() {
  const ret = wasm.memory;
  return ret;
}
function __wbindgen_number_get(arg0, arg1) {
  const obj = arg1;
  const ret = typeof obj === "number" ? obj : void 0;
  getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
}
function __wbindgen_number_new(arg0) {
  const ret = arg0;
  return ret;
}
function __wbindgen_string_get(arg0, arg1) {
  const obj = arg1;
  const ret = typeof obj === "string" ? obj : void 0;
  var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  var len1 = WASM_VECTOR_LEN;
  getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}
function __wbindgen_string_new(arg0, arg1) {
  const ret = getStringFromWasm0(arg0, arg1);
  return ret;
}
function __wbindgen_throw(arg0, arg1) {
  throw new Error(getStringFromWasm0(arg0, arg1));
}
function __wbindgen_try_into_number(arg0) {
  let result;
  try {
    result = +arg0;
  } catch (e) {
    result = e;
  }
  const ret = result;
  return ret;
}
const bindings = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  Attachment,
  BackupDecryptionKey,
  BackupKeys,
  BackupSecretsBundle,
  Base64EncodedPkMessage,
  BaseMigrationData,
  CancelInfo,
  CheckCode,
  CollectStrategy,
  CrossSigningBootstrapRequests,
  CrossSigningKeyExport,
  CrossSigningStatus,
  Curve25519PublicKey,
  Curve25519SecretKey,
  DecryptedRoomEvent,
  DecryptionErrorCode,
  DecryptionSettings,
  DehydratedDevice,
  DehydratedDeviceKey,
  DehydratedDevices,
  Device,
  DeviceId,
  DeviceKey,
  DeviceKeyAlgorithm,
  DeviceKeyAlgorithmName,
  DeviceKeyId,
  DeviceKeyName,
  DeviceLists,
  Ecies,
  Ed25519PublicKey,
  Ed25519Signature,
  Emoji,
  EncryptedAttachment,
  EncryptionAlgorithm,
  EncryptionInfo,
  EncryptionSettings,
  EstablishedEcies,
  EventId,
  HistoryVisibility,
  IdentityKeys,
  InboundCreationResult,
  InboundGroupSession,
  KeysBackupRequest,
  KeysClaimRequest,
  KeysQueryRequest,
  KeysUploadRequest,
  LocalTrust,
  LoggerLevel,
  MaybeSignature,
  MegolmDecryptionError,
  MegolmV1BackupKey,
  Migration,
  OlmMachine,
  OtherUserIdentity,
  OutboundCreationResult,
  OwnUserIdentity,
  PickledInboundGroupSession,
  PickledSession,
  PkDecryption,
  PkEncryption,
  PkMessage,
  PutDehydratedDeviceRequest,
  Qr,
  QrCode,
  QrCodeData,
  QrCodeMode,
  QrCodeScan,
  QrState,
  RehydratedDevice,
  RequestType,
  RoomId,
  RoomKeyCounts,
  RoomKeyImportResult,
  RoomKeyInfo,
  RoomKeyWithheldInfo,
  RoomMessageRequest,
  RoomSettings,
  Sas,
  SecretsBundle,
  ServerName,
  ShieldColor,
  ShieldState,
  ShieldStateCode,
  Signature,
  SignatureState,
  SignatureUploadRequest,
  SignatureVerification,
  Signatures,
  StoreHandle,
  ToDeviceRequest,
  Tracing,
  TrustRequirement,
  UploadSigningKeysRequest,
  UserDevices,
  UserId,
  VerificationMethod,
  VerificationRequest,
  VerificationRequestPhase,
  Versions,
  __wbg_String_8f0eb39a4a4c2f66,
  __wbg_Window_b0044ac7db258535,
  __wbg_WorkerGlobalScope_b74cefefc62a37da,
  __wbg_add_883d9432f9188ef2,
  __wbg_add_9338901b80183e0f,
  __wbg_at_7d852dd9f194d43e,
  __wbg_backupkeys_new,
  __wbg_bound_55a8d08e0491e17a,
  __wbg_bound_f2afc3766d4545cf,
  __wbg_buffer_609cc3eee51ed158,
  __wbg_call_672a4d21634d4a24,
  __wbg_call_7cccdd69e0791ae2,
  __wbg_call_833bed5770ea2041,
  __wbg_call_b8adc8b1d0a0d8eb,
  __wbg_clearTimeout_5a54f8841c30079a,
  __wbg_clear_f450db7eeb71163f,
  __wbg_close_26fc2e6856d8567a,
  __wbg_code_cfd8f6868bdaed9b,
  __wbg_continue_c46c11d3dbe1b030,
  __wbg_count_613cb921d67a4f26,
  __wbg_count_ea1a2987dff7759e,
  __wbg_createIndex_873ac48adc772309,
  __wbg_createIndex_fcfd513cf4581834,
  __wbg_createObjectStore_e566459f7161f82f,
  __wbg_crosssigningbootstraprequests_new,
  __wbg_crosssigningkeyexport_new,
  __wbg_crosssigningstatus_new,
  __wbg_crypto_574e78ad8b13b65f,
  __wbg_debug_3cb59063b29f58c1,
  __wbg_debug_f41e47509e8e4e36,
  __wbg_decryptedroomevent_new,
  __wbg_dehydrateddevice_new,
  __wbg_dehydrateddevicekey_new,
  __wbg_deleteObjectStore_3f08ae00cd288224,
  __wbg_delete_200677093b4cf756,
  __wbg_delete_2ecf7cf20900b3a2,
  __wbg_device_new,
  __wbg_deviceid_new,
  __wbg_devicekey_new,
  __wbg_devicekeyid_new,
  __wbg_done_769e5ede4b31c67b,
  __wbg_emoji_new,
  __wbg_encryptioninfo_new,
  __wbg_entries_3265d4158b33e5dc,
  __wbg_entries_c8a90a7ed73e84ce,
  __wbg_error_524f506f44df1645,
  __wbg_error_7534b8e9a36f1ab4,
  __wbg_error_76286673af64a31f,
  __wbg_error_ff4ddaabdfc5dbb3,
  __wbg_from_2a5d3e218e67aa85,
  __wbg_getAllKeys_b11d8835dc4be0e8,
  __wbg_getAll_304e868beec2021f,
  __wbg_getAll_d1e60c13c0073374,
  __wbg_getAll_e6903c610babcd42,
  __wbg_getRandomValues_3d90134a348e46b3,
  __wbg_getRandomValues_b8f5dbd5f3995a9e,
  __wbg_getTime_46267b1c24877e30,
  __wbg_get_67b2ba62fc30de12,
  __wbg_get_8da03f81f6a1111e,
  __wbg_get_93e54e8e166fbcab,
  __wbg_get_b9b93047fe3cf45b,
  __wbg_getwithrefkey_1dc361bd10053bfe,
  __wbg_global_b6f5c73312f62313,
  __wbg_inboundgroupsession_new,
  __wbg_index_e00ca5fff206ee3e,
  __wbg_indexedDB_601ec26c63e333de,
  __wbg_indexedDB_b1f49280282046f8,
  __wbg_indexedDB_f6b47b0dc333fd2f,
  __wbg_info_3b4be85e0a44d2af,
  __wbg_info_3daf2e093e091b66,
  __wbg_instanceof_ArrayBuffer_e14585432e3737fc,
  __wbg_instanceof_Map_f3469ce2244d2430,
  __wbg_instanceof_Promise_935168b8f4b49db3,
  __wbg_instanceof_Uint8Array_17156bcf118086a9,
  __wbg_isArray_a1eab7e0d067391b,
  __wbg_isSafeInteger_343e2beeeece1bb0,
  __wbg_item_c3c26b4103ad5aaf,
  __wbg_iterator_9a24c88df860dc65,
  __wbg_key_29fefecef430db96,
  __wbg_keysbackuprequest_new,
  __wbg_keysclaimrequest_new,
  __wbg_keysqueryrequest_new,
  __wbg_keysuploadrequest_new,
  __wbg_length_238152a0aedbb6e7,
  __wbg_length_a446193dc22c12f8,
  __wbg_length_e2d2a49132c1b256,
  __wbg_lowerBound_1872d19f5bcf83c6,
  __wbg_maybesignature_new,
  __wbg_megolmdecryptionerror_new,
  __wbg_message_5c5d919204d42400,
  __wbg_msCrypto_a61aeb35a24c1329,
  __wbg_name_f2d27098bfd843e7,
  __wbg_new_23a2665fac83c611,
  __wbg_new_31a97dac4f10fab7,
  __wbg_new_405e22f390576ce2,
  __wbg_new_5e0be73521bc8c17,
  __wbg_new_78feb108b6472713,
  __wbg_new_7a91e41fe43b3c92,
  __wbg_new_8a6f238a6ece86ea,
  __wbg_new_a12002a7f91c75be,
  __wbg_new_a239edaa1dc2968f,
  __wbg_newnoargs_105ed471475aaf50,
  __wbg_newwithbyteoffsetandlength_6d34787141015158,
  __wbg_newwithbyteoffsetandlength_d97e637ebe145a9a,
  __wbg_newwithlength_a381634e90c276d4,
  __wbg_newwithlength_ee8e1b95dea9d37c,
  __wbg_newwithmessage_baedba94f03976fd,
  __wbg_next_25feadfc0913fea9,
  __wbg_next_6574e1a8a62d1055,
  __wbg_node_905d3e251edff8a2,
  __wbg_now_2c95c9de01293173,
  __wbg_now_807e54c39636c349,
  __wbg_objectStoreNames_9bb1ab04a7012aaf,
  __wbg_objectStore_21878d46d25b64b6,
  __wbg_oldVersion_e8337811e52861c6,
  __wbg_olmmachine_new,
  __wbg_openCursor_1adef2266972fb45,
  __wbg_openCursor_238e247d18bde2cd,
  __wbg_openCursor_f4b061aa6d804b93,
  __wbg_open_88b1390d99a7c691,
  __wbg_open_e0c0b2993eb596e1,
  __wbg_otheruseridentity_new,
  __wbg_ownuseridentity_new,
  __wbg_parse_def2e24ef1252aff,
  __wbg_performance_7a3ffd0b17f663ad,
  __wbg_pickledinboundgroupsession_unwrap,
  __wbg_pickledsession_unwrap,
  __wbg_process_dc0fbacc7c1c06f7,
  __wbg_push_737cfc8c1432c2c6,
  __wbg_put_066faa31a6a88f5b,
  __wbg_putdehydrateddevicerequest_new,
  __wbg_qr_new,
  __wbg_queueMicrotask_97d92b4fcc8a61c5,
  __wbg_queueMicrotask_d3219def82552485,
  __wbg_randomFillSync_ac0988aba3254290,
  __wbg_readyState_4013cfdf4f22afb0,
  __wbg_rehydrateddevice_new,
  __wbg_require_60cc747a6bc5215a,
  __wbg_resolve_4851785c9c5f573d,
  __wbg_result_f29afabdf2c05826,
  __wbg_roomid_unwrap,
  __wbg_roomkeycounts_new,
  __wbg_roomkeyimportresult_new,
  __wbg_roomkeyinfo_new,
  __wbg_roomkeywithheldinfo_new,
  __wbg_roommessagerequest_new,
  __wbg_roomsettings_new,
  __wbg_sas_new,
  __wbg_secretsbundle_new,
  __wbg_setTimeout_db2dbaeefb6f39c7,
  __wbg_set_37837023f3d740e8,
  __wbg_set_3f1d0b984ed272ed,
  __wbg_set_65595bdd868b3009,
  __wbg_set_6775f73144c2ef27,
  __wbg_set_8fc6bf8a5b1071d1,
  __wbg_set_wasm,
  __wbg_setonabort_3bf4db6614fa98e9,
  __wbg_setonblocked_aebf64bd39f1eca8,
  __wbg_setoncomplete_4d19df0dadb7c4d4,
  __wbg_setonerror_b0d9d723b8fddbbb,
  __wbg_setonerror_d7e3056cc6e56085,
  __wbg_setonsuccess_afa464ee777a396d,
  __wbg_setonupgradeneeded_fcf7ce4f2eb0cb5f,
  __wbg_setonversionchange_6ee07fa49ee1e3a5,
  __wbg_setunique_dd24c422aa05df89,
  __wbg_signatures_new,
  __wbg_signatureuploadrequest_new,
  __wbg_signatureverification_new,
  __wbg_stack_0ed75d68575b0f3c,
  __wbg_static_accessor_GLOBAL_88a902d13a557d07,
  __wbg_static_accessor_GLOBAL_THIS_56578be7e9f832b0,
  __wbg_static_accessor_SELF_37c5d418e4bf5819,
  __wbg_static_accessor_WINDOW_5de37043a91a9c40,
  __wbg_storehandle_new,
  __wbg_stringify_f7ed6987935b4a24,
  __wbg_subarray_aa9065fa9dc5df96,
  __wbg_target_0a62d9d79a2a1ede,
  __wbg_then_44b73946d2fb3e7d,
  __wbg_then_48b406749878a531,
  __wbg_todevicerequest_new,
  __wbg_transaction_babc423936946a37,
  __wbg_transaction_d6d07c3c9963c49e,
  __wbg_transaction_e713aa7b07ccaedd,
  __wbg_update_acd72607f506872a,
  __wbg_userdevices_new,
  __wbg_userid_new,
  __wbg_userid_unwrap,
  __wbg_value_68c4e9a54bb7fd5e,
  __wbg_value_cd1ffa7b1ab794f1,
  __wbg_values_53465c57fc8cd691,
  __wbg_verificationrequest_new,
  __wbg_version_a70a33e5bbc6d6db,
  __wbg_versions_c01dfd4722a88165,
  __wbg_warn_4ca3906c248c47c4,
  __wbg_warn_6ce7b8525f302b4c,
  __wbindgen_as_number,
  __wbindgen_bigint_from_i64,
  __wbindgen_bigint_from_u64,
  __wbindgen_bigint_get_as_i64,
  __wbindgen_boolean_get,
  __wbindgen_cb_drop,
  __wbindgen_closure_wrapper1087,
  __wbindgen_closure_wrapper2244,
  __wbindgen_closure_wrapper5515,
  __wbindgen_closure_wrapper7008,
  __wbindgen_closure_wrapper7010,
  __wbindgen_debug_string,
  __wbindgen_error_new,
  __wbindgen_in,
  __wbindgen_init_externref_table,
  __wbindgen_is_array,
  __wbindgen_is_bigint,
  __wbindgen_is_function,
  __wbindgen_is_null,
  __wbindgen_is_object,
  __wbindgen_is_string,
  __wbindgen_is_undefined,
  __wbindgen_jsval_eq,
  __wbindgen_jsval_loose_eq,
  __wbindgen_memory,
  __wbindgen_number_get,
  __wbindgen_number_new,
  __wbindgen_string_get,
  __wbindgen_string_new,
  __wbindgen_throw,
  __wbindgen_try_into_number,
  getVersions,
  start
}, Symbol.toStringTag, { value: "Module" }));
const defaultURL = new URL("/assets/matrix_sdk_crypto_wasm_bg-Mlrn556D.wasm", import.meta.url);
__wbg_set_wasm(
  new Proxy(
    {},
    {
      get() {
        throw new Error(
          "@matrix-org/matrix-sdk-crypto-wasm was used before it was initialized. Call `initAsync` first."
        );
      }
    }
  )
);
let modPromise = null;
async function loadModuleAsync(url) {
  const { instance } = await WebAssembly.instantiateStreaming(fetch(url), {
    // @ts-expect-error: The bindings don't exactly match the 'ExportValue' type
    "./matrix_sdk_crypto_wasm_bg.js": bindings
  });
  __wbg_set_wasm(instance.exports);
  instance.exports.__wbindgen_start();
}
async function initAsync(url = defaultURL) {
  if (!modPromise) modPromise = loadModuleAsync(url);
  await modPromise;
}
var escaped = /[\\\"\x00-\x1F]/g;
var escapes = {};
for (var i = 0; i < 32; ++i) {
  escapes[String.fromCharCode(i)] = "\\U" + ("0000" + i.toString(16)).slice(-4).toUpperCase();
}
escapes["\b"] = "\\b";
escapes["	"] = "\\t";
escapes["\n"] = "\\n";
escapes["\f"] = "\\f";
escapes["\r"] = "\\r";
escapes['"'] = '\\"';
escapes["\\"] = "\\\\";
function escapeString(value) {
  escaped.lastIndex = 0;
  return value.replace(escaped, function(c) {
    return escapes[c];
  });
}
function stringify(value) {
  switch (typeof value) {
    case "string":
      return '"' + escapeString(value) + '"';
    case "number":
      return isFinite(value) ? value : "null";
    case "boolean":
      return value;
    case "object":
      if (value === null) {
        return "null";
      }
      if (Array.isArray(value)) {
        return stringifyArray(value);
      }
      return stringifyObject(value);
    default:
      throw new Error("Cannot stringify: " + typeof value);
  }
}
function stringifyArray(array) {
  var sep = "[";
  var result = "";
  for (var i = 0; i < array.length; ++i) {
    result += sep;
    sep = ",";
    result += stringify(array[i]);
  }
  if (sep != ",") {
    return "[]";
  } else {
    return result + "]";
  }
}
function stringifyObject(object) {
  var sep = "{";
  var result = "";
  var keys = Object.keys(object);
  keys.sort();
  for (var i = 0; i < keys.length; ++i) {
    var key = keys[i];
    result += sep + '"' + escapeString(key) + '":';
    sep = ",";
    result += stringify(object[key]);
  }
  if (sep != ",") {
    return "{}";
  } else {
    return result + "}";
  }
}
var anotherJson = { stringify };
const anotherjson = /* @__PURE__ */ getDefaultExportFromCjs(anotherJson);
class RoomEncryptor {
  /**
   * @param olmMachine - The rust-sdk's OlmMachine
   * @param keyClaimManager - Our KeyClaimManager, which manages the queue of one-time-key claim requests
   * @param outgoingRequestManager - The OutgoingRequestManager, which manages the queue of outgoing requests.
   * @param room - The room we want to encrypt for
   * @param encryptionSettings - body of the m.room.encryption event currently in force in this room
   */
  constructor(olmMachine, keyClaimManager, outgoingRequestManager, room, encryptionSettings) {
    this.olmMachine = olmMachine;
    this.keyClaimManager = keyClaimManager;
    this.outgoingRequestManager = outgoingRequestManager;
    this.room = room;
    this.encryptionSettings = encryptionSettings;
    _defineProperty(this, "prefixedLogger", void 0);
    _defineProperty(this, "lazyLoadedMembersResolved", false);
    _defineProperty(this, "currentEncryptionPromise", Promise.resolve());
    this.prefixedLogger = logger.getChild("[".concat(room.roomId, " encryption]"));
    var members = room.getJoinedMembers();
    this.olmMachine.updateTrackedUsers(members.map((u) => new UserId(u.userId))).catch((e) => this.prefixedLogger.error("Error initializing tracked users", e));
  }
  /**
   * Handle a new `m.room.encryption` event in this room
   *
   * @param config - The content of the encryption event
   */
  onCryptoEvent(config) {
    if (JSON.stringify(this.encryptionSettings) != JSON.stringify(config)) {
      throw new Error("Cannot reconfigure an active RoomEncryptor");
    }
  }
  /**
   * Handle a new `m.room.member` event in this room
   *
   * @param member - new membership state
   */
  onRoomMembership(member) {
    if (member.membership == KnownMembership.Join || member.membership == KnownMembership.Invite && this.room.shouldEncryptForInvitedMembers()) {
      this.olmMachine.updateTrackedUsers([new UserId(member.userId)]).catch((e) => {
        this.prefixedLogger.error("Unable to update tracked users", e);
      });
    }
  }
  /**
   * Prepare to encrypt events in this room.
   *
   * This ensures that we have a megolm session ready to use and that we have shared its key with all the devices
   * in the room.
   * @param globalBlacklistUnverifiedDevices - When `true`, and `deviceIsolationMode` is `AllDevicesIsolationMode`,
   * will not send encrypted messages to unverified devices.
   * Ignored when `deviceIsolationMode` is `OnlySignedDevicesIsolationMode`.
   * @param deviceIsolationMode - The device isolation mode. See {@link DeviceIsolationMode}.
   */
  prepareForEncryption(globalBlacklistUnverifiedDevices, deviceIsolationMode) {
    var _this = this;
    return _asyncToGenerator(function* () {
      yield _this.encryptEvent(null, globalBlacklistUnverifiedDevices, deviceIsolationMode);
    })();
  }
  /**
   * Encrypt an event for this room, or prepare for encryption.
   *
   * This will ensure that we have a megolm session for this room, share it with the devices in the room, and
   * then, if an event is provided, encrypt it using the session.
   *
   * @param event - Event to be encrypted, or null if only preparing for encryption (in which case we will pre-share the room key).
   * @param globalBlacklistUnverifiedDevices - When `true`, and `deviceIsolationMode` is `AllDevicesIsolationMode`,
   * will not send encrypted messages to unverified devices.
   * Ignored when `deviceIsolationMode` is `OnlySignedDevicesIsolationMode`.
   * @param deviceIsolationMode - The device isolation mode. See {@link DeviceIsolationMode}.
   */
  encryptEvent(event, globalBlacklistUnverifiedDevices, deviceIsolationMode) {
    var _event$getTxnId, _this2 = this;
    var logger2 = new LogSpan(this.prefixedLogger, event ? (_event$getTxnId = event.getTxnId()) !== null && _event$getTxnId !== void 0 ? _event$getTxnId : "" : "prepareForEncryption");
    var prom = this.currentEncryptionPromise.catch(() => {
    }).then(/* @__PURE__ */ _asyncToGenerator(function* () {
      yield logDuration(logger2, "ensureEncryptionSession", /* @__PURE__ */ _asyncToGenerator(function* () {
        yield _this2.ensureEncryptionSession(logger2, globalBlacklistUnverifiedDevices, deviceIsolationMode);
      }));
      if (event) {
        yield logDuration(logger2, "encryptEventInner", /* @__PURE__ */ _asyncToGenerator(function* () {
          yield _this2.encryptEventInner(logger2, event);
        }));
      }
    }));
    this.currentEncryptionPromise = prom;
    return prom;
  }
  /**
   * Prepare to encrypt events in this room.
   *
   * This ensures that we have a megolm session ready to use and that we have shared its key with all the devices
   * in the room.
   *
   * @param logger - a place to write diagnostics to
   * @param globalBlacklistUnverifiedDevices - When `true`, and `deviceIsolationMode` is `AllDevicesIsolationMode`,
   * will not send encrypted messages to unverified devices.
   * Ignored when `deviceIsolationMode` is `OnlySignedDevicesIsolationMode`.
   * @param deviceIsolationMode - The device isolation mode. See {@link DeviceIsolationMode}.
   */
  ensureEncryptionSession(logger2, globalBlacklistUnverifiedDevices, deviceIsolationMode) {
    var _this3 = this;
    return _asyncToGenerator(function* () {
      if (_this3.encryptionSettings.algorithm !== "m.megolm.v1.aes-sha2") {
        throw new Error("Cannot encrypt in ".concat(_this3.room.roomId, " for unsupported algorithm '").concat(_this3.encryptionSettings.algorithm, "'"));
      }
      logger2.debug("Starting encryption");
      var members = yield _this3.room.getEncryptionTargetMembers();
      if (!_this3.lazyLoadedMembersResolved) {
        yield logDuration(_this3.prefixedLogger, "loadMembersIfNeeded: updateTrackedUsers", /* @__PURE__ */ _asyncToGenerator(function* () {
          yield _this3.olmMachine.updateTrackedUsers(members.map((u) => new UserId(u.userId)));
        }));
        logger2.debug("Updated tracked users");
        _this3.lazyLoadedMembersResolved = true;
        logger2.debug("Processing outgoing requests");
        yield logDuration(_this3.prefixedLogger, "doProcessOutgoingRequests", /* @__PURE__ */ _asyncToGenerator(function* () {
          yield _this3.outgoingRequestManager.doProcessOutgoingRequests();
        }));
      } else {
        logger2.debug("Processing outgoing requests in background");
        _this3.outgoingRequestManager.doProcessOutgoingRequests();
      }
      logger2.debug("Encrypting for users (shouldEncryptForInvitedMembers: ".concat(_this3.room.shouldEncryptForInvitedMembers(), "):"), members.map((u) => "".concat(u.userId, " (").concat(u.membership, ")")));
      var userList = members.map((u) => new UserId(u.userId));
      yield logDuration(_this3.prefixedLogger, "ensureSessionsForUsers", /* @__PURE__ */ _asyncToGenerator(function* () {
        yield _this3.keyClaimManager.ensureSessionsForUsers(logger2, userList);
      }));
      var rustEncryptionSettings = new EncryptionSettings();
      rustEncryptionSettings.historyVisibility = toRustHistoryVisibility(_this3.room.getHistoryVisibility());
      rustEncryptionSettings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
      if (typeof _this3.encryptionSettings.rotation_period_ms === "number") {
        rustEncryptionSettings.rotationPeriod = BigInt(_this3.encryptionSettings.rotation_period_ms * 1e3);
      }
      if (typeof _this3.encryptionSettings.rotation_period_msgs === "number") {
        rustEncryptionSettings.rotationPeriodMessages = BigInt(_this3.encryptionSettings.rotation_period_msgs);
      }
      switch (deviceIsolationMode.kind) {
        case DeviceIsolationModeKind.AllDevicesIsolationMode:
          {
            var _this3$room$getBlackl;
            var onlyAllowTrustedDevices = (_this3$room$getBlackl = _this3.room.getBlacklistUnverifiedDevices()) !== null && _this3$room$getBlackl !== void 0 ? _this3$room$getBlackl : globalBlacklistUnverifiedDevices;
            rustEncryptionSettings.sharingStrategy = CollectStrategy.deviceBasedStrategy(onlyAllowTrustedDevices, deviceIsolationMode.errorOnVerifiedUserProblems);
          }
          break;
        case DeviceIsolationModeKind.OnlySignedDevicesIsolationMode:
          rustEncryptionSettings.sharingStrategy = CollectStrategy.identityBasedStrategy();
          break;
      }
      yield logDuration(_this3.prefixedLogger, "shareRoomKey", /* @__PURE__ */ _asyncToGenerator(function* () {
        var shareMessages = yield _this3.olmMachine.shareRoomKey(
          new RoomId(_this3.room.roomId),
          // safe to pass without cloning, as it's not reused here (before or after)
          userList,
          rustEncryptionSettings
        );
        if (shareMessages) {
          for (var m of shareMessages) {
            yield _this3.outgoingRequestManager.outgoingRequestProcessor.makeOutgoingRequest(m);
          }
        }
      }));
    })();
  }
  /**
   * Discard any existing group session for this room
   */
  forceDiscardSession() {
    var _this4 = this;
    return _asyncToGenerator(function* () {
      var r = yield _this4.olmMachine.invalidateGroupSession(new RoomId(_this4.room.roomId));
      if (r) {
        _this4.prefixedLogger.info("Discarded existing group session");
      }
    })();
  }
  encryptEventInner(logger2, event) {
    var _this5 = this;
    return _asyncToGenerator(function* () {
      logger2.debug("Encrypting actual message content");
      var encryptedContent = yield _this5.olmMachine.encryptRoomEvent(new RoomId(_this5.room.roomId), event.getType(), JSON.stringify(event.getContent()));
      event.makeEncrypted(EventType.RoomMessageEncrypted, JSON.parse(encryptedContent), _this5.olmMachine.identityKeys.curve25519.toBase64(), _this5.olmMachine.identityKeys.ed25519.toBase64());
      logger2.debug("Encrypted event successfully");
    })();
  }
}
function toRustHistoryVisibility(visibility) {
  switch (visibility) {
    case HistoryVisibility$1.Invited:
      return HistoryVisibility.Invited;
    case HistoryVisibility$1.Joined:
      return HistoryVisibility.Joined;
    case HistoryVisibility$1.Shared:
      return HistoryVisibility.Shared;
    case HistoryVisibility$1.WorldReadable:
      return HistoryVisibility.WorldReadable;
  }
}
var UnstablePrefix = "/_matrix/client/unstable/org.matrix.msc3814.v1";
var SECRET_STORAGE_NAME = "org.matrix.msc3814";
var DEHYDRATION_INTERVAL = 7 * 24 * 60 * 60 * 1e3;
class DehydratedDeviceManager extends TypedEventEmitter {
  constructor(logger2, olmMachine, http, outgoingRequestProcessor, secretStorage) {
    super();
    this.logger = logger2;
    this.olmMachine = olmMachine;
    this.http = http;
    this.outgoingRequestProcessor = outgoingRequestProcessor;
    this.secretStorage = secretStorage;
    _defineProperty(this, "intervalId", void 0);
  }
  cacheKey(key) {
    var _this = this;
    return _asyncToGenerator(function* () {
      yield _this.olmMachine.dehydratedDevices().saveDehydratedDeviceKey(key);
      _this.emit(CryptoEvent.DehydrationKeyCached);
    })();
  }
  /**
   * Return whether the server supports dehydrated devices.
   */
  isSupported() {
    var _this2 = this;
    return _asyncToGenerator(function* () {
      try {
        yield _this2.http.authedRequest(Method.Get, "/dehydrated_device", void 0, void 0, {
          prefix: UnstablePrefix
        });
      } catch (error) {
        var err = error;
        if (err.errcode === "M_UNRECOGNIZED") {
          return false;
        } else if (err.errcode === "M_NOT_FOUND") {
          return true;
        }
        throw error;
      }
      return true;
    })();
  }
  /**
   * Start using device dehydration.
   *
   * - Rehydrates a dehydrated device, if one is available and `opts.rehydrate`
   *   is `true`.
   * - Creates a new dehydration key, if necessary, and stores it in Secret
   *   Storage.
   *   - If `opts.createNewKey` is set to true, always creates a new key.
   *   - If a dehydration key is not available, creates a new one.
   * - Creates a new dehydrated device, and schedules periodically creating
   *   new dehydrated devices.
   *
   * @param opts - options for device dehydration. For backwards compatibility
   *     with old code, a boolean can be given here, which will be treated as
   *     the `createNewKey` option. However, this is deprecated.
   */
  start() {
    var _arguments = arguments, _this3 = this;
    return _asyncToGenerator(function* () {
      var opts = _arguments.length > 0 && _arguments[0] !== void 0 ? _arguments[0] : {};
      if (typeof opts === "boolean") {
        opts = {
          createNewKey: opts
        };
      }
      if (opts.onlyIfKeyCached && !(yield _this3.olmMachine.dehydratedDevices().getDehydratedDeviceKey())) {
        return;
      }
      _this3.stop();
      if (opts.rehydrate !== false) {
        try {
          yield _this3.rehydrateDeviceIfAvailable();
        } catch (e) {
          _this3.logger.info("dehydration: Error rehydrating device:", e);
          _this3.emit(CryptoEvent.RehydrationError, e.message);
        }
      }
      if (opts.createNewKey) {
        yield _this3.resetKey();
      }
      yield _this3.scheduleDeviceDehydration();
    })();
  }
  /**
   * Return whether the dehydration key is stored in Secret Storage.
   */
  isKeyStored() {
    var _this4 = this;
    return _asyncToGenerator(function* () {
      return Boolean(yield _this4.secretStorage.isStored(SECRET_STORAGE_NAME));
    })();
  }
  /**
   * Reset the dehydration key.
   *
   * Creates a new key and stores it in secret storage.
   *
   * @returns The newly-generated key.
   */
  resetKey() {
    var _this5 = this;
    return _asyncToGenerator(function* () {
      var key = DehydratedDeviceKey.createRandomKey();
      yield _this5.secretStorage.store(SECRET_STORAGE_NAME, key.toBase64());
      yield _this5.cacheKey(key);
      return key;
    })();
  }
  /**
   * Get and cache the encryption key from secret storage.
   *
   * If `create` is `true`, creates a new key if no existing key is present.
   *
   * @returns the key, if available, or `null` if no key is available
   */
  getKey(create) {
    var _this6 = this;
    return _asyncToGenerator(function* () {
      var cachedKey = yield _this6.olmMachine.dehydratedDevices().getDehydratedDeviceKey();
      if (cachedKey) return cachedKey;
      var keyB64 = yield _this6.secretStorage.get(SECRET_STORAGE_NAME);
      if (keyB64 === void 0) {
        if (!create) {
          return null;
        }
        return yield _this6.resetKey();
      }
      var bytes = decodeBase64(keyB64);
      try {
        var key = DehydratedDeviceKey.createKeyFromArray(bytes);
        yield _this6.cacheKey(key);
        return key;
      } finally {
        bytes.fill(0);
      }
    })();
  }
  /**
   * Rehydrate the dehydrated device stored on the server.
   *
   * Checks if there is a dehydrated device on the server.  If so, rehydrates
   * the device and processes the to-device events.
   *
   * Returns whether or not a dehydrated device was found.
   */
  rehydrateDeviceIfAvailable() {
    var _this7 = this;
    return _asyncToGenerator(function* () {
      var key = yield _this7.getKey(false);
      if (!key) {
        return false;
      }
      var dehydratedDeviceResp;
      try {
        dehydratedDeviceResp = yield _this7.http.authedRequest(Method.Get, "/dehydrated_device", void 0, void 0, {
          prefix: UnstablePrefix
        });
      } catch (error) {
        var err = error;
        if (err.errcode === "M_NOT_FOUND" || err.errcode === "M_UNRECOGNIZED") {
          _this7.logger.info("dehydration: No dehydrated device");
          return false;
        }
        throw err;
      }
      _this7.logger.info("dehydration: dehydrated device found");
      _this7.emit(CryptoEvent.RehydrationStarted);
      var rehydratedDevice = yield _this7.olmMachine.dehydratedDevices().rehydrate(key, new DeviceId(dehydratedDeviceResp.device_id), JSON.stringify(dehydratedDeviceResp.device_data));
      _this7.logger.info("dehydration: device rehydrated");
      var nextBatch = void 0;
      var toDeviceCount = 0;
      var roomKeyCount = 0;
      var path = encodeUri("/dehydrated_device/$device_id/events", {
        $device_id: dehydratedDeviceResp.device_id
      });
      while (true) {
        var eventResp = yield _this7.http.authedRequest(Method.Post, path, void 0, nextBatch ? {
          next_batch: nextBatch
        } : {}, {
          prefix: UnstablePrefix
        });
        if (eventResp.events.length === 0) {
          break;
        }
        toDeviceCount += eventResp.events.length;
        nextBatch = eventResp.next_batch;
        var roomKeyInfos = yield rehydratedDevice.receiveEvents(JSON.stringify(eventResp.events));
        roomKeyCount += roomKeyInfos.length;
        _this7.emit(CryptoEvent.RehydrationProgress, roomKeyCount, toDeviceCount);
      }
      _this7.logger.info("dehydration: received ".concat(roomKeyCount, " room keys from ").concat(toDeviceCount, " to-device events"));
      _this7.emit(CryptoEvent.RehydrationCompleted);
      return true;
    })();
  }
  /**
   * Creates and uploads a new dehydrated device.
   *
   * Creates and stores a new key in secret storage if none is available.
   */
  createAndUploadDehydratedDevice() {
    var _this8 = this;
    return _asyncToGenerator(function* () {
      var key = yield _this8.getKey(true);
      var dehydratedDevice = yield _this8.olmMachine.dehydratedDevices().create();
      _this8.emit(CryptoEvent.DehydratedDeviceCreated);
      var request = yield dehydratedDevice.keysForUpload("Dehydrated device", key);
      yield _this8.outgoingRequestProcessor.makeOutgoingRequest(request);
      _this8.emit(CryptoEvent.DehydratedDeviceUploaded);
      _this8.logger.info("dehydration: uploaded device");
    })();
  }
  /**
   * Schedule periodic creation of dehydrated devices.
   */
  scheduleDeviceDehydration() {
    var _this9 = this;
    return _asyncToGenerator(function* () {
      _this9.stop();
      yield _this9.createAndUploadDehydratedDevice();
      _this9.intervalId = setInterval(() => {
        _this9.createAndUploadDehydratedDevice().catch((error) => {
          _this9.emit(CryptoEvent.DehydratedDeviceRotationError, error.message);
          _this9.logger.error("Error creating dehydrated device:", error);
        });
      }, DEHYDRATION_INTERVAL);
    })();
  }
  /**
   * Stop the dehydrated device manager.
   *
   * Cancels any scheduled dehydration tasks.
   */
  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = void 0;
    }
  }
  /**
   * Delete the current dehydrated device and stop the dehydrated device manager.
   */
  delete() {
    var _this10 = this;
    return _asyncToGenerator(function* () {
      _this10.stop();
      try {
        yield _this10.http.authedRequest(Method.Delete, "/dehydrated_device", void 0, {}, {
          prefix: UnstablePrefix
        });
      } catch (error) {
        var err = error;
        if (err.errcode === "M_UNRECOGNIZED") {
          return;
        } else if (err.errcode === "M_NOT_FOUND") {
          return;
        }
        throw error;
      }
    })();
  }
}
function ownKeys$2(e, r) {
  var t = Object.keys(e);
  if (Object.getOwnPropertySymbols) {
    var o = Object.getOwnPropertySymbols(e);
    r && (o = o.filter(function(r2) {
      return Object.getOwnPropertyDescriptor(e, r2).enumerable;
    })), t.push.apply(t, o);
  }
  return t;
}
function _objectSpread$2(e) {
  for (var r = 1; r < arguments.length; r++) {
    var t = null != arguments[r] ? arguments[r] : {};
    r % 2 ? ownKeys$2(Object(t), true).forEach(function(r2) {
      _defineProperty(e, r2, t[r2]);
    }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys$2(Object(t)).forEach(function(r2) {
      Object.defineProperty(e, r2, Object.getOwnPropertyDescriptor(t, r2));
    });
  }
  return e;
}
class OutgoingRequestProcessor {
  constructor(olmMachine, http) {
    this.olmMachine = olmMachine;
    this.http = http;
  }
  makeOutgoingRequest(msg, uiaCallback) {
    var _this = this;
    return _asyncToGenerator(function* () {
      var resp;
      if (msg instanceof KeysUploadRequest) {
        resp = yield _this.requestWithRetry(Method.Post, "/_matrix/client/v3/keys/upload", {}, msg.body);
      } else if (msg instanceof KeysQueryRequest) {
        resp = yield _this.requestWithRetry(Method.Post, "/_matrix/client/v3/keys/query", {}, msg.body);
      } else if (msg instanceof KeysClaimRequest) {
        resp = yield _this.requestWithRetry(Method.Post, "/_matrix/client/v3/keys/claim", {}, msg.body);
      } else if (msg instanceof SignatureUploadRequest) {
        resp = yield _this.requestWithRetry(Method.Post, "/_matrix/client/v3/keys/signatures/upload", {}, msg.body);
      } else if (msg instanceof KeysBackupRequest) {
        resp = yield _this.requestWithRetry(Method.Put, "/_matrix/client/v3/room_keys/keys", {
          version: msg.version
        }, msg.body);
      } else if (msg instanceof ToDeviceRequest) {
        resp = yield _this.sendToDeviceRequest(msg);
      } else if (msg instanceof RoomMessageRequest) {
        var path = "/_matrix/client/v3/rooms/".concat(encodeURIComponent(msg.room_id), "/send/") + "".concat(encodeURIComponent(msg.event_type), "/").concat(encodeURIComponent(msg.txn_id));
        resp = yield _this.requestWithRetry(Method.Put, path, {}, msg.body);
      } else if (msg instanceof UploadSigningKeysRequest) {
        yield _this.makeRequestWithUIA(Method.Post, "/_matrix/client/v3/keys/device_signing/upload", {}, msg.body, uiaCallback);
        return;
      } else if (msg instanceof PutDehydratedDeviceRequest) {
        var _path = UnstablePrefix + "/dehydrated_device";
        yield _this.rawJsonRequest(Method.Put, _path, {}, msg.body);
        return;
      } else {
        logger.warn("Unsupported outgoing message", Object.getPrototypeOf(msg));
        resp = "";
      }
      if (msg.id) {
        try {
          yield logDuration(logger, "Mark Request as sent ".concat(msg.type), /* @__PURE__ */ _asyncToGenerator(function* () {
            yield _this.olmMachine.markRequestAsSent(msg.id, msg.type, resp);
          }));
        } catch (e) {
          if (e instanceof Error && (e.message === "Attempt to use a moved value" || e.message === "null pointer passed to rust")) {
            logger.log("Ignoring error '".concat(e.message, "': client is likely shutting down"));
          } else {
            throw e;
          }
        }
      } else {
        logger.trace("Outgoing request type:".concat(msg.type, " does not have an ID"));
      }
    })();
  }
  /**
   * Send the HTTP request for a `ToDeviceRequest`
   *
   * @param request - request to send
   * @returns JSON-serialized body of the response, if successful
   */
  sendToDeviceRequest(request) {
    var _this2 = this;
    return _asyncToGenerator(function* () {
      var parsedBody = JSON.parse(request.body);
      var messageList = [];
      for (var [userId, perUserMessages] of Object.entries(parsedBody.messages)) {
        for (var [deviceId, message] of Object.entries(perUserMessages)) {
          messageList.push("".concat(userId, "/").concat(deviceId, " (msgid ").concat(message[ToDeviceMessageId], ")"));
        }
      }
      logger.info("Sending batch of to-device messages. type=".concat(request.event_type, " txnid=").concat(request.txn_id), messageList);
      var path = "/_matrix/client/v3/sendToDevice/".concat(encodeURIComponent(request.event_type), "/") + encodeURIComponent(request.txn_id);
      return yield _this2.requestWithRetry(Method.Put, path, {}, request.body);
    })();
  }
  makeRequestWithUIA(method, path, queryParams, body, uiaCallback) {
    var _this3 = this;
    return _asyncToGenerator(function* () {
      if (!uiaCallback) {
        return yield _this3.requestWithRetry(method, path, queryParams, body);
      }
      var parsedBody = JSON.parse(body);
      var makeRequest = /* @__PURE__ */ function() {
        var _ref2 = _asyncToGenerator(function* (auth) {
          var newBody = _objectSpread$2({}, parsedBody);
          if (auth !== null) {
            newBody.auth = auth;
          }
          var resp2 = yield _this3.requestWithRetry(method, path, queryParams, JSON.stringify(newBody));
          return JSON.parse(resp2);
        });
        return function makeRequest2(_x) {
          return _ref2.apply(this, arguments);
        };
      }();
      var resp = yield uiaCallback(makeRequest);
      return JSON.stringify(resp);
    })();
  }
  requestWithRetry(method, path, queryParams, body) {
    var _this4 = this;
    return _asyncToGenerator(function* () {
      var currentRetryCount = 0;
      while (true) {
        try {
          return yield _this4.rawJsonRequest(method, path, queryParams, body);
        } catch (e) {
          currentRetryCount++;
          var backoff = calculateRetryBackoff(e, currentRetryCount, true);
          if (backoff < 0) {
            throw e;
          }
          yield sleep(backoff);
        }
      }
    })();
  }
  rawJsonRequest(method, path, queryParams, body) {
    var _this5 = this;
    return _asyncToGenerator(function* () {
      var opts = {
        // inhibit the JSON stringification and parsing within HttpApi.
        json: false,
        // nevertheless, we are sending, and accept, JSON.
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        // we use the full prefix
        prefix: "",
        // We set a timeout of 60 seconds to guard against requests getting stuck forever and wedging the
        // request loop (cf https://github.com/element-hq/element-web/issues/29534).
        //
        // (XXX: should we do this in the whole of the js-sdk?)
        localTimeoutMs: 6e4
      };
      return yield _this5.http.authedRequest(method, path, queryParams, body, opts);
    })();
  }
}
class KeyClaimManager {
  constructor(olmMachine, outgoingRequestProcessor) {
    this.olmMachine = olmMachine;
    this.outgoingRequestProcessor = outgoingRequestProcessor;
    _defineProperty(this, "currentClaimPromise", void 0);
    _defineProperty(this, "stopped", false);
    this.currentClaimPromise = Promise.resolve();
  }
  /**
   * Tell the KeyClaimManager to immediately stop processing requests.
   *
   * Any further calls, and any still in the queue, will fail with an error.
   */
  stop() {
    this.stopped = true;
  }
  /**
   * Given a list of users, attempt to ensure that we have Olm Sessions active with each of their devices
   *
   * If we don't have an active olm session, we will claim a one-time key and start one.
   * @param logger - logger to use
   * @param userList - list of userIDs to claim
   */
  ensureSessionsForUsers(logger2, userList) {
    var prom = this.currentClaimPromise.catch(() => {
    }).then(() => this.ensureSessionsForUsersInner(logger2, userList));
    this.currentClaimPromise = prom;
    return prom;
  }
  ensureSessionsForUsersInner(logger2, userList) {
    var _this = this;
    return _asyncToGenerator(function* () {
      if (_this.stopped) {
        throw new Error("Cannot ensure Olm sessions: shutting down");
      }
      logger2.info("Checking for missing Olm sessions");
      var claimRequest = yield _this.olmMachine.getMissingSessions(userList.map((u) => u.clone()));
      if (claimRequest) {
        logger2.info("Making /keys/claim request");
        yield _this.outgoingRequestProcessor.makeOutgoingRequest(claimRequest);
      }
      logger2.info("Olm sessions prepared");
    })();
  }
}
function rustDeviceToJsDevice(device, userId) {
  var keys = /* @__PURE__ */ new Map();
  for (var [keyId, key] of device.keys.entries()) {
    keys.set(keyId.toString(), key.toBase64());
  }
  var verified = DeviceVerification.Unverified;
  if (device.isBlacklisted()) {
    verified = DeviceVerification.Blocked;
  } else if (device.isVerified()) {
    verified = DeviceVerification.Verified;
  }
  var signatures = /* @__PURE__ */ new Map();
  var mayBeSignatureMap = device.signatures.get(userId);
  if (mayBeSignatureMap) {
    var convertedSignatures = /* @__PURE__ */ new Map();
    for (var [_key, value] of mayBeSignatureMap.entries()) {
      if (value.isValid() && value.signature) {
        convertedSignatures.set(_key, value.signature.toBase64());
      }
    }
    signatures.set(userId.toString(), convertedSignatures);
  }
  var rustAlgorithms = device.algorithms;
  var algorithms = /* @__PURE__ */ new Set();
  rustAlgorithms.forEach((algorithm) => {
    switch (algorithm) {
      case EncryptionAlgorithm.MegolmV1AesSha2:
        algorithms.add("m.megolm.v1.aes-sha2");
        break;
      case EncryptionAlgorithm.OlmV1Curve25519AesSha2:
      default:
        algorithms.add("m.olm.v1.curve25519-aes-sha2");
        break;
    }
  });
  return new Device$1({
    deviceId: device.deviceId.toString(),
    userId: userId.toString(),
    keys,
    algorithms: Array.from(algorithms),
    verified,
    signatures,
    displayName: device.displayName,
    dehydrated: device.isDehydrated
  });
}
function deviceKeysToDeviceMap(deviceKeys) {
  return new Map(Object.entries(deviceKeys).map((_ref) => {
    var [deviceId, device] = _ref;
    return [deviceId, downloadDeviceToJsDevice(device)];
  }));
}
function downloadDeviceToJsDevice(device) {
  var _device$unsigned;
  var keys = new Map(Object.entries(device.keys));
  var displayName = (_device$unsigned = device.unsigned) === null || _device$unsigned === void 0 ? void 0 : _device$unsigned.device_display_name;
  var signatures = /* @__PURE__ */ new Map();
  if (device.signatures) {
    for (var userId in device.signatures) {
      signatures.set(userId, new Map(Object.entries(device.signatures[userId])));
    }
  }
  return new Device$1({
    deviceId: device.device_id,
    userId: device.user_id,
    keys,
    algorithms: device.algorithms,
    verified: DeviceVerification.Unverified,
    signatures,
    displayName
  });
}
class CrossSigningIdentity {
  constructor(olmMachine, outgoingRequestProcessor, secretStorage) {
    this.olmMachine = olmMachine;
    this.outgoingRequestProcessor = outgoingRequestProcessor;
    this.secretStorage = secretStorage;
  }
  /**
   * Initialise our cross-signing keys by creating new keys if they do not exist, and uploading to the server
   */
  bootstrapCrossSigning(opts) {
    var _this = this;
    return _asyncToGenerator(function* () {
      if (opts.setupNewCrossSigning) {
        yield _this.resetCrossSigning(opts.authUploadDeviceSigningKeys);
        return;
      }
      var olmDeviceStatus = yield _this.olmMachine.crossSigningStatus();
      var masterKeyFromSecretStorage = yield _this.secretStorage.get("m.cross_signing.master");
      var selfSigningKeyFromSecretStorage = yield _this.secretStorage.get("m.cross_signing.self_signing");
      var userSigningKeyFromSecretStorage = yield _this.secretStorage.get("m.cross_signing.user_signing");
      var privateKeysInSecretStorage = Boolean(masterKeyFromSecretStorage && selfSigningKeyFromSecretStorage && userSigningKeyFromSecretStorage);
      var olmDeviceHasKeys = olmDeviceStatus.hasMaster && olmDeviceStatus.hasUserSigning && olmDeviceStatus.hasSelfSigning;
      logger.log("bootstrapCrossSigning: starting", {
        setupNewCrossSigning: opts.setupNewCrossSigning,
        olmDeviceHasMaster: olmDeviceStatus.hasMaster,
        olmDeviceHasUserSigning: olmDeviceStatus.hasUserSigning,
        olmDeviceHasSelfSigning: olmDeviceStatus.hasSelfSigning,
        privateKeysInSecretStorage
      });
      if (olmDeviceHasKeys) {
        if (!(yield _this.secretStorage.hasKey())) {
          logger.warn("bootstrapCrossSigning: Olm device has private keys, but secret storage is not yet set up; doing nothing for now.");
        } else if (!privateKeysInSecretStorage) {
          logger.log("bootstrapCrossSigning: Olm device has private keys: exporting to secret storage");
          yield _this.exportCrossSigningKeysToStorage();
        } else {
          logger.log("bootstrapCrossSigning: Olm device has private keys and they are saved in secret storage; doing nothing");
        }
      } else {
        if (privateKeysInSecretStorage) {
          logger.log("bootstrapCrossSigning: Cross-signing private keys not found locally, but they are available in secret storage, reading storage and caching locally");
          var status = yield _this.olmMachine.importCrossSigningKeys(masterKeyFromSecretStorage, selfSigningKeyFromSecretStorage, userSigningKeyFromSecretStorage);
          if (!status.hasMaster || !status.hasSelfSigning || !status.hasUserSigning) {
            throw new Error("importCrossSigningKeys failed to import the keys");
          }
          var device = yield _this.olmMachine.getDevice(_this.olmMachine.userId, _this.olmMachine.deviceId);
          try {
            var request = yield device.verify();
            yield _this.outgoingRequestProcessor.makeOutgoingRequest(request);
          } finally {
            device.free();
          }
        } else {
          logger.log("bootstrapCrossSigning: Cross-signing private keys not found locally or in secret storage, creating new keys");
          yield _this.resetCrossSigning(opts.authUploadDeviceSigningKeys);
        }
      }
      logger.log("bootstrapCrossSigning: complete");
    })();
  }
  /** Reset our cross-signing keys
   *
   * This method will:
   *   * Tell the OlmMachine to create new keys
   *   * Upload the new public keys and the device signature to the server
   *   * Upload the private keys to SSSS, if it is set up
   */
  resetCrossSigning(authUploadDeviceSigningKeys) {
    var _this2 = this;
    return _asyncToGenerator(function* () {
      var outgoingRequests = yield _this2.olmMachine.bootstrapCrossSigning(true);
      if (!(yield _this2.secretStorage.hasKey())) {
        logger.warn("resetCrossSigning: Secret storage is not yet set up; not exporting keys to secret storage yet.");
      } else {
        logger.log("resetCrossSigning: exporting private keys to secret storage");
        yield _this2.exportCrossSigningKeysToStorage();
      }
      logger.log("resetCrossSigning: publishing public keys to server");
      for (var req of [outgoingRequests.uploadKeysRequest, outgoingRequests.uploadSigningKeysRequest, outgoingRequests.uploadSignaturesRequest]) {
        if (req) {
          yield _this2.outgoingRequestProcessor.makeOutgoingRequest(req, authUploadDeviceSigningKeys);
        }
      }
    })();
  }
  /**
   * Extract the cross-signing keys from the olm machine and save them to secret storage, if it is configured
   *
   * (If secret storage is *not* configured, we assume that the export will happen when it is set up)
   */
  exportCrossSigningKeysToStorage() {
    var _this3 = this;
    return _asyncToGenerator(function* () {
      var exported = yield _this3.olmMachine.exportCrossSigningKeys();
      if (exported !== null && exported !== void 0 && exported.masterKey) {
        yield _this3.secretStorage.store("m.cross_signing.master", exported.masterKey);
      } else {
        logger.error("Cannot export MSK to secret storage, private key unknown");
      }
      if (exported !== null && exported !== void 0 && exported.self_signing_key) {
        yield _this3.secretStorage.store("m.cross_signing.self_signing", exported.self_signing_key);
      } else {
        logger.error("Cannot export SSK to secret storage, private key unknown");
      }
      if (exported !== null && exported !== void 0 && exported.userSigningKey) {
        yield _this3.secretStorage.store("m.cross_signing.user_signing", exported.userSigningKey);
      } else {
        logger.error("Cannot export USK to secret storage, private key unknown");
      }
    })();
  }
}
function secretStorageContainsCrossSigningKeys(_x) {
  return _secretStorageContainsCrossSigningKeys.apply(this, arguments);
}
function _secretStorageContainsCrossSigningKeys() {
  _secretStorageContainsCrossSigningKeys = _asyncToGenerator(function* (secretStorage) {
    return secretStorageCanAccessSecrets(secretStorage, ["m.cross_signing.master", "m.cross_signing.user_signing", "m.cross_signing.self_signing"]);
  });
  return _secretStorageContainsCrossSigningKeys.apply(this, arguments);
}
function secretStorageCanAccessSecrets(_x2, _x3) {
  return _secretStorageCanAccessSecrets.apply(this, arguments);
}
function _secretStorageCanAccessSecrets() {
  _secretStorageCanAccessSecrets = _asyncToGenerator(function* (secretStorage, secretNames) {
    var defaultKeyId = yield secretStorage.getDefaultKeyId();
    if (!defaultKeyId) return false;
    for (var secretName of secretNames) {
      var record = (yield secretStorage.isStored(secretName)) || {};
      if (!(defaultKeyId in record)) return false;
    }
    return true;
  });
  return _secretStorageCanAccessSecrets.apply(this, arguments);
}
class RustVerificationRequest extends TypedEventEmitter {
  /**
   * Construct a new RustVerificationRequest to wrap the rust-level `VerificationRequest`.
   *
   * @param olmMachine - The `OlmMachine` from the underlying rust crypto sdk.
   * @param inner - VerificationRequest from the Rust SDK.
   * @param outgoingRequestProcessor - `OutgoingRequestProcessor` to use for making outgoing HTTP requests.
   * @param supportedVerificationMethods - Verification methods to use when `accept()` is called.
   */
  constructor(olmMachine, inner, outgoingRequestProcessor, supportedVerificationMethods) {
    super();
    this.olmMachine = olmMachine;
    this.inner = inner;
    this.outgoingRequestProcessor = outgoingRequestProcessor;
    this.supportedVerificationMethods = supportedVerificationMethods;
    _defineProperty(this, "reEmitter", void 0);
    _defineProperty(this, "_accepting", false);
    _defineProperty(this, "_cancelling", false);
    _defineProperty(this, "_verifier", void 0);
    this.reEmitter = new TypedReEmitter(this);
    var weakThis = new WeakRef(this);
    inner.registerChangesCallback(/* @__PURE__ */ _asyncToGenerator(function* () {
      var _weakThis$deref;
      return (_weakThis$deref = weakThis.deref()) === null || _weakThis$deref === void 0 ? void 0 : _weakThis$deref.onChange();
    }));
  }
  /**
   * Hook which is called when the underlying rust class notifies us that there has been a change.
   */
  onChange() {
    var verification = this.inner.getVerification();
    if (verification instanceof Sas) {
      if (this._verifier === void 0 || this._verifier instanceof RustQrCodeVerifier) {
        this.setVerifier(new RustSASVerifier(verification, this, this.outgoingRequestProcessor));
      } else if (this._verifier instanceof RustSASVerifier) {
        this._verifier.replaceInner(verification);
      }
    } else if (verification instanceof Qr && this._verifier === void 0) {
      this.setVerifier(new RustQrCodeVerifier(verification, this.outgoingRequestProcessor));
    }
    this.emit(VerificationRequestEvent.Change);
  }
  setVerifier(verifier) {
    if (this._verifier) {
      this.reEmitter.stopReEmitting(this._verifier, [VerificationRequestEvent.Change]);
    }
    this._verifier = verifier;
    this.reEmitter.reEmit(this._verifier, [VerificationRequestEvent.Change]);
  }
  /**
   * Unique ID for this verification request.
   *
   * An ID isn't assigned until the first message is sent, so this may be `undefined` in the early phases.
   */
  get transactionId() {
    return this.inner.flowId;
  }
  /**
   * For an in-room verification, the ID of the room.
   *
   * For to-device verifications, `undefined`.
   */
  get roomId() {
    var _this$inner$roomId;
    return (_this$inner$roomId = this.inner.roomId) === null || _this$inner$roomId === void 0 ? void 0 : _this$inner$roomId.toString();
  }
  /**
   * True if this request was initiated by the local client.
   *
   * For in-room verifications, the initiator is who sent the `m.key.verification.request` event.
   * For to-device verifications, the initiator is who sent the `m.key.verification.start` event.
   */
  get initiatedByMe() {
    return this.inner.weStarted();
  }
  /** The user id of the other party in this request */
  get otherUserId() {
    return this.inner.otherUserId.toString();
  }
  /** For verifications via to-device messages: the ID of the other device. Otherwise, undefined. */
  get otherDeviceId() {
    var _this$inner$otherDevi;
    return (_this$inner$otherDevi = this.inner.otherDeviceId) === null || _this$inner$otherDevi === void 0 ? void 0 : _this$inner$otherDevi.toString();
  }
  /** Get the other device involved in the verification, if it is known */
  getOtherDevice() {
    var _this = this;
    return _asyncToGenerator(function* () {
      var otherDeviceId = _this.inner.otherDeviceId;
      if (!otherDeviceId) {
        return void 0;
      }
      return yield _this.olmMachine.getDevice(_this.inner.otherUserId, otherDeviceId, 5);
    })();
  }
  /** True if the other party in this request is one of this user's own devices. */
  get isSelfVerification() {
    return this.inner.isSelfVerification();
  }
  /** current phase of the request. */
  get phase() {
    var phase = this.inner.phase();
    switch (phase) {
      case VerificationRequestPhase.Created:
      case VerificationRequestPhase.Requested:
        return VerificationPhase.Requested;
      case VerificationRequestPhase.Ready:
        return this._accepting ? VerificationPhase.Requested : VerificationPhase.Ready;
      case VerificationRequestPhase.Transitioned:
        if (!this._verifier) {
          throw new Error("VerificationRequest: inner phase == Transitioned but no verifier!");
        }
        return this._verifier.verificationPhase;
      case VerificationRequestPhase.Done:
        return VerificationPhase.Done;
      case VerificationRequestPhase.Cancelled:
        return VerificationPhase.Cancelled;
    }
    throw new Error("Unknown verification phase ".concat(phase));
  }
  /** True if the request has sent its initial event and needs more events to complete
   * (ie it is in phase `Requested`, `Ready` or `Started`).
   */
  get pending() {
    if (this.inner.isPassive()) return false;
    var phase = this.phase;
    return phase !== VerificationPhase.Done && phase !== VerificationPhase.Cancelled;
  }
  /**
   * True if we have started the process of sending an `m.key.verification.ready` (but have not necessarily received
   * the remote echo which causes a transition to {@link VerificationPhase.Ready}.
   */
  get accepting() {
    return this._accepting;
  }
  /**
   * True if we have started the process of sending an `m.key.verification.cancel` (but have not necessarily received
   * the remote echo which causes a transition to {@link VerificationPhase.Cancelled}).
   */
  get declining() {
    return this._cancelling;
  }
  /**
   * The remaining number of ms before the request will be automatically cancelled.
   *
   * `null` indicates that there is no timeout
   */
  get timeout() {
    return this.inner.timeRemainingMillis();
  }
  /** once the phase is Started (and !initiatedByMe) or Ready: common methods supported by both sides */
  get methods() {
    throw new Error("not implemented");
  }
  /** the method picked in the .start event */
  get chosenMethod() {
    if (this.phase !== VerificationPhase.Started) return null;
    var verification = this.inner.getVerification();
    if (verification instanceof Sas) {
      return VerificationMethod$1.Sas;
    } else if (verification instanceof Qr) {
      return VerificationMethod$1.Reciprocate;
    } else {
      return null;
    }
  }
  /**
   * Checks whether the other party supports a given verification method.
   * This is useful when setting up the QR code UI, as it is somewhat asymmetrical:
   * if the other party supports SCAN_QR, we should show a QR code in the UI, and vice versa.
   * For methods that need to be supported by both ends, use the `methods` property.
   *
   * @param method - the method to check
   * @returns true if the other party said they supported the method
   */
  otherPartySupportsMethod(method) {
    var theirMethods = this.inner.theirSupportedMethods;
    if (theirMethods === void 0) {
      return false;
    }
    var requiredMethod = verificationMethodsByIdentifier[method];
    return theirMethods.some((m) => m === requiredMethod);
  }
  /**
   * Accepts the request, sending a .ready event to the other party
   *
   * @returns Promise which resolves when the event has been sent.
   */
  accept() {
    var _this2 = this;
    return _asyncToGenerator(function* () {
      if (_this2.inner.phase() !== VerificationRequestPhase.Requested || _this2._accepting) {
        throw new Error("Cannot accept a verification request in phase ".concat(_this2.phase));
      }
      _this2._accepting = true;
      try {
        var req = _this2.inner.acceptWithMethods(_this2.supportedVerificationMethods.map(verificationMethodIdentifierToMethod));
        if (req) {
          yield _this2.outgoingRequestProcessor.makeOutgoingRequest(req);
        }
      } finally {
        _this2._accepting = false;
      }
      _this2.emit(VerificationRequestEvent.Change);
    })();
  }
  /**
   * Cancels the request, sending a cancellation to the other party
   *
   * @param params - Details for the cancellation, including `reason` (defaults to "User declined"), and `code`
   *    (defaults to `m.user`).
   *
   * @returns Promise which resolves when the event has been sent.
   */
  cancel(params) {
    var _this3 = this;
    return _asyncToGenerator(function* () {
      if (_this3._cancelling) {
        return;
      }
      _this3._cancelling = true;
      try {
        var req = _this3.inner.cancel();
        if (req) {
          yield _this3.outgoingRequestProcessor.makeOutgoingRequest(req);
        }
      } finally {
        _this3._cancelling = false;
      }
    })();
  }
  /**
   * Create a {@link Verifier} to do this verification via a particular method.
   *
   * If a verifier has already been created for this request, returns that verifier.
   *
   * This does *not* send the `m.key.verification.start` event - to do so, call {@link Verifier#verifier} on the
   * returned verifier.
   *
   * If no previous events have been sent, pass in `targetDevice` to set who to direct this request to.
   *
   * @param method - the name of the verification method to use.
   * @param targetDevice - details of where to send the request to.
   *
   * @returns The verifier which will do the actual verification.
   */
  beginKeyVerification(method, targetDevice) {
    throw new Error("not implemented");
  }
  /**
   * Send an `m.key.verification.start` event to start verification via a particular method.
   *
   * Implementation of {@link Crypto.VerificationRequest#startVerification}.
   *
   * @param method - the name of the verification method to use.
   */
  startVerification(method) {
    var _this4 = this;
    return _asyncToGenerator(function* () {
      if (method !== VerificationMethod$1.Sas) {
        throw new Error("Unsupported verification method ".concat(method));
      }
      if (!(yield _this4.getOtherDevice())) {
        throw new Error("startVerification(): other device is unknown");
      }
      var res = yield _this4.inner.startSas();
      if (res) {
        var [, req] = res;
        yield _this4.outgoingRequestProcessor.makeOutgoingRequest(req);
      }
      if (!_this4._verifier) {
        throw new Error("Still no verifier after startSas() call");
      }
      return _this4._verifier;
    })();
  }
  /**
   * Start a QR code verification by providing a scanned QR code for this verification flow.
   *
   * Implementation of {@link Crypto.VerificationRequest#scanQRCode}.
   *
   * @param qrCodeData - the decoded QR code.
   * @returns A verifier; call `.verify()` on it to wait for the other side to complete the verification flow.
   */
  scanQRCode(uint8Array) {
    var _this5 = this;
    return _asyncToGenerator(function* () {
      var scan = QrCodeScan.fromBytes(uint8Array);
      var verifier = yield _this5.inner.scanQrCode(scan);
      if (!_this5._verifier) {
        throw new Error("Still no verifier after scanQrCode() call");
      }
      var req = verifier.reciprocate();
      if (req) {
        yield _this5.outgoingRequestProcessor.makeOutgoingRequest(req);
      }
      return _this5._verifier;
    })();
  }
  /**
   * The verifier which is doing the actual verification, once the method has been established.
   * Only defined when the `phase` is Started.
   */
  get verifier() {
    return this.phase === VerificationPhase.Started ? this._verifier : void 0;
  }
  /**
   * Stub implementation of {@link Crypto.VerificationRequest#getQRCodeBytes}.
   */
  getQRCodeBytes() {
    throw new Error("getQRCodeBytes() unsupported in Rust Crypto; use generateQRCode() instead.");
  }
  /**
   * Generate the data for a QR code allowing the other device to verify this one, if it supports it.
   *
   * Implementation of {@link Crypto.VerificationRequest#generateQRCode}.
   */
  generateQRCode() {
    var _this6 = this;
    return _asyncToGenerator(function* () {
      if (!(yield _this6.getOtherDevice())) {
        throw new Error("generateQRCode(): other device is unknown");
      }
      var innerVerifier = yield _this6.inner.generateQrCode();
      if (!innerVerifier) return;
      return innerVerifier.toBytes();
    })();
  }
  /**
   * If this request has been cancelled, the cancellation code (e.g `m.user`) which is responsible for cancelling
   * this verification.
   */
  get cancellationCode() {
    var _this$inner$cancelInf, _this$inner$cancelInf2;
    return (_this$inner$cancelInf = (_this$inner$cancelInf2 = this.inner.cancelInfo) === null || _this$inner$cancelInf2 === void 0 ? void 0 : _this$inner$cancelInf2.cancelCode()) !== null && _this$inner$cancelInf !== void 0 ? _this$inner$cancelInf : null;
  }
  /**
   * The id of the user that cancelled the request.
   *
   * Only defined when phase is Cancelled
   */
  get cancellingUserId() {
    var cancelInfo = this.inner.cancelInfo;
    if (!cancelInfo) {
      return void 0;
    } else if (cancelInfo.cancelledbyUs()) {
      return this.olmMachine.userId.toString();
    } else {
      return this.inner.otherUserId.toString();
    }
  }
}
class BaseRustVerifer extends TypedEventEmitter {
  constructor(inner, outgoingRequestProcessor) {
    super();
    this.inner = inner;
    this.outgoingRequestProcessor = outgoingRequestProcessor;
    _defineProperty(this, "completionDeferred", void 0);
    this.completionDeferred = defer();
    var weakThis = new WeakRef(this);
    inner.registerChangesCallback(/* @__PURE__ */ _asyncToGenerator(function* () {
      var _weakThis$deref2;
      return (_weakThis$deref2 = weakThis.deref()) === null || _weakThis$deref2 === void 0 ? void 0 : _weakThis$deref2.onChange();
    }));
    this.completionDeferred.promise.catch(() => null);
  }
  /**
   * Hook which is called when the underlying rust class notifies us that there has been a change.
   *
   * Can be overridden by subclasses to see if we can notify the application about an update. The overriding method
   * must call `super.onChange()`.
   */
  onChange() {
    if (this.inner.isDone()) {
      this.completionDeferred.resolve(void 0);
    } else if (this.inner.isCancelled()) {
      var cancelInfo = this.inner.cancelInfo();
      this.completionDeferred.reject(new Error("Verification cancelled by ".concat(cancelInfo.cancelledbyUs() ? "us" : "them", " with code ").concat(cancelInfo.cancelCode(), ": ").concat(cancelInfo.reason())));
    }
    this.emit(VerificationRequestEvent.Change);
  }
  /**
   * Returns true if the verification has been cancelled, either by us or the other side.
   */
  get hasBeenCancelled() {
    return this.inner.isCancelled();
  }
  /**
   * The ID of the other user in the verification process.
   */
  get userId() {
    return this.inner.otherUserId.toString();
  }
  /**
   * Cancel a verification.
   *
   * We will send an `m.key.verification.cancel` if the verification is still in flight. The verification promise
   * will reject, and a {@link Crypto.VerifierEvent#Cancel} will be emitted.
   *
   * @param e - the reason for the cancellation.
   */
  cancel(e) {
    var req = this.inner.cancel();
    if (req) {
      this.outgoingRequestProcessor.makeOutgoingRequest(req);
    }
  }
  /**
   * Get the details for an SAS verification, if one is in progress
   *
   * Returns `null`, unless this verifier is for a SAS-based verification and we are waiting for the user to confirm
   * the SAS matches.
   */
  getShowSasCallbacks() {
    return null;
  }
  /**
   * Get the details for reciprocating QR code verification, if one is in progress
   *
   * Returns `null`, unless this verifier is for reciprocating a QR-code-based verification (ie, the other user has
   * already scanned our QR code), and we are waiting for the user to confirm.
   */
  getReciprocateQrCodeCallbacks() {
    return null;
  }
}
class RustQrCodeVerifier extends BaseRustVerifer {
  constructor(inner, outgoingRequestProcessor) {
    super(inner, outgoingRequestProcessor);
    _defineProperty(this, "callbacks", null);
  }
  onChange() {
    if (this.callbacks === null && this.inner.hasBeenScanned()) {
      this.callbacks = {
        confirm: () => {
          this.confirmScanning();
        },
        cancel: () => this.cancel()
      };
    }
    super.onChange();
  }
  /**
   * Start the key verification, if it has not already been started.
   *
   * @returns Promise which resolves when the verification has completed, or rejects if the verification is cancelled
   *    or times out.
   */
  verify() {
    var _this7 = this;
    return _asyncToGenerator(function* () {
      if (_this7.callbacks !== null) {
        _this7.emit(VerifierEvent.ShowReciprocateQr, _this7.callbacks);
      }
      yield _this7.completionDeferred.promise;
    })();
  }
  /**
   * Calculate an appropriate VerificationPhase for a VerificationRequest where this is the verifier.
   *
   * This is abnormally complicated because a rust-side QR Code verifier can span several verification phases.
   */
  get verificationPhase() {
    switch (this.inner.state()) {
      case QrState.Created:
        return VerificationPhase.Ready;
      case QrState.Scanned:
        return VerificationPhase.Started;
      case QrState.Confirmed:
        return VerificationPhase.Started;
      case QrState.Reciprocated:
        return VerificationPhase.Started;
      case QrState.Done:
        return VerificationPhase.Done;
      case QrState.Cancelled:
        return VerificationPhase.Cancelled;
      default:
        throw new Error("Unknown qr code state ".concat(this.inner.state()));
    }
  }
  /**
   * Get the details for reciprocating QR code verification, if one is in progress
   *
   * Returns `null`, unless this verifier is for reciprocating a QR-code-based verification (ie, the other user has
   * already scanned our QR code), and we are waiting for the user to confirm.
   */
  getReciprocateQrCodeCallbacks() {
    return this.callbacks;
  }
  confirmScanning() {
    var _this8 = this;
    return _asyncToGenerator(function* () {
      var req = _this8.inner.confirmScanning();
      if (req) {
        yield _this8.outgoingRequestProcessor.makeOutgoingRequest(req);
      }
    })();
  }
}
class RustSASVerifier extends BaseRustVerifer {
  constructor(inner, _verificationRequest, outgoingRequestProcessor) {
    super(inner, outgoingRequestProcessor);
    _defineProperty(this, "callbacks", null);
  }
  /**
   * Start the key verification, if it has not already been started.
   *
   * This means sending a `m.key.verification.start` if we are the first responder, or a `m.key.verification.accept`
   * if the other side has already sent a start event.
   *
   * @returns Promise which resolves when the verification has completed, or rejects if the verification is cancelled
   *    or times out.
   */
  verify() {
    var _this9 = this;
    return _asyncToGenerator(function* () {
      yield _this9.sendAccept();
      yield _this9.completionDeferred.promise;
    })();
  }
  /**
   * Send the accept or start event, if it hasn't already been sent
   */
  sendAccept() {
    var _this10 = this;
    return _asyncToGenerator(function* () {
      var req = _this10.inner.accept();
      if (req) {
        yield _this10.outgoingRequestProcessor.makeOutgoingRequest(req);
      }
    })();
  }
  /** if we can now show the callbacks, do so */
  onChange() {
    var _this11 = this;
    super.onChange();
    if (this.callbacks === null) {
      var emoji = this.inner.emoji();
      var decimal = this.inner.decimals();
      if (emoji === void 0 && decimal === void 0) {
        return;
      }
      var sas = {};
      if (emoji) {
        sas.emoji = emoji.map((e) => [e.symbol, e.description]);
      }
      if (decimal) {
        sas.decimal = [decimal[0], decimal[1], decimal[2]];
      }
      this.callbacks = {
        sas,
        confirm: function() {
          var _confirm = _asyncToGenerator(function* () {
            var requests = yield _this11.inner.confirm();
            for (var m of requests) {
              yield _this11.outgoingRequestProcessor.makeOutgoingRequest(m);
            }
          });
          function confirm() {
            return _confirm.apply(this, arguments);
          }
          return confirm;
        }(),
        mismatch: () => {
          var request = this.inner.cancelWithCode("m.mismatched_sas");
          if (request) {
            this.outgoingRequestProcessor.makeOutgoingRequest(request);
          }
        },
        cancel: () => {
          var request = this.inner.cancelWithCode("m.user");
          if (request) {
            this.outgoingRequestProcessor.makeOutgoingRequest(request);
          }
        }
      };
      this.emit(VerifierEvent.ShowSas, this.callbacks);
    }
  }
  /**
   * Calculate an appropriate VerificationPhase for a VerificationRequest where this is the verifier.
   */
  get verificationPhase() {
    return VerificationPhase.Started;
  }
  /**
   * Get the details for an SAS verification, if one is in progress
   *
   * Returns `null`, unless this verifier is for a SAS-based verification and we are waiting for the user to confirm
   * the SAS matches.
   */
  getShowSasCallbacks() {
    return this.callbacks;
  }
  /**
   * Replace the inner Rust verifier with a different one.
   *
   * @param inner - the new Rust verifier
   * @internal
   */
  replaceInner(inner) {
    if (this.inner != inner) {
      this.inner = inner;
      var weakThis = new WeakRef(this);
      inner.registerChangesCallback(/* @__PURE__ */ _asyncToGenerator(function* () {
        var _weakThis$deref3;
        return (_weakThis$deref3 = weakThis.deref()) === null || _weakThis$deref3 === void 0 ? void 0 : _weakThis$deref3.onChange();
      }));
      this.sendAccept();
      this.onChange();
    }
  }
}
var verificationMethodsByIdentifier = {
  [VerificationMethod$1.Sas]: VerificationMethod.SasV1,
  [VerificationMethod$1.ScanQrCode]: VerificationMethod.QrCodeScanV1,
  [VerificationMethod$1.ShowQrCode]: VerificationMethod.QrCodeShowV1,
  [VerificationMethod$1.Reciprocate]: VerificationMethod.ReciprocateV1
};
function verificationMethodIdentifierToMethod(method) {
  var meth = verificationMethodsByIdentifier[method];
  if (meth === void 0) {
    throw new Error("Unknown verification method ".concat(method));
  }
  return meth;
}
function isVerificationEvent(event) {
  switch (event.getType()) {
    case EventType.KeyVerificationCancel:
    case EventType.KeyVerificationDone:
    case EventType.KeyVerificationMac:
    case EventType.KeyVerificationStart:
    case EventType.KeyVerificationKey:
    case EventType.KeyVerificationReady:
    case EventType.KeyVerificationAccept:
      return true;
    case EventType.RoomMessage:
      return event.getContent().msgtype === MsgType.KeyVerificationRequest;
    default:
      return false;
  }
}
class RustBackupManager extends TypedEventEmitter {
  constructor(olmMachine, http, outgoingRequestProcessor) {
    super();
    this.olmMachine = olmMachine;
    this.http = http;
    this.outgoingRequestProcessor = outgoingRequestProcessor;
    _defineProperty(this, "checkedForBackup", false);
    _defineProperty(this, "serverBackupInfo", void 0);
    _defineProperty(this, "activeBackupVersion", null);
    _defineProperty(this, "stopped", false);
    _defineProperty(this, "backupKeysLoopRunning", false);
    _defineProperty(this, "keyBackupCheckInProgress", null);
  }
  /**
   * Tells the RustBackupManager to stop.
   * The RustBackupManager is scheduling background uploads of keys to the backup, this
   * call allows to cancel the process when the client is stoppped.
   */
  stop() {
    this.stopped = true;
  }
  /**
   * Get the backup version we are currently backing up to, if any
   */
  getActiveBackupVersion() {
    var _this = this;
    return _asyncToGenerator(function* () {
      if (!(yield _this.olmMachine.isBackupEnabled())) return null;
      return _this.activeBackupVersion;
    })();
  }
  /**
   * Return the details of the latest backup on the server, when we last checked.
   *
   * This normally returns a cached value, but if we haven't yet made a request to the server, it will fire one off.
   * It will always return the details of the active backup if key backup is enabled.
   *
   * If there was no backup on the server, `null`. If our attempt to check resulted in an error, `undefined`.
   */
  getServerBackupInfo() {
    var _this2 = this;
    return _asyncToGenerator(function* () {
      yield _this2.checkKeyBackupAndEnable(false);
      return _this2.serverBackupInfo;
    })();
  }
  /**
   * Determine if a key backup can be trusted.
   *
   * @param info - key backup info dict from {@link CryptoApi.getKeyBackupInfo}.
   */
  isKeyBackupTrusted(info) {
    var _this3 = this;
    return _asyncToGenerator(function* () {
      var signatureVerification = yield _this3.olmMachine.verifyBackup(info);
      var backupKeys = yield _this3.olmMachine.getBackupKeys();
      var decryptionKey = backupKeys === null || backupKeys === void 0 ? void 0 : backupKeys.decryptionKey;
      var backupMatchesSavedPrivateKey = !!decryptionKey && backupInfoMatchesBackupDecryptionKey(info, decryptionKey);
      return {
        matchesDecryptionKey: backupMatchesSavedPrivateKey,
        trusted: signatureVerification.trusted()
      };
    })();
  }
  /**
   * Re-check the key backup and enable/disable it as appropriate.
   *
   * @param force - whether we should force a re-check even if one has already happened.
   */
  checkKeyBackupAndEnable(force) {
    if (!force && this.checkedForBackup) {
      return Promise.resolve(null);
    }
    if (!this.keyBackupCheckInProgress) {
      this.keyBackupCheckInProgress = this.doCheckKeyBackup().finally(() => {
        this.keyBackupCheckInProgress = null;
      });
    }
    return this.keyBackupCheckInProgress;
  }
  /**
   * Handles a backup secret received event and store it if it matches the current backup version.
   *
   * @param secret - The secret as received from a `m.secret.send` event for secret `m.megolm_backup.v1`.
   * @returns true if the secret is valid and has been stored, false otherwise.
   */
  handleBackupSecretReceived(secret) {
    var _this4 = this;
    return _asyncToGenerator(function* () {
      var _latestBackupInfo;
      var latestBackupInfo;
      try {
        latestBackupInfo = yield _this4.requestKeyBackupVersion();
      } catch (e) {
        logger.warn("handleBackupSecretReceived: Error checking for latest key backup", e);
        return false;
      }
      if (!((_latestBackupInfo = latestBackupInfo) !== null && _latestBackupInfo !== void 0 && _latestBackupInfo.version)) {
        logger.warn("handleBackupSecretReceived: Received a backup decryption key, but there is no trusted server-side key backup");
        return false;
      }
      try {
        var backupDecryptionKey = BackupDecryptionKey.fromBase64(secret);
        var privateKeyMatches = backupInfoMatchesBackupDecryptionKey(latestBackupInfo, backupDecryptionKey);
        if (!privateKeyMatches) {
          logger.warn("handleBackupSecretReceived: Private decryption key does not match the public key of the current remote backup.");
          return false;
        }
        logger.info("handleBackupSecretReceived: A valid backup decryption key has been received and stored in cache.");
        yield _this4.saveBackupDecryptionKey(backupDecryptionKey, latestBackupInfo.version);
        return true;
      } catch (e) {
        logger.warn("handleBackupSecretReceived: Invalid backup decryption key", e);
      }
      return false;
    })();
  }
  saveBackupDecryptionKey(backupDecryptionKey, version) {
    var _this5 = this;
    return _asyncToGenerator(function* () {
      yield _this5.olmMachine.saveBackupDecryptionKey(backupDecryptionKey, version);
      _this5.emit(CryptoEvent.KeyBackupDecryptionKeyCached, version);
    })();
  }
  /**
   * Import a list of room keys previously exported by exportRoomKeys
   *
   * @param keys - a list of session export objects
   * @param opts - options object
   * @returns a promise which resolves once the keys have been imported
   */
  importRoomKeys(keys, opts) {
    var _this6 = this;
    return _asyncToGenerator(function* () {
      yield _this6.importRoomKeysAsJson(JSON.stringify(keys), opts);
    })();
  }
  /**
   * Import a list of room keys previously exported by exportRoomKeysAsJson
   *
   * @param jsonKeys - a JSON string encoding a list of session export objects,
   *    each of which is an IMegolmSessionData
   * @param opts - options object
   * @returns a promise which resolves once the keys have been imported
   */
  importRoomKeysAsJson(jsonKeys, opts) {
    var _this7 = this;
    return _asyncToGenerator(function* () {
      yield _this7.olmMachine.importExportedRoomKeys(jsonKeys, (progress, total) => {
        var _opts$progressCallbac;
        var importOpt = {
          total: Number(total),
          successes: Number(progress),
          stage: ImportRoomKeyStage.LoadKeys,
          failures: 0
        };
        opts === null || opts === void 0 || (_opts$progressCallbac = opts.progressCallback) === null || _opts$progressCallbac === void 0 || _opts$progressCallbac.call(opts, importOpt);
      });
    })();
  }
  /**
   * Implementation of {@link CryptoBackend#importBackedUpRoomKeys}.
   */
  importBackedUpRoomKeys(keys, backupVersion, opts) {
    var _this8 = this;
    return _asyncToGenerator(function* () {
      var keysByRoom = /* @__PURE__ */ new Map();
      for (var key of keys) {
        var roomId = new RoomId(key.room_id);
        if (!keysByRoom.has(roomId)) {
          keysByRoom.set(roomId, /* @__PURE__ */ new Map());
        }
        keysByRoom.get(roomId).set(key.session_id, key);
      }
      yield _this8.olmMachine.importBackedUpRoomKeys(keysByRoom, (progress, total, failures) => {
        var _opts$progressCallbac2;
        var importOpt = {
          total: Number(total),
          successes: Number(progress),
          stage: ImportRoomKeyStage.LoadKeys,
          failures: Number(failures)
        };
        opts === null || opts === void 0 || (_opts$progressCallbac2 = opts.progressCallback) === null || _opts$progressCallbac2 === void 0 || _opts$progressCallbac2.call(opts, importOpt);
      }, backupVersion);
    })();
  }
  /** Helper for `checkKeyBackup` */
  doCheckKeyBackup() {
    var _this9 = this;
    return _asyncToGenerator(function* () {
      logger.log("Checking key backup status...");
      var backupInfo;
      try {
        backupInfo = yield _this9.requestKeyBackupVersion();
      } catch (e) {
        logger.warn("Error checking for active key backup", e);
        _this9.serverBackupInfo = void 0;
        return null;
      }
      _this9.checkedForBackup = true;
      if (backupInfo && !backupInfo.version) {
        logger.warn("active backup lacks a useful 'version'; ignoring it");
        backupInfo = void 0;
      }
      _this9.serverBackupInfo = backupInfo;
      var activeVersion = yield _this9.getActiveBackupVersion();
      if (!backupInfo) {
        if (activeVersion !== null) {
          logger.log("No key backup present on server: disabling key backup");
          yield _this9.disableKeyBackup();
        } else {
          logger.log("No key backup present on server: not enabling key backup");
        }
        return null;
      }
      var trustInfo = yield _this9.isKeyBackupTrusted(backupInfo);
      if (!trustInfo.matchesDecryptionKey && !trustInfo.trusted) {
        if (activeVersion !== null) {
          logger.log("Key backup present on server but not trusted: disabling key backup");
          yield _this9.disableKeyBackup();
        } else {
          logger.log("Key backup present on server but not trusted: not enabling key backup");
        }
      } else {
        if (activeVersion === null) {
          logger.log("Found usable key backup v".concat(backupInfo.version, ": enabling key backups"));
          yield _this9.enableKeyBackup(backupInfo);
        } else if (activeVersion !== backupInfo.version) {
          logger.log("On backup version ".concat(activeVersion, " but found version ").concat(backupInfo.version, ": switching."));
          yield _this9.disableKeyBackup();
          yield _this9.enableKeyBackup(backupInfo);
        } else {
          logger.log("Backup version ".concat(backupInfo.version, " still current"));
        }
      }
      return {
        backupInfo,
        trustInfo
      };
    })();
  }
  enableKeyBackup(backupInfo) {
    var _this10 = this;
    return _asyncToGenerator(function* () {
      yield _this10.olmMachine.enableBackupV1(backupInfo.auth_data.public_key, backupInfo.version);
      _this10.activeBackupVersion = backupInfo.version;
      _this10.emit(CryptoEvent.KeyBackupStatus, true);
      _this10.backupKeysLoop();
    })();
  }
  /**
   * Restart the backup key loop if there is an active trusted backup.
   * Doesn't try to check the backup server side. To be called when a new
   * megolm key is known locally.
   */
  maybeUploadKey() {
    var _this11 = this;
    return _asyncToGenerator(function* () {
      if (_this11.activeBackupVersion != null) {
        _this11.backupKeysLoop();
      }
    })();
  }
  disableKeyBackup() {
    var _this12 = this;
    return _asyncToGenerator(function* () {
      yield _this12.olmMachine.disableBackup();
      _this12.activeBackupVersion = null;
      _this12.emit(CryptoEvent.KeyBackupStatus, false);
    })();
  }
  backupKeysLoop() {
    var _arguments = arguments, _this13 = this;
    return _asyncToGenerator(function* () {
      var maxDelay = _arguments.length > 0 && _arguments[0] !== void 0 ? _arguments[0] : 1e4;
      if (_this13.backupKeysLoopRunning) {
        logger.log("Backup loop already running");
        return;
      }
      _this13.backupKeysLoopRunning = true;
      logger.log("Backup: Starting keys upload loop for backup version:".concat(_this13.activeBackupVersion, "."));
      var delay = Math.random() * maxDelay;
      yield sleep(delay);
      try {
        var numFailures = 0;
        var remainingToUploadCount = null;
        var isFirstIteration = true;
        while (!_this13.stopped) {
          var request = void 0;
          try {
            request = yield logDuration(logger, "BackupRoomKeys: Get keys to backup from rust crypto-sdk", /* @__PURE__ */ _asyncToGenerator(function* () {
              return yield _this13.olmMachine.backupRoomKeys();
            }));
          } catch (err) {
            logger.error("Backup: Failed to get keys to backup from rust crypto-sdk", err);
          }
          if (!request || _this13.stopped || !_this13.activeBackupVersion) {
            logger.log("Backup: Ending loop for version ".concat(_this13.activeBackupVersion, "."));
            if (!request) {
              _this13.emit(CryptoEvent.KeyBackupSessionsRemaining, 0);
            }
            return;
          }
          try {
            yield _this13.outgoingRequestProcessor.makeOutgoingRequest(request);
            numFailures = 0;
            if (_this13.stopped) break;
            if (!isFirstIteration && remainingToUploadCount === null) {
              try {
                var keyCount = yield _this13.olmMachine.roomKeyCounts();
                remainingToUploadCount = keyCount.total - keyCount.backedUp;
              } catch (err) {
                logger.error("Backup: Failed to get key counts from rust crypto-sdk", err);
              }
            }
            if (remainingToUploadCount !== null) {
              _this13.emit(CryptoEvent.KeyBackupSessionsRemaining, remainingToUploadCount);
              var keysCountInBatch = _this13.keysCountInBatch(request);
              remainingToUploadCount = Math.max(remainingToUploadCount - keysCountInBatch, 0);
            }
          } catch (err) {
            numFailures++;
            logger.error("Backup: Error processing backup request for rust crypto-sdk", err);
            if (err instanceof MatrixError) {
              var errCode = err.data.errcode;
              if (errCode == "M_NOT_FOUND" || errCode == "M_WRONG_ROOM_KEYS_VERSION") {
                logger.log("Backup: Failed to upload keys to current vesion: ".concat(errCode, "."));
                try {
                  yield _this13.disableKeyBackup();
                } catch (error) {
                  logger.error("Backup: An error occurred while disabling key backup:", error);
                }
                _this13.emit(CryptoEvent.KeyBackupFailed, err.data.errcode);
                _this13.backupKeysLoopRunning = false;
                _this13.checkKeyBackupAndEnable(true);
                return;
              } else if (err.isRateLimitError()) {
                try {
                  var waitTime = err.getRetryAfterMs();
                  if (waitTime && waitTime > 0) {
                    yield sleep(waitTime);
                    continue;
                  }
                } catch (error) {
                  logger.warn("Backup: An error occurred while retrieving a rate-limit retry delay", error);
                }
              }
            }
            yield sleep(1e3 * Math.pow(2, Math.min(numFailures - 1, 4)));
          }
          isFirstIteration = false;
        }
      } finally {
        _this13.backupKeysLoopRunning = false;
      }
    })();
  }
  /**
   * Utility method to count the number of keys in a backup request, in order to update the remaining keys count.
   * This should be the chunk size of the backup request for all requests but the last, but we don't have access to it
   * (it's static in the Rust SDK).
   * @param batch - The backup request to count the keys from.
   *
   * @returns The number of keys in the backup request.
   */
  keysCountInBatch(batch) {
    var parsedBody = JSON.parse(batch.body);
    return countKeysInBackup(parsedBody);
  }
  /**
   * Get information about a key backup from the server
   * - If version is provided, get information about that backup version.
   * - If no version is provided, get information about the latest backup.
   *
   * @param version - The version of the backup to get information about.
   * @returns Information object from API or null if there is no active backup.
   */
  requestKeyBackupVersion(version) {
    var _this14 = this;
    return _asyncToGenerator(function* () {
      return yield requestKeyBackupVersion(_this14.http, version);
    })();
  }
  /**
   * Creates a new key backup by generating a new random private key.
   *
   * If there is an existing backup server side it will be deleted and replaced
   * by the new one.
   *
   * @param signObject - Method that should sign the backup with existing device and
   * existing identity.
   * @returns a KeyBackupCreationInfo - All information related to the backup.
   */
  setupKeyBackup(signObject) {
    var _this15 = this;
    return _asyncToGenerator(function* () {
      yield _this15.deleteAllKeyBackupVersions();
      var randomKey = BackupDecryptionKey.createRandomKey();
      var pubKey = randomKey.megolmV1PublicKey;
      var authData = {
        public_key: pubKey.publicKeyBase64
      };
      yield signObject(authData);
      var res = yield _this15.http.authedRequest(Method.Post, "/room_keys/version", void 0, {
        algorithm: pubKey.algorithm,
        auth_data: authData
      }, {
        prefix: ClientPrefix.V3
      });
      yield _this15.saveBackupDecryptionKey(randomKey, res.version);
      return {
        version: res.version,
        algorithm: pubKey.algorithm,
        authData,
        decryptionKey: randomKey
      };
    })();
  }
  /**
   * Deletes all key backups.
   *
   * Will call the API to delete active backup until there is no more present.
   */
  deleteAllKeyBackupVersions() {
    var _this16 = this;
    return _asyncToGenerator(function* () {
      var _yield$_this16$reques, _yield$_this16$reques2;
      var current = (_yield$_this16$reques = (_yield$_this16$reques2 = yield _this16.requestKeyBackupVersion()) === null || _yield$_this16$reques2 === void 0 ? void 0 : _yield$_this16$reques2.version) !== null && _yield$_this16$reques !== void 0 ? _yield$_this16$reques : null;
      while (current != null) {
        var _yield$_this16$reques3, _yield$_this16$reques4;
        yield _this16.deleteKeyBackupVersion(current);
        current = (_yield$_this16$reques3 = (_yield$_this16$reques4 = yield _this16.requestKeyBackupVersion()) === null || _yield$_this16$reques4 === void 0 ? void 0 : _yield$_this16$reques4.version) !== null && _yield$_this16$reques3 !== void 0 ? _yield$_this16$reques3 : null;
      }
    })();
  }
  /**
   * Deletes the given key backup.
   *
   * @param version - The backup version to delete.
   */
  deleteKeyBackupVersion(version) {
    var _this17 = this;
    return _asyncToGenerator(function* () {
      logger.debug("deleteKeyBackupVersion v:".concat(version));
      var path = encodeUri("/room_keys/version/$version", {
        $version: version
      });
      yield _this17.http.authedRequest(Method.Delete, path, void 0, void 0, {
        prefix: ClientPrefix.V3
      });
      if (_this17.activeBackupVersion === version) {
        _this17.serverBackupInfo = null;
        yield _this17.disableKeyBackup();
      }
    })();
  }
  /**
   * Creates a new backup decryptor for the given private key.
   * @param decryptionKey - The private key to use for decryption.
   */
  createBackupDecryptor(decryptionKey) {
    return new RustBackupDecryptor(decryptionKey);
  }
  /**
   * Restore a key backup.
   *
   * @param backupVersion - The version of the backup to restore.
   * @param backupDecryptor - The backup decryptor to use to decrypt the keys.
   * @param opts - Options for the restore.
   * @returns The total number of keys and the total imported.
   */
  restoreKeyBackup(backupVersion, backupDecryptor, opts) {
    var _this18 = this;
    return _asyncToGenerator(function* () {
      var keyBackup = yield _this18.downloadKeyBackup(backupVersion);
      return _this18.importKeyBackup(keyBackup, backupVersion, backupDecryptor, opts);
    })();
  }
  /**
   * Call `/room_keys/keys` to download the key backup (room keys) for the given backup version.
   * https://spec.matrix.org/v1.12/client-server-api/#get_matrixclientv3room_keyskeys
   *
   * @param backupVersion
   * @returns The key backup response.
   */
  downloadKeyBackup(backupVersion) {
    return this.http.authedRequest(Method.Get, "/room_keys/keys", {
      version: backupVersion
    }, void 0, {
      prefix: ClientPrefix.V3
    });
  }
  /**
   * Import the room keys from a `/room_keys/keys` call.
   * Calls `opts.progressCallback` with the progress of the import.
   *
   * @param keyBackup - The response from the server containing the keys to import.
   * @param backupVersion - The version of the backup info.
   * @param backupDecryptor - The backup decryptor to use to decrypt the keys.
   * @param opts - Options for the import.
   *
   * @returns The total number of keys and the total imported.
   *
   * @private
   */
  importKeyBackup(keyBackup, backupVersion, backupDecryptor, opts) {
    var _this19 = this;
    return _asyncToGenerator(function* () {
      var _opts$progressCallbac3;
      var CHUNK_SIZE = 200;
      var totalKeyCount = countKeysInBackup(keyBackup);
      var totalImported = 0;
      var totalFailures = 0;
      opts === null || opts === void 0 || (_opts$progressCallbac3 = opts.progressCallback) === null || _opts$progressCallbac3 === void 0 || _opts$progressCallbac3.call(opts, {
        total: totalKeyCount,
        successes: totalImported,
        stage: ImportRoomKeyStage.LoadKeys,
        failures: totalFailures
      });
      var handleChunkCallback = /* @__PURE__ */ function() {
        var _ref2 = _asyncToGenerator(function* (roomChunks) {
          var _opts$progressCallbac4;
          var currentChunk = [];
          var _loop = function* _loop2(roomId3) {
            var decryptedSessions = yield backupDecryptor.decryptSessions(roomChunks.get(roomId3));
            decryptedSessions.forEach((session2) => {
              session2.room_id = roomId3;
              currentChunk.push(session2);
            });
          };
          for (var roomId2 of roomChunks.keys()) {
            yield* _loop(roomId2);
          }
          try {
            yield _this19.importBackedUpRoomKeys(currentChunk, backupVersion);
            totalImported += currentChunk.length;
          } catch (e) {
            totalFailures += currentChunk.length;
            logger.error("Error importing keys from backup", e);
          }
          opts === null || opts === void 0 || (_opts$progressCallbac4 = opts.progressCallback) === null || _opts$progressCallbac4 === void 0 || _opts$progressCallbac4.call(opts, {
            total: totalKeyCount,
            successes: totalImported,
            stage: ImportRoomKeyStage.LoadKeys,
            failures: totalFailures
          });
        });
        return function handleChunkCallback2(_x) {
          return _ref2.apply(this, arguments);
        };
      }();
      var groupChunkCount = 0;
      var chunkGroupByRoom = /* @__PURE__ */ new Map();
      for (var [roomId, roomData] of Object.entries(keyBackup.rooms)) {
        if (!roomData.sessions) continue;
        chunkGroupByRoom.set(roomId, {});
        for (var [sessionId, session] of Object.entries(roomData.sessions)) {
          var sessionsForRoom = chunkGroupByRoom.get(roomId);
          sessionsForRoom[sessionId] = session;
          groupChunkCount += 1;
          if (groupChunkCount >= CHUNK_SIZE) {
            yield handleChunkCallback(chunkGroupByRoom);
            chunkGroupByRoom = /* @__PURE__ */ new Map();
            chunkGroupByRoom.set(roomId, {});
            groupChunkCount = 0;
          }
        }
      }
      if (groupChunkCount > 0) {
        yield handleChunkCallback(chunkGroupByRoom);
      }
      return {
        total: totalKeyCount,
        imported: totalImported
      };
    })();
  }
}
function backupInfoMatchesBackupDecryptionKey(info, backupDecryptionKey) {
  var _info$auth_data;
  if (info.algorithm !== "m.megolm_backup.v1.curve25519-aes-sha2") {
    logger.warn("backupMatchesPrivateKey: Unsupported backup algorithm", info.algorithm);
    return false;
  }
  return ((_info$auth_data = info.auth_data) === null || _info$auth_data === void 0 ? void 0 : _info$auth_data.public_key) === backupDecryptionKey.megolmV1PublicKey.publicKeyBase64;
}
class RustBackupDecryptor {
  constructor(decryptionKey) {
    _defineProperty(this, "decryptionKey", void 0);
    _defineProperty(this, "sourceTrusted", void 0);
    this.decryptionKey = decryptionKey;
    this.sourceTrusted = false;
  }
  /**
   * Implements {@link BackupDecryptor#decryptSessions}
   */
  decryptSessions(ciphertexts) {
    var _this20 = this;
    return _asyncToGenerator(function* () {
      var keys = [];
      for (var [sessionId, sessionData] of Object.entries(ciphertexts)) {
        try {
          var decrypted = JSON.parse(_this20.decryptionKey.decryptV1(sessionData.session_data.ephemeral, sessionData.session_data.mac, sessionData.session_data.ciphertext));
          decrypted.session_id = sessionId;
          keys.push(decrypted);
        } catch (e) {
          logger.log("Failed to decrypt megolm session from backup", e, sessionData);
        }
      }
      return keys;
    })();
  }
  /**
   * Implements {@link BackupDecryptor#free}
   */
  free() {
    this.decryptionKey.free();
  }
}
function requestKeyBackupVersion(_x2, _x3) {
  return _requestKeyBackupVersion.apply(this, arguments);
}
function _requestKeyBackupVersion() {
  _requestKeyBackupVersion = _asyncToGenerator(function* (http, version) {
    try {
      var path = version ? encodeUri("/room_keys/version/$version", {
        $version: version
      }) : "/room_keys/version";
      return yield http.authedRequest(Method.Get, path, void 0, void 0, {
        prefix: ClientPrefix.V3
      });
    } catch (e) {
      if (e.errcode === "M_NOT_FOUND") {
        return null;
      } else {
        throw e;
      }
    }
  });
  return _requestKeyBackupVersion.apply(this, arguments);
}
function decryptionKeyMatchesKeyBackupInfo(decryptionKey, keyBackupInfo) {
  var authData = keyBackupInfo.auth_data;
  return authData.public_key === decryptionKey.megolmV1PublicKey.publicKeyBase64;
}
function countKeysInBackup(keyBackup) {
  var count = 0;
  for (var {
    sessions
  } of Object.values(keyBackup.rooms)) {
    count += Object.keys(sessions).length;
  }
  return count;
}
class OutgoingRequestsManager {
  constructor(logger2, olmMachine, outgoingRequestProcessor) {
    this.logger = logger2;
    this.olmMachine = olmMachine;
    this.outgoingRequestProcessor = outgoingRequestProcessor;
    _defineProperty(this, "stopped", false);
    _defineProperty(this, "outgoingRequestLoopRunning", false);
    _defineProperty(this, "nextLoopDeferred", void 0);
  }
  /**
   * Shut down as soon as possible the current loop of outgoing requests processing.
   */
  stop() {
    this.stopped = true;
  }
  /**
   * Process the OutgoingRequests from the OlmMachine.
   *
   * This should be called at the end of each sync, to process any OlmMachine OutgoingRequests created by the rust sdk.
   * In some cases if OutgoingRequests need to be sent immediately, this can be called directly.
   *
   * Calls to doProcessOutgoingRequests() are processed synchronously, one after the other, in order.
   * If doProcessOutgoingRequests() is called while another call is still being processed, it will be queued.
   * Multiple calls to doProcessOutgoingRequests() when a call is already processing will be batched together.
   */
  doProcessOutgoingRequests() {
    if (!this.nextLoopDeferred) {
      this.nextLoopDeferred = defer();
    }
    var result = this.nextLoopDeferred.promise;
    if (!this.outgoingRequestLoopRunning) {
      this.outgoingRequestLoop().catch((e) => {
        this.logger.error("Uncaught error in outgoing request loop", e);
      });
    }
    return result;
  }
  outgoingRequestLoop() {
    var _this = this;
    return _asyncToGenerator(function* () {
      if (_this.outgoingRequestLoopRunning) {
        throw new Error("Cannot run two outgoing request loops");
      }
      _this.outgoingRequestLoopRunning = true;
      try {
        while (!_this.stopped && _this.nextLoopDeferred) {
          var deferred = _this.nextLoopDeferred;
          _this.nextLoopDeferred = void 0;
          yield _this.processOutgoingRequests().then(deferred.resolve, deferred.reject);
        }
      } finally {
        _this.outgoingRequestLoopRunning = false;
      }
      if (_this.nextLoopDeferred) {
        _this.nextLoopDeferred.reject(new Error("OutgoingRequestsManager was stopped"));
      }
    })();
  }
  /**
   * Make a single request to `olmMachine.outgoingRequests` and do the corresponding requests.
   */
  processOutgoingRequests() {
    var _this2 = this;
    return _asyncToGenerator(function* () {
      if (_this2.stopped) return;
      var outgoingRequests = yield _this2.olmMachine.outgoingRequests();
      var _loop = function* _loop2(request2) {
        if (_this2.stopped) return {
          v: void 0
        };
        try {
          yield logDuration(_this2.logger, "Make outgoing request ".concat(request2.type), /* @__PURE__ */ _asyncToGenerator(function* () {
            yield _this2.outgoingRequestProcessor.makeOutgoingRequest(request2);
          }));
        } catch (e) {
          _this2.logger.error("Failed to process outgoing request ".concat(request2.type, ": ").concat(e));
        }
      }, _ret;
      for (var request of outgoingRequests) {
        _ret = yield* _loop(request);
        if (_ret) return _ret.v;
      }
    })();
  }
}
var KEY_BACKUP_BACKOFF = 5e3;
var KeyDownloadErrorCode = /* @__PURE__ */ function(KeyDownloadErrorCode2) {
  KeyDownloadErrorCode2["MISSING_DECRYPTION_KEY"] = "MISSING_DECRYPTION_KEY";
  KeyDownloadErrorCode2["NETWORK_ERROR"] = "NETWORK_ERROR";
  KeyDownloadErrorCode2["STOPPED"] = "STOPPED";
  return KeyDownloadErrorCode2;
}(KeyDownloadErrorCode || {});
class KeyDownloadError extends Error {
  constructor(code) {
    super("Failed to get key from backup: ".concat(code));
    this.code = code;
    this.name = "KeyDownloadError";
  }
}
class KeyDownloadRateLimitError extends Error {
  constructor(retryMillis) {
    super("Failed to get key from backup: rate limited");
    this.retryMillis = retryMillis;
    this.name = "KeyDownloadRateLimitError";
  }
}
class PerSessionKeyBackupDownloader {
  /**
   * Creates a new instance of PerSessionKeyBackupDownloader.
   *
   * @param backupManager - The backup manager to use.
   * @param olmMachine - The olm machine to use.
   * @param http - The http instance to use.
   * @param logger - The logger to use.
   */
  constructor(logger2, olmMachine, http, backupManager) {
    this.olmMachine = olmMachine;
    this.http = http;
    this.backupManager = backupManager;
    _defineProperty(this, "stopped", false);
    _defineProperty(this, "configuration", null);
    _defineProperty(this, "sessionLastCheckAttemptedTime", /* @__PURE__ */ new Map());
    _defineProperty(this, "logger", void 0);
    _defineProperty(this, "downloadLoopRunning", false);
    _defineProperty(this, "queuedRequests", []);
    _defineProperty(this, "hasConfigurationProblem", false);
    _defineProperty(this, "currentBackupVersionCheck", null);
    _defineProperty(this, "onBackupStatusChanged", () => {
      this.hasConfigurationProblem = false;
      this.configuration = null;
      this.getOrCreateBackupConfiguration().then((configuration) => {
        if (configuration) {
          this.downloadKeysLoop();
        }
      });
    });
    this.logger = logger2.getChild("[PerSessionKeyBackupDownloader]");
    backupManager.on(CryptoEvent.KeyBackupStatus, this.onBackupStatusChanged);
    backupManager.on(CryptoEvent.KeyBackupFailed, this.onBackupStatusChanged);
    backupManager.on(CryptoEvent.KeyBackupDecryptionKeyCached, this.onBackupStatusChanged);
  }
  /**
   * Check if key download is successfully configured and active.
   *
   * @return `true` if key download is correctly configured and active; otherwise `false`.
   */
  isKeyBackupDownloadConfigured() {
    return this.configuration !== null;
  }
  /**
   * Return the details of the latest backup on the server, when we last checked.
   *
   * This is just a convenience method to expose {@link RustBackupManager.getServerBackupInfo}.
   */
  getServerBackupInfo() {
    var _this = this;
    return _asyncToGenerator(function* () {
      return yield _this.backupManager.getServerBackupInfo();
    })();
  }
  /**
   * Called when a MissingRoomKey or UnknownMessageIndex decryption error is encountered.
   *
   * This will try to download the key from the backup if there is a trusted active backup.
   * In case of success the key will be imported and the onRoomKeysUpdated callback will be called
   * internally by the rust-sdk and decryption will be retried.
   *
   * @param roomId - The room ID of the room where the error occurred.
   * @param megolmSessionId - The megolm session ID that is missing.
   */
  onDecryptionKeyMissingError(roomId, megolmSessionId) {
    if (this.isAlreadyInQueue(roomId, megolmSessionId)) {
      this.logger.trace("Not checking key backup for session ".concat(megolmSessionId, " as it is already queued"));
      return;
    }
    if (this.wasRequestedRecently(megolmSessionId)) {
      this.logger.trace("Not checking key backup for session ".concat(megolmSessionId, " as it was already requested recently"));
      return;
    }
    this.queuedRequests.push({
      roomId,
      megolmSessionId
    });
    this.downloadKeysLoop();
  }
  stop() {
    this.stopped = true;
    this.backupManager.off(CryptoEvent.KeyBackupStatus, this.onBackupStatusChanged);
    this.backupManager.off(CryptoEvent.KeyBackupFailed, this.onBackupStatusChanged);
    this.backupManager.off(CryptoEvent.KeyBackupDecryptionKeyCached, this.onBackupStatusChanged);
  }
  /** Returns true if the megolm session is already queued for download. */
  isAlreadyInQueue(roomId, megolmSessionId) {
    return this.queuedRequests.some((info) => {
      return info.roomId == roomId && info.megolmSessionId == megolmSessionId;
    });
  }
  /**
   * Marks the session as not found in backup, to avoid retrying to soon for a key not in backup
   *
   * @param megolmSessionId - The megolm session ID that is missing.
   */
  markAsNotFoundInBackup(megolmSessionId) {
    var now = Date.now();
    this.sessionLastCheckAttemptedTime.set(megolmSessionId, now);
    if (this.sessionLastCheckAttemptedTime.size > 100) {
      this.sessionLastCheckAttemptedTime = new Map(Array.from(this.sessionLastCheckAttemptedTime).filter((sid, ts) => {
        return Math.max(now - ts, 0) < KEY_BACKUP_BACKOFF;
      }));
    }
  }
  /** Returns true if the session was requested recently. */
  wasRequestedRecently(megolmSessionId) {
    var lastCheck = this.sessionLastCheckAttemptedTime.get(megolmSessionId);
    if (!lastCheck) return false;
    return Math.max(Date.now() - lastCheck, 0) < KEY_BACKUP_BACKOFF;
  }
  getBackupDecryptionKey() {
    var _this2 = this;
    return _asyncToGenerator(function* () {
      try {
        return yield _this2.olmMachine.getBackupKeys();
      } catch (_unused) {
        return null;
      }
    })();
  }
  /**
   * Requests a key from the server side backup.
   *
   * @param version - The backup version to use.
   * @param roomId - The room ID of the room where the error occurred.
   * @param sessionId - The megolm session ID that is missing.
   */
  requestRoomKeyFromBackup(version, roomId, sessionId) {
    var _this3 = this;
    return _asyncToGenerator(function* () {
      var path = encodeUri("/room_keys/keys/$roomId/$sessionId", {
        $roomId: roomId,
        $sessionId: sessionId
      });
      return yield _this3.http.authedRequest(Method.Get, path, {
        version
      }, void 0, {
        prefix: ClientPrefix.V3
      });
    })();
  }
  downloadKeysLoop() {
    var _this4 = this;
    return _asyncToGenerator(function* () {
      if (_this4.downloadLoopRunning) return;
      if (_this4.hasConfigurationProblem) return;
      _this4.downloadLoopRunning = true;
      try {
        while (_this4.queuedRequests.length > 0) {
          var request = _this4.queuedRequests[0];
          try {
            var configuration = yield _this4.getOrCreateBackupConfiguration();
            if (!configuration) {
              _this4.downloadLoopRunning = false;
              return;
            }
            var result = yield _this4.queryKeyBackup(request.roomId, request.megolmSessionId, configuration);
            if (_this4.stopped) {
              return;
            }
            try {
              yield _this4.decryptAndImport(request, result, configuration);
            } catch (e) {
              _this4.logger.error("Error while decrypting and importing key backup for session ".concat(request.megolmSessionId), e);
            }
            _this4.queuedRequests.shift();
          } catch (err) {
            if (err instanceof KeyDownloadError) {
              switch (err.code) {
                case KeyDownloadErrorCode.MISSING_DECRYPTION_KEY:
                  _this4.markAsNotFoundInBackup(request.megolmSessionId);
                  _this4.queuedRequests.shift();
                  break;
                case KeyDownloadErrorCode.NETWORK_ERROR:
                  yield sleep(KEY_BACKUP_BACKOFF);
                  break;
                case KeyDownloadErrorCode.STOPPED:
                  _this4.downloadLoopRunning = false;
                  return;
              }
            } else if (err instanceof KeyDownloadRateLimitError) {
              yield sleep(err.retryMillis);
            }
          }
        }
      } finally {
        _this4.downloadLoopRunning = false;
      }
    })();
  }
  /**
   * Query the backup for a key.
   *
   * @param targetRoomId - ID of the room that the session is used in.
   * @param targetSessionId - ID of the session for which to check backup.
   * @param configuration - The backup configuration to use.
   */
  queryKeyBackup(targetRoomId, targetSessionId, configuration) {
    var _this5 = this;
    return _asyncToGenerator(function* () {
      _this5.logger.debug("Checking key backup for session ".concat(targetSessionId));
      if (_this5.stopped) throw new KeyDownloadError(KeyDownloadErrorCode.STOPPED);
      try {
        var res = yield _this5.requestRoomKeyFromBackup(configuration.backupVersion, targetRoomId, targetSessionId);
        _this5.logger.debug("Got key from backup for sessionId:".concat(targetSessionId));
        return res;
      } catch (e) {
        if (_this5.stopped) throw new KeyDownloadError(KeyDownloadErrorCode.STOPPED);
        _this5.logger.info("No luck requesting key backup for session ".concat(targetSessionId, ": ").concat(e));
        if (e instanceof MatrixError) {
          var errCode = e.data.errcode;
          if (errCode == "M_NOT_FOUND") {
            throw new KeyDownloadError(KeyDownloadErrorCode.MISSING_DECRYPTION_KEY);
          }
          if (e.isRateLimitError()) {
            var waitTime;
            try {
              var _e$getRetryAfterMs;
              waitTime = (_e$getRetryAfterMs = e.getRetryAfterMs()) !== null && _e$getRetryAfterMs !== void 0 ? _e$getRetryAfterMs : void 0;
            } catch (error) {
              _this5.logger.warn("Error while retrieving a rate-limit retry delay", error);
            }
            if (waitTime && waitTime > 0) {
              _this5.logger.info("Rate limited by server, waiting ".concat(waitTime, "ms"));
            }
            throw new KeyDownloadRateLimitError(waitTime !== null && waitTime !== void 0 ? waitTime : KEY_BACKUP_BACKOFF);
          }
        }
        throw new KeyDownloadError(KeyDownloadErrorCode.NETWORK_ERROR);
      }
    })();
  }
  decryptAndImport(sessionInfo, data, configuration) {
    var _this6 = this;
    return _asyncToGenerator(function* () {
      var sessionsToImport = {
        [sessionInfo.megolmSessionId]: data
      };
      var keys = yield configuration.decryptor.decryptSessions(sessionsToImport);
      for (var k of keys) {
        k.room_id = sessionInfo.roomId;
      }
      yield _this6.backupManager.importBackedUpRoomKeys(keys, configuration.backupVersion);
    })();
  }
  /**
   * Gets the current backup configuration or create one if it doesn't exist.
   *
   * When a valid configuration is found it is cached and returned for subsequent calls.
   * Otherwise, if a check is forced or a check has not yet been done, a new check is done.
   *
   * @returns The backup configuration to use or null if there is a configuration problem.
   */
  getOrCreateBackupConfiguration() {
    var _this7 = this;
    return _asyncToGenerator(function* () {
      if (_this7.configuration) {
        return _this7.configuration;
      }
      if (_this7.hasConfigurationProblem) {
        return null;
      }
      if (_this7.currentBackupVersionCheck != null) {
        _this7.logger.debug("Already checking server version, use current promise");
        return yield _this7.currentBackupVersionCheck;
      }
      _this7.currentBackupVersionCheck = _this7.internalCheckFromServer();
      try {
        return yield _this7.currentBackupVersionCheck;
      } finally {
        _this7.currentBackupVersionCheck = null;
      }
    })();
  }
  internalCheckFromServer() {
    var _this8 = this;
    return _asyncToGenerator(function* () {
      var _currentServerVersion, _currentServerVersion2, _currentServerVersion4;
      var currentServerVersion = null;
      try {
        currentServerVersion = yield _this8.backupManager.getServerBackupInfo();
      } catch (e) {
        _this8.logger.debug("Backup: error while checking server version: ".concat(e));
        _this8.hasConfigurationProblem = true;
        return null;
      }
      _this8.logger.debug("Got current backup version from server: ".concat((_currentServerVersion = currentServerVersion) === null || _currentServerVersion === void 0 ? void 0 : _currentServerVersion.version));
      if (((_currentServerVersion2 = currentServerVersion) === null || _currentServerVersion2 === void 0 ? void 0 : _currentServerVersion2.algorithm) != "m.megolm_backup.v1.curve25519-aes-sha2") {
        var _currentServerVersion3;
        _this8.logger.info("Unsupported algorithm ".concat((_currentServerVersion3 = currentServerVersion) === null || _currentServerVersion3 === void 0 ? void 0 : _currentServerVersion3.algorithm));
        _this8.hasConfigurationProblem = true;
        return null;
      }
      if (!((_currentServerVersion4 = currentServerVersion) !== null && _currentServerVersion4 !== void 0 && _currentServerVersion4.version)) {
        _this8.logger.info("No current key backup");
        _this8.hasConfigurationProblem = true;
        return null;
      }
      var activeVersion = yield _this8.backupManager.getActiveBackupVersion();
      if (activeVersion == null || currentServerVersion.version != activeVersion) {
        _this8.logger.info("The current backup version on the server (".concat(currentServerVersion.version, ") is not trusted. Version we are currently backing up to: ").concat(activeVersion));
        _this8.hasConfigurationProblem = true;
        return null;
      }
      var backupKeys = yield _this8.getBackupDecryptionKey();
      if (!(backupKeys !== null && backupKeys !== void 0 && backupKeys.decryptionKey)) {
        _this8.logger.debug("Not checking key backup for session (no decryption key)");
        _this8.hasConfigurationProblem = true;
        return null;
      }
      if (activeVersion != backupKeys.backupVersion) {
        _this8.logger.debug("Version for which we have a decryption key (".concat(backupKeys.backupVersion, ") doesn't match the version we are backing up to (").concat(activeVersion, ")"));
        _this8.hasConfigurationProblem = true;
        return null;
      }
      var authData = currentServerVersion.auth_data;
      if (authData.public_key != backupKeys.decryptionKey.megolmV1PublicKey.publicKeyBase64) {
        _this8.logger.debug("Key backup on server does not match our decryption key");
        _this8.hasConfigurationProblem = true;
        return null;
      }
      var backupDecryptor = _this8.backupManager.createBackupDecryptor(backupKeys.decryptionKey);
      _this8.hasConfigurationProblem = false;
      _this8.configuration = {
        decryptor: backupDecryptor,
        backupVersion: activeVersion
      };
      return _this8.configuration;
    })();
  }
}
function keyFromAuthData(authData, passphrase) {
  if (!authData.private_key_salt || !authData.private_key_iterations) {
    throw new Error("Salt and/or iterations not found: this backup cannot be restored with a passphrase");
  }
  return deriveRecoveryKeyFromPassphrase(passphrase, authData.private_key_salt, authData.private_key_iterations, authData.private_key_bits);
}
function ownKeys$1(e, r) {
  var t = Object.keys(e);
  if (Object.getOwnPropertySymbols) {
    var o = Object.getOwnPropertySymbols(e);
    r && (o = o.filter(function(r2) {
      return Object.getOwnPropertyDescriptor(e, r2).enumerable;
    })), t.push.apply(t, o);
  }
  return t;
}
function _objectSpread$1(e) {
  for (var r = 1; r < arguments.length; r++) {
    var t = null != arguments[r] ? arguments[r] : {};
    r % 2 ? ownKeys$1(Object(t), true).forEach(function(r2) {
      _defineProperty(e, r2, t[r2]);
    }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys$1(Object(t)).forEach(function(r2) {
      Object.defineProperty(e, r2, Object.getOwnPropertyDescriptor(t, r2));
    });
  }
  return e;
}
var ALL_VERIFICATION_METHODS = [VerificationMethod$1.Sas, VerificationMethod$1.ScanQrCode, VerificationMethod$1.ShowQrCode, VerificationMethod$1.Reciprocate];
class RustCrypto extends TypedEventEmitter {
  constructor(logger2, olmMachine, http, userId, _deviceId, secretStorage, cryptoCallbacks) {
    super();
    this.logger = logger2;
    this.olmMachine = olmMachine;
    this.http = http;
    this.userId = userId;
    this.secretStorage = secretStorage;
    this.cryptoCallbacks = cryptoCallbacks;
    _defineProperty(this, "RECOVERY_KEY_DERIVATION_ITERATIONS", 5e5);
    _defineProperty(this, "_trustCrossSignedDevices", true);
    _defineProperty(this, "deviceIsolationMode", new AllDevicesIsolationMode(false));
    _defineProperty(this, "stopped", false);
    _defineProperty(this, "roomEncryptors", {});
    _defineProperty(this, "eventDecryptor", void 0);
    _defineProperty(this, "keyClaimManager", void 0);
    _defineProperty(this, "outgoingRequestProcessor", void 0);
    _defineProperty(this, "crossSigningIdentity", void 0);
    _defineProperty(this, "backupManager", void 0);
    _defineProperty(this, "outgoingRequestsManager", void 0);
    _defineProperty(this, "perSessionBackupDownloader", void 0);
    _defineProperty(this, "dehydratedDeviceManager", void 0);
    _defineProperty(this, "reemitter", new TypedReEmitter(this));
    _defineProperty(this, "globalBlacklistUnverifiedDevices", false);
    _defineProperty(this, "_supportedVerificationMethods", ALL_VERIFICATION_METHODS);
    this.outgoingRequestProcessor = new OutgoingRequestProcessor(olmMachine, http);
    this.outgoingRequestsManager = new OutgoingRequestsManager(this.logger, olmMachine, this.outgoingRequestProcessor);
    this.keyClaimManager = new KeyClaimManager(olmMachine, this.outgoingRequestProcessor);
    this.backupManager = new RustBackupManager(olmMachine, http, this.outgoingRequestProcessor);
    this.perSessionBackupDownloader = new PerSessionKeyBackupDownloader(this.logger, this.olmMachine, this.http, this.backupManager);
    this.dehydratedDeviceManager = new DehydratedDeviceManager(this.logger, olmMachine, http, this.outgoingRequestProcessor, secretStorage);
    this.eventDecryptor = new EventDecryptor(this.logger, olmMachine, this.perSessionBackupDownloader);
    this.reemitter.reEmit(this.backupManager, [CryptoEvent.KeyBackupStatus, CryptoEvent.KeyBackupSessionsRemaining, CryptoEvent.KeyBackupFailed, CryptoEvent.KeyBackupDecryptionKeyCached]);
    this.reemitter.reEmit(this.dehydratedDeviceManager, [CryptoEvent.DehydratedDeviceCreated, CryptoEvent.DehydratedDeviceUploaded, CryptoEvent.RehydrationStarted, CryptoEvent.RehydrationProgress, CryptoEvent.RehydrationCompleted, CryptoEvent.RehydrationError, CryptoEvent.DehydrationKeyCached, CryptoEvent.DehydratedDeviceRotationError]);
    this.crossSigningIdentity = new CrossSigningIdentity(olmMachine, this.outgoingRequestProcessor, secretStorage);
    this.checkKeyBackupAndEnable();
  }
  /**
   * Return the OlmMachine only if {@link RustCrypto#stop} has not been called.
   *
   * This allows us to better handle race conditions where the client is stopped before or during a crypto API call.
   *
   * @throws ClientStoppedError if {@link RustCrypto#stop} has been called.
   */
  getOlmMachineOrThrow() {
    if (this.stopped) {
      throw new ClientStoppedError();
    }
    return this.olmMachine;
  }
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // CryptoBackend implementation
  //
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  set globalErrorOnUnknownDevices(_v) {
  }
  get globalErrorOnUnknownDevices() {
    return false;
  }
  stop() {
    if (this.stopped) {
      return;
    }
    this.stopped = true;
    this.keyClaimManager.stop();
    this.backupManager.stop();
    this.outgoingRequestsManager.stop();
    this.perSessionBackupDownloader.stop();
    this.dehydratedDeviceManager.stop();
    this.olmMachine.close();
  }
  encryptEvent(event, _room) {
    var _this = this;
    return _asyncToGenerator(function* () {
      var roomId = event.getRoomId();
      var encryptor = _this.roomEncryptors[roomId];
      if (!encryptor) {
        throw new Error("Cannot encrypt event in unconfigured room ".concat(roomId));
      }
      yield encryptor.encryptEvent(event, _this.globalBlacklistUnverifiedDevices, _this.deviceIsolationMode);
    })();
  }
  decryptEvent(event) {
    var _this2 = this;
    return _asyncToGenerator(function* () {
      var roomId = event.getRoomId();
      if (!roomId) {
        throw new Error("to-device event was not decrypted in preprocessToDeviceMessages");
      }
      return yield _this2.eventDecryptor.attemptEventDecryption(event, _this2.deviceIsolationMode);
    })();
  }
  /**
   * Implementation of {@link CryptoBackend#getBackupDecryptor}.
   */
  getBackupDecryptor(backupInfo, privKey) {
    var _this3 = this;
    return _asyncToGenerator(function* () {
      if (!(privKey instanceof Uint8Array)) {
        throw new Error("getBackupDecryptor: expects Uint8Array");
      }
      if (backupInfo.algorithm != "m.megolm_backup.v1.curve25519-aes-sha2") {
        throw new Error("getBackupDecryptor: Unsupported algorithm ".concat(backupInfo.algorithm));
      }
      var backupDecryptionKey = BackupDecryptionKey.fromBase64(encodeBase64(privKey));
      if (!decryptionKeyMatchesKeyBackupInfo(backupDecryptionKey, backupInfo)) {
        throw new Error("getBackupDecryptor: key backup on server does not match the decryption key");
      }
      return _this3.backupManager.createBackupDecryptor(backupDecryptionKey);
    })();
  }
  /**
   * Implementation of {@link CryptoBackend#importBackedUpRoomKeys}.
   */
  importBackedUpRoomKeys(keys, backupVersion, opts) {
    var _this4 = this;
    return _asyncToGenerator(function* () {
      return yield _this4.backupManager.importBackedUpRoomKeys(keys, backupVersion, opts);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#getVersion}.
   */
  getVersion() {
    var versions = getVersions();
    return "Rust SDK ".concat(versions.matrix_sdk_crypto, " (").concat(versions.git_sha, "), Vodozemac ").concat(versions.vodozemac);
  }
  /**
   * Implementation of {@link CryptoApi#setDeviceIsolationMode}.
   */
  setDeviceIsolationMode(isolationMode) {
    this.deviceIsolationMode = isolationMode;
  }
  /**
   * Implementation of {@link CryptoApi#isEncryptionEnabledInRoom}.
   */
  isEncryptionEnabledInRoom(roomId) {
    var _this5 = this;
    return _asyncToGenerator(function* () {
      var roomSettings = yield _this5.olmMachine.getRoomSettings(new RoomId(roomId));
      return Boolean(roomSettings === null || roomSettings === void 0 ? void 0 : roomSettings.algorithm);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#getOwnDeviceKeys}.
   */
  getOwnDeviceKeys() {
    var _this6 = this;
    return _asyncToGenerator(function* () {
      var keys = _this6.olmMachine.identityKeys;
      return {
        ed25519: keys.ed25519.toBase64(),
        curve25519: keys.curve25519.toBase64()
      };
    })();
  }
  prepareToEncrypt(room) {
    var encryptor = this.roomEncryptors[room.roomId];
    if (encryptor) {
      encryptor.prepareForEncryption(this.globalBlacklistUnverifiedDevices, this.deviceIsolationMode);
    }
  }
  forceDiscardSession(roomId) {
    var _this$roomEncryptors$;
    return (_this$roomEncryptors$ = this.roomEncryptors[roomId]) === null || _this$roomEncryptors$ === void 0 ? void 0 : _this$roomEncryptors$.forceDiscardSession();
  }
  exportRoomKeys() {
    var _this7 = this;
    return _asyncToGenerator(function* () {
      var raw = yield _this7.olmMachine.exportRoomKeys(() => true);
      return JSON.parse(raw);
    })();
  }
  exportRoomKeysAsJson() {
    var _this8 = this;
    return _asyncToGenerator(function* () {
      return yield _this8.olmMachine.exportRoomKeys(() => true);
    })();
  }
  importRoomKeys(keys, opts) {
    var _this9 = this;
    return _asyncToGenerator(function* () {
      return yield _this9.backupManager.importRoomKeys(keys, opts);
    })();
  }
  importRoomKeysAsJson(keys, opts) {
    var _this10 = this;
    return _asyncToGenerator(function* () {
      return yield _this10.backupManager.importRoomKeysAsJson(keys, opts);
    })();
  }
  /**
   * Implementation of {@link CryptoApi.userHasCrossSigningKeys}.
   */
  userHasCrossSigningKeys() {
    var _arguments = arguments, _this11 = this;
    return _asyncToGenerator(function* () {
      var userId = _arguments.length > 0 && _arguments[0] !== void 0 ? _arguments[0] : _this11.userId;
      var downloadUncached = _arguments.length > 1 && _arguments[1] !== void 0 ? _arguments[1] : false;
      var rustTrackedUsers = yield _this11.olmMachine.trackedUsers();
      var rustTrackedUser;
      for (var u of rustTrackedUsers) {
        if (userId === u.toString()) {
          rustTrackedUser = u;
          break;
        }
      }
      if (rustTrackedUser !== void 0) {
        if (userId === _this11.userId) {
          var request = _this11.olmMachine.queryKeysForUsers(
            // clone as rust layer will take ownership and it's reused later
            [rustTrackedUser.clone()]
          );
          yield _this11.outgoingRequestProcessor.makeOutgoingRequest(request);
        }
        var userIdentity = yield _this11.olmMachine.getIdentity(rustTrackedUser);
        userIdentity === null || userIdentity === void 0 || userIdentity.free();
        return userIdentity !== void 0;
      } else if (downloadUncached) {
        var _keyResult$master_key;
        var keyResult = yield _this11.downloadDeviceList(/* @__PURE__ */ new Set([userId]));
        var keys = (_keyResult$master_key = keyResult.master_keys) === null || _keyResult$master_key === void 0 ? void 0 : _keyResult$master_key[userId];
        if (!keys) return false;
        return Boolean(Object.values(keys.keys)[0]);
      } else {
        return false;
      }
    })();
  }
  /**
   * Get the device information for the given list of users.
   *
   * @param userIds - The users to fetch.
   * @param downloadUncached - If true, download the device list for users whose device list we are not
   *    currently tracking. Defaults to false, in which case such users will not appear at all in the result map.
   *
   * @returns A map `{@link DeviceMap}`.
   */
  getUserDeviceInfo(userIds) {
    var _arguments2 = arguments, _this12 = this;
    return _asyncToGenerator(function* () {
      var downloadUncached = _arguments2.length > 1 && _arguments2[1] !== void 0 ? _arguments2[1] : false;
      var deviceMapByUserId = /* @__PURE__ */ new Map();
      var rustTrackedUsers = yield _this12.getOlmMachineOrThrow().trackedUsers();
      var trackedUsers = /* @__PURE__ */ new Set();
      rustTrackedUsers.forEach((rustUserId) => trackedUsers.add(rustUserId.toString()));
      var untrackedUsers = /* @__PURE__ */ new Set();
      for (var _userId of userIds) {
        if (trackedUsers.has(_userId)) {
          deviceMapByUserId.set(_userId, yield _this12.getUserDevices(_userId));
        } else {
          untrackedUsers.add(_userId);
        }
      }
      if (downloadUncached && untrackedUsers.size >= 1) {
        var queryResult = yield _this12.downloadDeviceList(untrackedUsers);
        Object.entries(queryResult.device_keys).forEach((_ref) => {
          var [userId, deviceKeys] = _ref;
          return deviceMapByUserId.set(userId, deviceKeysToDeviceMap(deviceKeys));
        });
      }
      return deviceMapByUserId;
    })();
  }
  /**
   * Get the device list for the given user from the olm machine
   * @param userId - Rust SDK UserId
   */
  getUserDevices(userId) {
    var _this13 = this;
    return _asyncToGenerator(function* () {
      var rustUserId = new UserId(userId);
      var userDevices = yield _this13.olmMachine.getUserDevices(rustUserId, 1);
      try {
        var deviceArray = userDevices.devices();
        try {
          return new Map(deviceArray.map((device) => [device.deviceId.toString(), rustDeviceToJsDevice(device, rustUserId)]));
        } finally {
          deviceArray.forEach((d) => d.free());
        }
      } finally {
        userDevices.free();
      }
    })();
  }
  /**
   * Download the given user keys by calling `/keys/query` request
   * @param untrackedUsers - download keys of these users
   */
  downloadDeviceList(untrackedUsers) {
    var _this14 = this;
    return _asyncToGenerator(function* () {
      var queryBody = {
        device_keys: {}
      };
      untrackedUsers.forEach((user) => queryBody.device_keys[user] = []);
      return yield _this14.http.authedRequest(Method.Post, "/_matrix/client/v3/keys/query", void 0, queryBody, {
        prefix: ""
      });
    })();
  }
  /**
   * Implementation of {@link CryptoApi#getTrustCrossSignedDevices}.
   */
  getTrustCrossSignedDevices() {
    return this._trustCrossSignedDevices;
  }
  /**
   * Implementation of {@link CryptoApi#setTrustCrossSignedDevices}.
   */
  setTrustCrossSignedDevices(val) {
    this._trustCrossSignedDevices = val;
  }
  /**
   * Mark the given device as locally verified.
   *
   * Implementation of {@link CryptoApi#setDeviceVerified}.
   */
  setDeviceVerified(userId, deviceId) {
    var _arguments3 = arguments, _this15 = this;
    return _asyncToGenerator(function* () {
      var verified = _arguments3.length > 2 && _arguments3[2] !== void 0 ? _arguments3[2] : true;
      var device = yield _this15.olmMachine.getDevice(new UserId(userId), new DeviceId(deviceId));
      if (!device) {
        throw new Error("Unknown device ".concat(userId, "|").concat(deviceId));
      }
      try {
        yield device.setLocalTrust(verified ? LocalTrust.Verified : LocalTrust.Unset);
      } finally {
        device.free();
      }
    })();
  }
  /**
   * Blindly cross-sign one of our other devices.
   *
   * Implementation of {@link CryptoApi#crossSignDevice}.
   */
  crossSignDevice(deviceId) {
    var _this16 = this;
    return _asyncToGenerator(function* () {
      var device = yield _this16.olmMachine.getDevice(new UserId(_this16.userId), new DeviceId(deviceId));
      if (!device) {
        throw new Error("Unknown device ".concat(deviceId));
      }
      try {
        var outgoingRequest = yield device.verify();
        yield _this16.outgoingRequestProcessor.makeOutgoingRequest(outgoingRequest);
      } finally {
        device.free();
      }
    })();
  }
  /**
   * Implementation of {@link CryptoApi#getDeviceVerificationStatus}.
   */
  getDeviceVerificationStatus(userId, deviceId) {
    var _this17 = this;
    return _asyncToGenerator(function* () {
      var device = yield _this17.olmMachine.getDevice(new UserId(userId), new DeviceId(deviceId));
      if (!device) return null;
      try {
        return new DeviceVerificationStatus({
          signedByOwner: device.isCrossSignedByOwner(),
          crossSigningVerified: device.isCrossSigningTrusted(),
          localVerified: device.isLocallyTrusted(),
          trustCrossSignedDevices: _this17._trustCrossSignedDevices
        });
      } finally {
        device.free();
      }
    })();
  }
  /**
   * Implementation of {@link CryptoApi#getUserVerificationStatus}.
   */
  getUserVerificationStatus(userId) {
    var _this18 = this;
    return _asyncToGenerator(function* () {
      var userIdentity = yield _this18.getOlmMachineOrThrow().getIdentity(new UserId(userId));
      if (userIdentity === void 0) {
        return new UserVerificationStatus(false, false, false);
      }
      var verified = userIdentity.isVerified();
      var wasVerified = userIdentity.wasPreviouslyVerified();
      var needsUserApproval = userIdentity instanceof OtherUserIdentity ? userIdentity.identityNeedsUserApproval() : false;
      userIdentity.free();
      return new UserVerificationStatus(verified, wasVerified, false, needsUserApproval);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#pinCurrentUserIdentity}.
   */
  pinCurrentUserIdentity(userId) {
    var _this19 = this;
    return _asyncToGenerator(function* () {
      var userIdentity = yield _this19.getOlmMachineOrThrow().getIdentity(new UserId(userId));
      if (userIdentity === void 0) {
        throw new Error("Cannot pin identity of unknown user");
      }
      if (userIdentity instanceof OwnUserIdentity) {
        throw new Error("Cannot pin identity of own user");
      }
      yield userIdentity.pinCurrentMasterKey();
    })();
  }
  /**
   * Implementation of {@link CryptoApi#withdrawVerificationRequirement}.
   */
  withdrawVerificationRequirement(userId) {
    var _this20 = this;
    return _asyncToGenerator(function* () {
      var userIdentity = yield _this20.getOlmMachineOrThrow().getIdentity(new UserId(userId));
      if (userIdentity === void 0) {
        throw new Error("Cannot withdraw verification of unknown user");
      }
      yield userIdentity.withdrawVerification();
    })();
  }
  /**
   * Implementation of {@link CryptoApi#isCrossSigningReady}
   */
  isCrossSigningReady() {
    var _this21 = this;
    return _asyncToGenerator(function* () {
      var {
        privateKeysInSecretStorage,
        privateKeysCachedLocally
      } = yield _this21.getCrossSigningStatus();
      var hasKeysInCache = Boolean(privateKeysCachedLocally.masterKey) && Boolean(privateKeysCachedLocally.selfSigningKey) && Boolean(privateKeysCachedLocally.userSigningKey);
      var identity = yield _this21.getOwnIdentity();
      return !!(identity !== null && identity !== void 0 && identity.isVerified()) && (hasKeysInCache || privateKeysInSecretStorage);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#getCrossSigningKeyId}
   */
  getCrossSigningKeyId() {
    var _arguments4 = arguments, _this22 = this;
    return _asyncToGenerator(function* () {
      var type = _arguments4.length > 0 && _arguments4[0] !== void 0 ? _arguments4[0] : CrossSigningKey.Master;
      var userIdentity = yield _this22.olmMachine.getIdentity(new UserId(_this22.userId));
      if (!userIdentity) {
        return null;
      }
      try {
        var crossSigningStatus = yield _this22.olmMachine.crossSigningStatus();
        var privateKeysOnDevice = crossSigningStatus.hasMaster && crossSigningStatus.hasUserSigning && crossSigningStatus.hasSelfSigning;
        if (!privateKeysOnDevice) {
          return null;
        }
        if (!userIdentity.isVerified()) {
          return null;
        }
        var key;
        switch (type) {
          case CrossSigningKey.Master:
            key = userIdentity.masterKey;
            break;
          case CrossSigningKey.SelfSigning:
            key = userIdentity.selfSigningKey;
            break;
          case CrossSigningKey.UserSigning:
            key = userIdentity.userSigningKey;
            break;
          default:
            return null;
        }
        var parsedKey = JSON.parse(key);
        return Object.values(parsedKey.keys)[0];
      } finally {
        userIdentity.free();
      }
    })();
  }
  /**
   * Implementation of {@link CryptoApi#bootstrapCrossSigning}
   */
  bootstrapCrossSigning(opts) {
    var _this23 = this;
    return _asyncToGenerator(function* () {
      yield _this23.crossSigningIdentity.bootstrapCrossSigning(opts);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#isSecretStorageReady}
   */
  isSecretStorageReady() {
    var _this24 = this;
    return _asyncToGenerator(function* () {
      var secretsToCheck = ["m.cross_signing.master", "m.cross_signing.user_signing", "m.cross_signing.self_signing"];
      var keyBackupEnabled = (yield _this24.backupManager.getActiveBackupVersion()) != null;
      if (keyBackupEnabled) {
        secretsToCheck.push("m.megolm_backup.v1");
      }
      return secretStorageCanAccessSecrets(_this24.secretStorage, secretsToCheck);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#bootstrapSecretStorage}
   */
  bootstrapSecretStorage() {
    var _arguments5 = arguments, _this25 = this;
    return _asyncToGenerator(function* () {
      var {
        createSecretStorageKey,
        setupNewSecretStorage,
        setupNewKeyBackup
      } = _arguments5.length > 0 && _arguments5[0] !== void 0 ? _arguments5[0] : {};
      var isNewSecretStorageKeyNeeded = setupNewSecretStorage || !(yield _this25.secretStorageHasAESKey());
      if (isNewSecretStorageKeyNeeded) {
        if (!createSecretStorageKey) {
          throw new Error("unable to create a new secret storage key, createSecretStorageKey is not set");
        }
        _this25.logger.info("bootstrapSecretStorage: creating new secret storage key");
        var recoveryKey = yield createSecretStorageKey();
        if (!recoveryKey) {
          throw new Error("createSecretStorageKey() callback did not return a secret storage key");
        }
        yield _this25.addSecretStorageKeyToSecretStorage(recoveryKey);
      }
      var crossSigningPrivateKeys = yield _this25.olmMachine.exportCrossSigningKeys();
      var hasPrivateKeys = crossSigningPrivateKeys && crossSigningPrivateKeys.masterKey !== void 0 && crossSigningPrivateKeys.self_signing_key !== void 0 && crossSigningPrivateKeys.userSigningKey !== void 0;
      if (hasPrivateKeys && (isNewSecretStorageKeyNeeded || !(yield secretStorageContainsCrossSigningKeys(_this25.secretStorage)))) {
        _this25.logger.info("bootstrapSecretStorage: cross-signing keys not yet exported; doing so now.");
        yield _this25.secretStorage.store("m.cross_signing.master", crossSigningPrivateKeys.masterKey);
        yield _this25.secretStorage.store("m.cross_signing.user_signing", crossSigningPrivateKeys.userSigningKey);
        yield _this25.secretStorage.store("m.cross_signing.self_signing", crossSigningPrivateKeys.self_signing_key);
      }
      if (!setupNewKeyBackup) {
        yield _this25.saveBackupKeyToStorage();
      } else {
        yield _this25.resetKeyBackup();
      }
    })();
  }
  /**
   * If we have a backup key for the current, trusted backup in cache,
   * save it to secret storage.
   */
  saveBackupKeyToStorage() {
    var _this26 = this;
    return _asyncToGenerator(function* () {
      var keyBackupInfo = yield _this26.backupManager.getServerBackupInfo();
      if (!keyBackupInfo || !keyBackupInfo.version) {
        logger.info("Not saving backup key to secret storage: no backup info");
        return;
      }
      var backupKeys = yield _this26.olmMachine.getBackupKeys();
      if (!backupKeys.decryptionKey) {
        logger.info("Not saving backup key to secret storage: no backup key");
        return;
      }
      if (!decryptionKeyMatchesKeyBackupInfo(backupKeys.decryptionKey, keyBackupInfo)) {
        logger.info("Not saving backup key to secret storage: decryption key does not match backup info");
        return;
      }
      var backupKeyBase64 = backupKeys.decryptionKey.toBase64();
      yield _this26.secretStorage.store("m.megolm_backup.v1", backupKeyBase64);
    })();
  }
  /**
   * Add the secretStorage key to the secret storage
   * - The secret storage key must have the `keyInfo` field filled
   * - The secret storage key is set as the default key of the secret storage
   * - Call `cryptoCallbacks.cacheSecretStorageKey` when done
   *
   * @param secretStorageKey - The secret storage key to add in the secret storage.
   */
  addSecretStorageKeyToSecretStorage(secretStorageKey) {
    var _this27 = this;
    return _asyncToGenerator(function* () {
      var _secretStorageKey$key, _secretStorageKey$key2, _this27$cryptoCallbac, _this27$cryptoCallbac2;
      var secretStorageKeyObject = yield _this27.secretStorage.addKey(SECRET_STORAGE_ALGORITHM_V1_AES, {
        passphrase: (_secretStorageKey$key = secretStorageKey.keyInfo) === null || _secretStorageKey$key === void 0 ? void 0 : _secretStorageKey$key.passphrase,
        name: (_secretStorageKey$key2 = secretStorageKey.keyInfo) === null || _secretStorageKey$key2 === void 0 ? void 0 : _secretStorageKey$key2.name,
        key: secretStorageKey.privateKey
      });
      yield _this27.secretStorage.setDefaultKeyId(secretStorageKeyObject.keyId);
      (_this27$cryptoCallbac = (_this27$cryptoCallbac2 = _this27.cryptoCallbacks).cacheSecretStorageKey) === null || _this27$cryptoCallbac === void 0 || _this27$cryptoCallbac.call(_this27$cryptoCallbac2, secretStorageKeyObject.keyId, secretStorageKeyObject.keyInfo, secretStorageKey.privateKey);
    })();
  }
  /**
   * Check if a secret storage AES Key is already added in secret storage
   *
   * @returns True if an AES key is in the secret storage
   */
  secretStorageHasAESKey() {
    var _this28 = this;
    return _asyncToGenerator(function* () {
      var secretStorageKeyTuple = yield _this28.secretStorage.getKey();
      if (!secretStorageKeyTuple) return false;
      var [, keyInfo] = secretStorageKeyTuple;
      return keyInfo.algorithm === SECRET_STORAGE_ALGORITHM_V1_AES;
    })();
  }
  /**
   * Implementation of {@link CryptoApi#getCrossSigningStatus}
   */
  getCrossSigningStatus() {
    var _this29 = this;
    return _asyncToGenerator(function* () {
      var userIdentity = yield _this29.getOlmMachineOrThrow().getIdentity(new UserId(_this29.userId));
      var publicKeysOnDevice = Boolean(userIdentity === null || userIdentity === void 0 ? void 0 : userIdentity.masterKey) && Boolean(userIdentity === null || userIdentity === void 0 ? void 0 : userIdentity.selfSigningKey) && Boolean(userIdentity === null || userIdentity === void 0 ? void 0 : userIdentity.userSigningKey);
      userIdentity === null || userIdentity === void 0 || userIdentity.free();
      var privateKeysInSecretStorage = yield secretStorageContainsCrossSigningKeys(_this29.secretStorage);
      var crossSigningStatus = yield _this29.getOlmMachineOrThrow().crossSigningStatus();
      return {
        publicKeysOnDevice,
        privateKeysInSecretStorage,
        privateKeysCachedLocally: {
          masterKey: Boolean(crossSigningStatus === null || crossSigningStatus === void 0 ? void 0 : crossSigningStatus.hasMaster),
          userSigningKey: Boolean(crossSigningStatus === null || crossSigningStatus === void 0 ? void 0 : crossSigningStatus.hasUserSigning),
          selfSigningKey: Boolean(crossSigningStatus === null || crossSigningStatus === void 0 ? void 0 : crossSigningStatus.hasSelfSigning)
        }
      };
    })();
  }
  /**
   * Implementation of {@link CryptoApi#createRecoveryKeyFromPassphrase}
   */
  createRecoveryKeyFromPassphrase(password) {
    var _this30 = this;
    return _asyncToGenerator(function* () {
      if (password) {
        var salt = secureRandomString(32);
        var recoveryKey = yield deriveRecoveryKeyFromPassphrase(password, salt, _this30.RECOVERY_KEY_DERIVATION_ITERATIONS);
        return {
          keyInfo: {
            passphrase: {
              algorithm: "m.pbkdf2",
              iterations: _this30.RECOVERY_KEY_DERIVATION_ITERATIONS,
              salt
            }
          },
          privateKey: recoveryKey,
          encodedPrivateKey: encodeRecoveryKey(recoveryKey)
        };
      } else {
        var key = new Uint8Array(32);
        globalThis.crypto.getRandomValues(key);
        return {
          privateKey: key,
          encodedPrivateKey: encodeRecoveryKey(key)
        };
      }
    })();
  }
  /**
   * Implementation of {@link CryptoApi#getEncryptionInfoForEvent}.
   */
  getEncryptionInfoForEvent(event) {
    var _this31 = this;
    return _asyncToGenerator(function* () {
      return _this31.eventDecryptor.getEncryptionInfoForEvent(event);
    })();
  }
  /**
   * Returns to-device verification requests that are already in progress for the given user id.
   *
   * Implementation of {@link CryptoApi#getVerificationRequestsToDeviceInProgress}
   *
   * @param userId - the ID of the user to query
   *
   * @returns the VerificationRequests that are in progress
   */
  getVerificationRequestsToDeviceInProgress(userId) {
    var requests = this.olmMachine.getVerificationRequests(new UserId(userId));
    return requests.filter((request) => request.roomId === void 0).map((request) => new RustVerificationRequest(this.olmMachine, request, this.outgoingRequestProcessor, this._supportedVerificationMethods));
  }
  /**
   * Finds a DM verification request that is already in progress for the given room id
   *
   * Implementation of {@link CryptoApi#findVerificationRequestDMInProgress}
   *
   * @param roomId - the room to use for verification
   * @param userId - search the verification request for the given user
   *
   * @returns the VerificationRequest that is in progress, if any
   *
   */
  findVerificationRequestDMInProgress(roomId, userId) {
    if (!userId) throw new Error("missing userId");
    var requests = this.olmMachine.getVerificationRequests(new UserId(userId));
    var request = requests.find((request2) => {
      var _request$roomId;
      return ((_request$roomId = request2.roomId) === null || _request$roomId === void 0 ? void 0 : _request$roomId.toString()) === roomId;
    });
    if (request) {
      return new RustVerificationRequest(this.olmMachine, request, this.outgoingRequestProcessor, this._supportedVerificationMethods);
    }
  }
  /**
   * Implementation of {@link CryptoApi#requestVerificationDM}
   */
  requestVerificationDM(userId, roomId) {
    var _this32 = this;
    return _asyncToGenerator(function* () {
      var userIdentity = yield _this32.olmMachine.getIdentity(new UserId(userId));
      if (!userIdentity) throw new Error("unknown userId ".concat(userId));
      try {
        var methods = _this32._supportedVerificationMethods.map((method) => verificationMethodIdentifierToMethod(method));
        var verificationEventContent = yield userIdentity.verificationRequestContent(methods);
        var eventId = yield _this32.sendVerificationRequestContent(roomId, verificationEventContent);
        var request = yield userIdentity.requestVerification(new RoomId(roomId), new EventId(eventId), methods);
        return new RustVerificationRequest(_this32.olmMachine, request, _this32.outgoingRequestProcessor, _this32._supportedVerificationMethods);
      } finally {
        userIdentity.free();
      }
    })();
  }
  /**
   * Send the verification content to a room
   * See https://spec.matrix.org/v1.7/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid
   *
   * Prefer to use {@link OutgoingRequestProcessor.makeOutgoingRequest} when dealing with {@link RustSdkCryptoJs.RoomMessageRequest}
   *
   * @param roomId - the targeted room
   * @param verificationEventContent - the request body.
   *
   * @returns the event id
   */
  sendVerificationRequestContent(roomId, verificationEventContent) {
    var _this33 = this;
    return _asyncToGenerator(function* () {
      var txId = secureRandomString(32);
      var {
        event_id: eventId
      } = yield _this33.http.authedRequest(Method.Put, "/_matrix/client/v3/rooms/".concat(encodeURIComponent(roomId), "/send/m.room.message/").concat(encodeURIComponent(txId)), void 0, verificationEventContent, {
        prefix: ""
      });
      return eventId;
    })();
  }
  /**
   * Set the verification methods we offer to the other side during an interactive verification.
   *
   * If `undefined`, we will offer all the methods supported by the Rust SDK.
   */
  setSupportedVerificationMethods(methods) {
    this._supportedVerificationMethods = methods !== null && methods !== void 0 ? methods : ALL_VERIFICATION_METHODS;
  }
  /**
   * Send a verification request to our other devices.
   *
   * If a verification is already in flight, returns it. Otherwise, initiates a new one.
   *
   * Implementation of {@link CryptoApi#requestOwnUserVerification}.
   *
   * @returns a VerificationRequest when the request has been sent to the other party.
   */
  requestOwnUserVerification() {
    var _this34 = this;
    return _asyncToGenerator(function* () {
      var userIdentity = yield _this34.olmMachine.getIdentity(new UserId(_this34.userId));
      if (userIdentity === void 0) {
        throw new Error("cannot request verification for this device when there is no existing cross-signing key");
      }
      try {
        var [request, outgoingRequest] = yield userIdentity.requestVerification(_this34._supportedVerificationMethods.map(verificationMethodIdentifierToMethod));
        yield _this34.outgoingRequestProcessor.makeOutgoingRequest(outgoingRequest);
        return new RustVerificationRequest(_this34.olmMachine, request, _this34.outgoingRequestProcessor, _this34._supportedVerificationMethods);
      } finally {
        userIdentity.free();
      }
    })();
  }
  /**
   * Request an interactive verification with the given device.
   *
   * If a verification is already in flight, returns it. Otherwise, initiates a new one.
   *
   * Implementation of {@link CryptoApi#requestDeviceVerification}.
   *
   * @param userId - ID of the owner of the device to verify
   * @param deviceId - ID of the device to verify
   *
   * @returns a VerificationRequest when the request has been sent to the other party.
   */
  requestDeviceVerification(userId, deviceId) {
    var _this35 = this;
    return _asyncToGenerator(function* () {
      var device = yield _this35.olmMachine.getDevice(new UserId(userId), new DeviceId(deviceId));
      if (!device) {
        throw new Error("Not a known device");
      }
      try {
        var [request, outgoingRequest] = device.requestVerification(_this35._supportedVerificationMethods.map(verificationMethodIdentifierToMethod));
        yield _this35.outgoingRequestProcessor.makeOutgoingRequest(outgoingRequest);
        return new RustVerificationRequest(_this35.olmMachine, request, _this35.outgoingRequestProcessor, _this35._supportedVerificationMethods);
      } finally {
        device.free();
      }
    })();
  }
  /**
   * Fetch the backup decryption key we have saved in our store.
   *
   * Implementation of {@link CryptoApi#getSessionBackupPrivateKey}.
   *
   * @returns the key, if any, or null
   */
  getSessionBackupPrivateKey() {
    var _this36 = this;
    return _asyncToGenerator(function* () {
      var backupKeys = yield _this36.olmMachine.getBackupKeys();
      if (!backupKeys.decryptionKey) return null;
      return decodeBase64(backupKeys.decryptionKey.toBase64());
    })();
  }
  /**
   * Store the backup decryption key.
   *
   * Implementation of {@link CryptoApi#storeSessionBackupPrivateKey}.
   *
   * @param key - the backup decryption key
   * @param version - the backup version for this key.
   */
  storeSessionBackupPrivateKey(key, version) {
    var _this37 = this;
    return _asyncToGenerator(function* () {
      var base64Key = encodeBase64(key);
      if (!version) {
        throw new Error("storeSessionBackupPrivateKey: version is required");
      }
      yield _this37.backupManager.saveBackupDecryptionKey(BackupDecryptionKey.fromBase64(base64Key), version);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#loadSessionBackupPrivateKeyFromSecretStorage}.
   */
  loadSessionBackupPrivateKeyFromSecretStorage() {
    var _this38 = this;
    return _asyncToGenerator(function* () {
      var backupKey = yield _this38.secretStorage.get("m.megolm_backup.v1");
      if (!backupKey) {
        throw new Error("loadSessionBackupPrivateKeyFromSecretStorage: missing decryption key in secret storage");
      }
      var keyBackupInfo = yield _this38.backupManager.getServerBackupInfo();
      if (!keyBackupInfo || !keyBackupInfo.version) {
        throw new Error("loadSessionBackupPrivateKeyFromSecretStorage: unable to get backup version");
      }
      var backupDecryptionKey = BackupDecryptionKey.fromBase64(backupKey);
      if (!decryptionKeyMatchesKeyBackupInfo(backupDecryptionKey, keyBackupInfo)) {
        throw new Error("loadSessionBackupPrivateKeyFromSecretStorage: decryption key does not match backup info");
      }
      yield _this38.backupManager.saveBackupDecryptionKey(backupDecryptionKey, keyBackupInfo.version);
    })();
  }
  /**
   * Get the current status of key backup.
   *
   * Implementation of {@link CryptoApi#getActiveSessionBackupVersion}.
   */
  getActiveSessionBackupVersion() {
    var _this39 = this;
    return _asyncToGenerator(function* () {
      return yield _this39.backupManager.getActiveBackupVersion();
    })();
  }
  /**
   * Implementation of {@link CryptoApi#getKeyBackupInfo}.
   */
  getKeyBackupInfo() {
    var _this40 = this;
    return _asyncToGenerator(function* () {
      return (yield _this40.backupManager.getServerBackupInfo()) || null;
    })();
  }
  /**
   * Determine if a key backup can be trusted.
   *
   * Implementation of {@link CryptoApi#isKeyBackupTrusted}.
   */
  isKeyBackupTrusted(info) {
    var _this41 = this;
    return _asyncToGenerator(function* () {
      return yield _this41.backupManager.isKeyBackupTrusted(info);
    })();
  }
  /**
   * Force a re-check of the key backup and enable/disable it as appropriate.
   *
   * Implementation of {@link CryptoApi#checkKeyBackupAndEnable}.
   */
  checkKeyBackupAndEnable() {
    var _this42 = this;
    return _asyncToGenerator(function* () {
      return yield _this42.backupManager.checkKeyBackupAndEnable(true);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#deleteKeyBackupVersion}.
   */
  deleteKeyBackupVersion(version) {
    var _this43 = this;
    return _asyncToGenerator(function* () {
      yield _this43.backupManager.deleteKeyBackupVersion(version);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#resetKeyBackup}.
   */
  resetKeyBackup() {
    var _this44 = this;
    return _asyncToGenerator(function* () {
      var backupInfo = yield _this44.backupManager.setupKeyBackup((o) => _this44.signObject(o));
      if (yield _this44.secretStorageHasAESKey()) {
        yield _this44.secretStorage.store("m.megolm_backup.v1", backupInfo.decryptionKey.toBase64());
      }
      _this44.checkKeyBackupAndEnable();
    })();
  }
  /**
   * Implementation of {@link CryptoApi#disableKeyStorage}.
   */
  disableKeyStorage() {
    var _this45 = this;
    return _asyncToGenerator(function* () {
      var info = yield _this45.getKeyBackupInfo();
      if (info !== null && info !== void 0 && info.version) {
        yield _this45.deleteKeyBackupVersion(info.version);
      } else {
        logger.error("Can't delete key backup version: no version available");
      }
      yield _this45.deleteSecretStorage();
      yield _this45.dehydratedDeviceManager.delete();
    })();
  }
  /**
   * Signs the given object with the current device and current identity (if available).
   * As defined in {@link https://spec.matrix.org/v1.8/appendices/#signing-json | Signing JSON}.
   *
   * Helper for {@link RustCrypto#resetKeyBackup}.
   *
   * @param obj - The object to sign
   */
  signObject(obj) {
    var _this46 = this;
    return _asyncToGenerator(function* () {
      var sigs = new Map(Object.entries(obj.signatures || {}));
      var unsigned = obj.unsigned;
      delete obj.signatures;
      delete obj.unsigned;
      var userSignatures = sigs.get(_this46.userId) || {};
      var canonalizedJson = anotherjson.stringify(obj);
      var signatures = yield _this46.olmMachine.sign(canonalizedJson);
      var map = JSON.parse(signatures.asJSON());
      sigs.set(_this46.userId, _objectSpread$1(_objectSpread$1({}, userSignatures), map[_this46.userId]));
      if (unsigned !== void 0) obj.unsigned = unsigned;
      obj.signatures = Object.fromEntries(sigs.entries());
    })();
  }
  /**
   * Implementation of {@link CryptoApi#restoreKeyBackupWithPassphrase}.
   */
  restoreKeyBackupWithPassphrase(passphrase, opts) {
    var _this47 = this;
    return _asyncToGenerator(function* () {
      var backupInfo = yield _this47.backupManager.getServerBackupInfo();
      if (!(backupInfo !== null && backupInfo !== void 0 && backupInfo.version)) {
        throw new Error("No backup info available");
      }
      var privateKey = yield keyFromAuthData(backupInfo.auth_data, passphrase);
      yield _this47.storeSessionBackupPrivateKey(privateKey, backupInfo.version);
      return _this47.restoreKeyBackup(opts);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#restoreKeyBackup}.
   */
  restoreKeyBackup(opts) {
    var _this48 = this;
    return _asyncToGenerator(function* () {
      var backupKeys = yield _this48.olmMachine.getBackupKeys();
      var {
        decryptionKey,
        backupVersion
      } = backupKeys;
      if (!decryptionKey || !backupVersion) throw new Error("No decryption key found in crypto store");
      var decodedDecryptionKey = decodeBase64(decryptionKey.toBase64());
      var backupInfo = yield _this48.backupManager.requestKeyBackupVersion(backupVersion);
      if (!backupInfo) throw new Error("Backup version to restore ".concat(backupVersion, " not found on server"));
      var backupDecryptor = yield _this48.getBackupDecryptor(backupInfo, decodedDecryptionKey);
      try {
        var _opts$progressCallbac;
        opts === null || opts === void 0 || (_opts$progressCallbac = opts.progressCallback) === null || _opts$progressCallbac === void 0 || _opts$progressCallbac.call(opts, {
          stage: ImportRoomKeyStage.Fetch
        });
        return yield _this48.backupManager.restoreKeyBackup(backupVersion, backupDecryptor, opts);
      } finally {
        backupDecryptor.free();
      }
    })();
  }
  /**
   * Implementation of {@link CryptoApi#isDehydrationSupported}.
   */
  isDehydrationSupported() {
    var _this49 = this;
    return _asyncToGenerator(function* () {
      return yield _this49.dehydratedDeviceManager.isSupported();
    })();
  }
  /**
   * Implementation of {@link CryptoApi#startDehydration}.
   */
  startDehydration() {
    var _arguments6 = arguments, _this50 = this;
    return _asyncToGenerator(function* () {
      var opts = _arguments6.length > 0 && _arguments6[0] !== void 0 ? _arguments6[0] : {};
      if (!(yield _this50.isCrossSigningReady()) || !(yield _this50.isSecretStorageReady())) {
        throw new Error("Device dehydration requires cross-signing and secret storage to be set up");
      }
      return yield _this50.dehydratedDeviceManager.start(opts || {});
    })();
  }
  /**
   * Implementation of {@link CryptoApi#importSecretsBundle}.
   */
  importSecretsBundle(secrets) {
    var _this51 = this;
    return _asyncToGenerator(function* () {
      var secretsBundle = SecretsBundle.from_json(secrets);
      yield _this51.getOlmMachineOrThrow().importSecretsBundle(secretsBundle);
    })();
  }
  /**
   * Implementation of {@link CryptoApi#exportSecretsBundle}.
   */
  exportSecretsBundle() {
    var _this52 = this;
    return _asyncToGenerator(function* () {
      var secretsBundle = yield _this52.getOlmMachineOrThrow().exportSecretsBundle();
      var secrets = secretsBundle.to_json();
      secretsBundle.free();
      return secrets;
    })();
  }
  /**
   * Implementation of {@link CryptoApi#encryptToDeviceMessages}.
   */
  encryptToDeviceMessages(eventType, devices, payload) {
    var _this53 = this;
    return _asyncToGenerator(function* () {
      var logger2 = new LogSpan(_this53.logger, "encryptToDeviceMessages");
      var uniqueUsers = new Set(devices.map((_ref2) => {
        var {
          userId
        } = _ref2;
        return userId;
      }));
      yield _this53.keyClaimManager.ensureSessionsForUsers(logger2, Array.from(uniqueUsers).map((userId) => new UserId(userId)));
      var batch = {
        batch: [],
        eventType: EventType.RoomMessageEncrypted
      };
      yield Promise.all(devices.map(/* @__PURE__ */ function() {
        var _ref4 = _asyncToGenerator(function* (_ref3) {
          var {
            userId,
            deviceId
          } = _ref3;
          var device = yield _this53.olmMachine.getDevice(new UserId(userId), new DeviceId(deviceId));
          if (device) {
            var encryptedPayload = JSON.parse(yield device.encryptToDeviceEvent(eventType, payload));
            batch.batch.push({
              deviceId,
              userId,
              payload: encryptedPayload
            });
          } else {
            _this53.logger.warn("encryptToDeviceMessages: unknown device ".concat(userId, ":").concat(deviceId));
          }
        });
        return function(_x) {
          return _ref4.apply(this, arguments);
        };
      }()));
      return batch;
    })();
  }
  /**
   * Implementation of {@link CryptoApi#resetEncryption}.
   */
  resetEncryption(authUploadDeviceSigningKeys) {
    var _this54 = this;
    return _asyncToGenerator(function* () {
      _this54.logger.debug("resetEncryption: resetting encryption");
      _this54.dehydratedDeviceManager.delete();
      yield _this54.backupManager.deleteAllKeyBackupVersions();
      yield _this54.deleteSecretStorage();
      yield _this54.crossSigningIdentity.bootstrapCrossSigning({
        setupNewCrossSigning: true,
        authUploadDeviceSigningKeys
      });
      yield _this54.resetKeyBackup();
      _this54.logger.debug("resetEncryption: ended");
    })();
  }
  /**
   * Removes the secret storage key, default key pointer and all (known) secret storage data
   * from the user's account data
   */
  deleteSecretStorage() {
    var _this55 = this;
    return _asyncToGenerator(function* () {
      yield _this55.secretStorage.store("m.cross_signing.master", null);
      yield _this55.secretStorage.store("m.cross_signing.self_signing", null);
      yield _this55.secretStorage.store("m.cross_signing.user_signing", null);
      yield _this55.secretStorage.store("m.megolm_backup.v1", null);
      var defaultKeyId = yield _this55.secretStorage.getDefaultKeyId();
      if (defaultKeyId) yield _this55.secretStorage.store("m.secret_storage.key.".concat(defaultKeyId), null);
      yield _this55.secretStorage.setDefaultKeyId(null);
    })();
  }
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // SyncCryptoCallbacks implementation
  //
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  /**
   * Apply sync changes to the olm machine
   * @param events - the received to-device messages
   * @param oneTimeKeysCounts - the received one time key counts
   * @param unusedFallbackKeys - the received unused fallback keys
   * @param devices - the received device list updates
   * @returns A list of preprocessed to-device messages.
   */
  receiveSyncChanges(_ref5) {
    var _this56 = this;
    return _asyncToGenerator(function* () {
      var {
        events,
        oneTimeKeysCounts = /* @__PURE__ */ new Map(),
        unusedFallbackKeys,
        devices = new DeviceLists()
      } = _ref5;
      var result = yield logDuration(logger, "receiveSyncChanges", /* @__PURE__ */ _asyncToGenerator(function* () {
        return yield _this56.olmMachine.receiveSyncChanges(events ? JSON.stringify(events) : "[]", devices, oneTimeKeysCounts, unusedFallbackKeys);
      }));
      return JSON.parse(result);
    })();
  }
  /** called by the sync loop to preprocess incoming to-device messages
   *
   * @param events - the received to-device messages
   * @returns A list of preprocessed to-device messages.
   */
  preprocessToDeviceMessages(events) {
    var _this57 = this;
    return _asyncToGenerator(function* () {
      var processed = yield _this57.receiveSyncChanges({
        events
      });
      for (var message of processed) {
        if (message.type === EventType.KeyVerificationRequest) {
          var sender = message.sender;
          var transactionId = message.content.transaction_id;
          if (transactionId && sender) {
            _this57.onIncomingKeyVerificationRequest(sender, transactionId);
          }
        }
      }
      return processed;
    })();
  }
  /** called by the sync loop to process one time key counts and unused fallback keys
   *
   * @param oneTimeKeysCounts - the received one time key counts
   * @param unusedFallbackKeys - the received unused fallback keys
   */
  processKeyCounts(oneTimeKeysCounts, unusedFallbackKeys) {
    var _this58 = this;
    return _asyncToGenerator(function* () {
      var mapOneTimeKeysCount = oneTimeKeysCounts && new Map(Object.entries(oneTimeKeysCounts));
      var setUnusedFallbackKeys = unusedFallbackKeys && new Set(unusedFallbackKeys);
      if (mapOneTimeKeysCount !== void 0 || setUnusedFallbackKeys !== void 0) {
        yield _this58.receiveSyncChanges({
          oneTimeKeysCounts: mapOneTimeKeysCount,
          unusedFallbackKeys: setUnusedFallbackKeys
        });
      }
    })();
  }
  /** called by the sync loop to process the notification that device lists have
   * been changed.
   *
   * @param deviceLists - device_lists field from /sync
   */
  processDeviceLists(deviceLists) {
    var _this59 = this;
    return _asyncToGenerator(function* () {
      var _deviceLists$changed, _deviceLists$left;
      var devices = new DeviceLists((_deviceLists$changed = deviceLists.changed) === null || _deviceLists$changed === void 0 ? void 0 : _deviceLists$changed.map((userId) => new UserId(userId)), (_deviceLists$left = deviceLists.left) === null || _deviceLists$left === void 0 ? void 0 : _deviceLists$left.map((userId) => new UserId(userId)));
      yield _this59.receiveSyncChanges({
        devices
      });
    })();
  }
  /** called by the sync loop on m.room.encrypted events
   *
   * @param room - in which the event was received
   * @param event - encryption event to be processed
   */
  onCryptoEvent(room, event) {
    var _this60 = this;
    return _asyncToGenerator(function* () {
      var config = event.getContent();
      var settings = new RoomSettings();
      if (config.algorithm === "m.megolm.v1.aes-sha2") {
        settings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
      } else {
        _this60.logger.warn("Room ".concat(room.roomId, ": ignoring crypto event with invalid algorithm ").concat(config.algorithm));
        return;
      }
      try {
        settings.sessionRotationPeriodMs = config.rotation_period_ms;
        settings.sessionRotationPeriodMessages = config.rotation_period_msgs;
        yield _this60.olmMachine.setRoomSettings(new RoomId(room.roomId), settings);
      } catch (e) {
        _this60.logger.warn("Room ".concat(room.roomId, ": ignoring crypto event which caused error: ").concat(e));
        return;
      }
      var existingEncryptor = _this60.roomEncryptors[room.roomId];
      if (existingEncryptor) {
        existingEncryptor.onCryptoEvent(config);
      } else {
        _this60.roomEncryptors[room.roomId] = new RoomEncryptor(_this60.olmMachine, _this60.keyClaimManager, _this60.outgoingRequestsManager, room, config);
      }
    })();
  }
  /** called by the sync loop after processing each sync.
   *
   *
   * @param syncState - information on the completed sync.
   */
  onSyncCompleted(syncState) {
    this.outgoingRequestsManager.doProcessOutgoingRequests().catch((e) => {
      this.logger.warn("onSyncCompleted: Error processing outgoing requests", e);
    });
  }
  /**
   * Implementation of {@link CryptoApi#markAllTrackedUsersAsDirty}.
   */
  markAllTrackedUsersAsDirty() {
    var _this61 = this;
    return _asyncToGenerator(function* () {
      yield _this61.olmMachine.markAllTrackedUsersAsDirty();
    })();
  }
  /**
   * Handle an incoming m.key.verification.request event, received either in-room or in a to-device message.
   *
   * @param sender - the sender of the event
   * @param transactionId - the transaction ID for the verification. For to-device messages, this comes from the
   *    content of the message; for in-room messages it is the event ID.
   */
  onIncomingKeyVerificationRequest(sender, transactionId) {
    var request = this.olmMachine.getVerificationRequest(new UserId(sender), transactionId);
    if (request) {
      this.emit(CryptoEvent.VerificationRequestReceived, new RustVerificationRequest(this.olmMachine, request, this.outgoingRequestProcessor, this._supportedVerificationMethods));
    } else {
      this.logger.info("Ignoring just-received verification request ".concat(transactionId, " which did not start a rust-side verification"));
    }
  }
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // Other public functions
  //
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  /** called by the MatrixClient on a room membership event
   *
   * @param event - The matrix event which caused this event to fire.
   * @param member - The member whose RoomMember.membership changed.
   * @param oldMembership - The previous membership state. Null if it's a new member.
   */
  onRoomMembership(event, member, oldMembership) {
    var enc = this.roomEncryptors[event.getRoomId()];
    if (!enc) {
      return;
    }
    enc.onRoomMembership(member);
  }
  /** Callback for OlmMachine.registerRoomKeyUpdatedCallback
   *
   * Called by the rust-sdk whenever there is an update to (megolm) room keys. We
   * check if we have any events waiting for the given keys, and schedule them for
   * a decryption retry if so.
   *
   * @param keys - details of the updated keys
   */
  onRoomKeysUpdated(keys) {
    var _this62 = this;
    return _asyncToGenerator(function* () {
      for (var key of keys) {
        _this62.onRoomKeyUpdated(key);
      }
      _this62.backupManager.maybeUploadKey();
    })();
  }
  onRoomKeyUpdated(key) {
    var _this63 = this;
    if (this.stopped) return;
    this.logger.debug("Got update for session ".concat(key.sessionId, " from sender ").concat(key.senderKey.toBase64(), " in ").concat(key.roomId.toString()));
    var pendingList = this.eventDecryptor.getEventsPendingRoomKey(key.roomId.toString(), key.sessionId);
    if (pendingList.length === 0) return;
    this.logger.debug("Retrying decryption on events:", pendingList.map((e) => "".concat(e.getId())));
    var _loop = function _loop2(ev2) {
      ev2.attemptDecryption(_this63, {
        isRetry: true
      }).catch((_e) => {
        _this63.logger.info("Still unable to decrypt event ".concat(ev2.getId(), " after receiving key"));
      });
    };
    for (var ev of pendingList) {
      _loop(ev);
    }
  }
  /**
   * Callback for `OlmMachine.registerRoomKeyWithheldCallback`.
   *
   * Called by the rust sdk whenever we are told that a key has been withheld. We see if we had any events that
   * failed to decrypt for the given session, and update their status if so.
   *
   * @param withheld - Details of the withheld sessions.
   */
  onRoomKeysWithheld(withheld) {
    var _this64 = this;
    return _asyncToGenerator(function* () {
      for (var session of withheld) {
        _this64.logger.debug("Got withheld message for session ".concat(session.sessionId, " in ").concat(session.roomId.toString()));
        var pendingList = _this64.eventDecryptor.getEventsPendingRoomKey(session.roomId.toString(), session.sessionId);
        if (pendingList.length === 0) return;
        _this64.logger.debug("Retrying decryption on events:", pendingList.map((e) => "".concat(e.getId())));
        for (var ev of pendingList) {
          ev.attemptDecryption(_this64, {
            isRetry: true
          }).catch((_e) => {
          });
        }
      }
    })();
  }
  /**
   * Callback for `OlmMachine.registerUserIdentityUpdatedCallback`
   *
   * Called by the rust-sdk whenever there is an update to any user's cross-signing status. We re-check their trust
   * status and emit a `UserTrustStatusChanged` event, as well as a `KeysChanged` if it is our own identity that changed.
   *
   * @param userId - the user with the updated identity
   */
  onUserIdentityUpdated(userId) {
    var _this65 = this;
    return _asyncToGenerator(function* () {
      var newVerification = yield _this65.getUserVerificationStatus(userId.toString());
      _this65.emit(CryptoEvent.UserTrustStatusChanged, userId.toString(), newVerification);
      if (userId.toString() === _this65.userId) {
        _this65.emit(CryptoEvent.KeysChanged, {});
        yield _this65.checkKeyBackupAndEnable();
      }
    })();
  }
  /**
   * Callback for `OlmMachine.registerDevicesUpdatedCallback`
   *
   * Called when users' devices have updated. Emits `WillUpdateDevices` and `DevicesUpdated`. In the JavaScript
   * crypto backend, these events are called at separate times, with `WillUpdateDevices` being emitted just before
   * the devices are saved, and `DevicesUpdated` being emitted just after. But the OlmMachine only gives us
   * one event, so we emit both events here.
   *
   * @param userIds - an array of user IDs of users whose devices have updated.
   */
  onDevicesUpdated(userIds) {
    var _this66 = this;
    return _asyncToGenerator(function* () {
      _this66.emit(CryptoEvent.WillUpdateDevices, userIds, false);
      _this66.emit(CryptoEvent.DevicesUpdated, userIds, false);
    })();
  }
  /**
   * Handles secret received from the rust secret inbox.
   *
   * The gossipped secrets are received using the `m.secret.send` event type
   * and are guaranteed to have been received over a 1-to-1 Olm
   * Session from a verified device.
   *
   * The only secret currently handled in this way is `m.megolm_backup.v1`.
   *
   * @param name - the secret name
   * @param value - the secret value
   */
  handleSecretReceived(name, value) {
    var _this67 = this;
    return _asyncToGenerator(function* () {
      _this67.logger.debug("onReceiveSecret: Received secret ".concat(name));
      if (name === "m.megolm_backup.v1") {
        return yield _this67.backupManager.handleBackupSecretReceived(value);
      }
      return false;
    })();
  }
  /**
   * Called when a new secret is received in the rust secret inbox.
   *
   * Will poll the secret inbox and handle the secrets received.
   *
   * @param name - The name of the secret received.
   */
  checkSecrets(name) {
    var _this68 = this;
    return _asyncToGenerator(function* () {
      var pendingValues = yield _this68.olmMachine.getSecretsFromInbox(name);
      for (var value of pendingValues) {
        if (yield _this68.handleSecretReceived(name, value)) {
          break;
        }
      }
      yield _this68.olmMachine.deleteSecretsFromInbox(name);
    })();
  }
  /**
   * Handle a live event received via /sync.
   * See {@link ClientEventHandlerMap#event}
   *
   * @param event - live event
   */
  onLiveEventFromSync(event) {
    var _this69 = this;
    return _asyncToGenerator(function* () {
      if (event.isState() || !!event.getUnsigned().transaction_id) return;
      var processEvent = /* @__PURE__ */ function() {
        var _ref7 = _asyncToGenerator(function* (evt) {
          if (isVerificationEvent(event)) {
            yield _this69.onKeyVerificationEvent(evt);
          }
        });
        return function processEvent2(_x2) {
          return _ref7.apply(this, arguments);
        };
      }();
      if (event.isDecryptionFailure() || event.isEncrypted()) {
        var TIMEOUT_DELAY = 5 * 60 * 1e3;
        var timeoutId = setTimeout(() => event.off(MatrixEventEvent.Decrypted, onDecrypted), TIMEOUT_DELAY);
        var onDecrypted = (decryptedEvent, error) => {
          if (error) return;
          clearTimeout(timeoutId);
          event.off(MatrixEventEvent.Decrypted, onDecrypted);
          processEvent(decryptedEvent);
        };
        event.on(MatrixEventEvent.Decrypted, onDecrypted);
      } else {
        yield processEvent(event);
      }
    })();
  }
  /**
   * Handle an in-room key verification event.
   *
   * @param event - a key validation request event.
   */
  onKeyVerificationEvent(event) {
    var _this70 = this;
    return _asyncToGenerator(function* () {
      var roomId = event.getRoomId();
      if (!roomId) {
        throw new Error("missing roomId in the event");
      }
      _this70.logger.debug("Incoming verification event ".concat(event.getId(), " type ").concat(event.getType(), " from ").concat(event.getSender()));
      yield _this70.olmMachine.receiveVerificationEvent(JSON.stringify({
        event_id: event.getId(),
        type: event.getType(),
        sender: event.getSender(),
        state_key: event.getStateKey(),
        content: event.getContent(),
        origin_server_ts: event.getTs()
      }), new RoomId(roomId));
      if (event.getType() === EventType.RoomMessage && event.getContent().msgtype === MsgType.KeyVerificationRequest) {
        _this70.onIncomingKeyVerificationRequest(event.getSender(), event.getId());
      }
      _this70.outgoingRequestsManager.doProcessOutgoingRequests().catch((e) => {
        _this70.logger.warn("onKeyVerificationRequest: Error processing outgoing requests", e);
      });
    })();
  }
  /**
   * Returns the cross-signing user identity of the current user.
   *
   * Not part of the public crypto-api interface.
   * Used during migration from legacy js-crypto to update local trust if needed.
   */
  getOwnIdentity() {
    var _this71 = this;
    return _asyncToGenerator(function* () {
      return yield _this71.olmMachine.getIdentity(new UserId(_this71.userId));
    })();
  }
}
class EventDecryptor {
  constructor(logger2, olmMachine, perSessionBackupDownloader) {
    this.logger = logger2;
    this.olmMachine = olmMachine;
    this.perSessionBackupDownloader = perSessionBackupDownloader;
    _defineProperty(this, "eventsPendingKey", new MapWithDefault(() => new MapWithDefault(() => /* @__PURE__ */ new Set())));
  }
  attemptEventDecryption(event, isolationMode) {
    var _this72 = this;
    return _asyncToGenerator(function* () {
      _this72.addEventToPendingList(event);
      var trustRequirement;
      switch (isolationMode.kind) {
        case DeviceIsolationModeKind.AllDevicesIsolationMode:
          trustRequirement = TrustRequirement.Untrusted;
          break;
        case DeviceIsolationModeKind.OnlySignedDevicesIsolationMode:
          trustRequirement = TrustRequirement.CrossSignedOrLegacy;
          break;
      }
      try {
        var res = yield _this72.olmMachine.decryptRoomEvent(stringifyEvent(event), new RoomId(event.getRoomId()), new DecryptionSettings(trustRequirement));
        _this72.removeEventFromPendingList(event);
        return {
          clearEvent: JSON.parse(res.event),
          claimedEd25519Key: res.senderClaimedEd25519Key,
          senderCurve25519Key: res.senderCurve25519Key,
          forwardingCurve25519KeyChain: res.forwardingCurve25519KeyChain
        };
      } catch (err) {
        if (err instanceof MegolmDecryptionError) {
          _this72.onMegolmDecryptionError(event, err, yield _this72.perSessionBackupDownloader.getServerBackupInfo());
        } else {
          throw new DecryptionError(DecryptionFailureCode.UNKNOWN_ERROR, "Unknown error");
        }
      }
    })();
  }
  /**
   * Handle a `MegolmDecryptionError` returned by the rust SDK.
   *
   * Fires off a request to the `perSessionBackupDownloader`, if appropriate, and then throws a `DecryptionError`.
   *
   * @param event - The event which could not be decrypted.
   * @param err - The error from the Rust SDK.
   * @param serverBackupInfo - Details about the current backup from the server. `null` if there is no backup.
   *     `undefined` if our attempt to check failed.
   */
  onMegolmDecryptionError(event, err, serverBackupInfo) {
    var content = event.getWireContent();
    var errorDetails = {
      sender_key: content.sender_key,
      session_id: content.session_id
    };
    if (err.code === DecryptionErrorCode.MissingRoomKey || err.code === DecryptionErrorCode.UnknownMessageIndex) {
      this.perSessionBackupDownloader.onDecryptionKeyMissingError(event.getRoomId(), content.session_id);
      var membership = event.getMembershipAtEvent();
      if (membership && membership !== KnownMembership.Join && membership !== KnownMembership.Invite) {
        throw new DecryptionError(DecryptionFailureCode.HISTORICAL_MESSAGE_USER_NOT_JOINED, "This message was sent when we were not a member of the room.", errorDetails);
      }
      if (event.getTs() <= this.olmMachine.deviceCreationTimeMs) {
        if (serverBackupInfo === null) {
          throw new DecryptionError(DecryptionFailureCode.HISTORICAL_MESSAGE_NO_KEY_BACKUP, "This message was sent before this device logged in, and there is no key backup on the server.", errorDetails);
        } else if (!this.perSessionBackupDownloader.isKeyBackupDownloadConfigured()) {
          throw new DecryptionError(DecryptionFailureCode.HISTORICAL_MESSAGE_BACKUP_UNCONFIGURED, "This message was sent before this device logged in, and key backup is not working.", errorDetails);
        } else {
          throw new DecryptionError(DecryptionFailureCode.HISTORICAL_MESSAGE_WORKING_BACKUP, "This message was sent before this device logged in. Key backup is working, but we still do not (yet) have the key.", errorDetails);
        }
      }
    }
    if (err.maybe_withheld) {
      var failureCode = err.maybe_withheld === "The sender has disabled encrypting to unverified devices." ? DecryptionFailureCode.MEGOLM_KEY_WITHHELD_FOR_UNVERIFIED_DEVICE : DecryptionFailureCode.MEGOLM_KEY_WITHHELD;
      throw new DecryptionError(failureCode, err.maybe_withheld, errorDetails);
    }
    switch (err.code) {
      case DecryptionErrorCode.MissingRoomKey:
        throw new DecryptionError(DecryptionFailureCode.MEGOLM_UNKNOWN_INBOUND_SESSION_ID, "The sender's device has not sent us the keys for this message.", errorDetails);
      case DecryptionErrorCode.UnknownMessageIndex:
        throw new DecryptionError(DecryptionFailureCode.OLM_UNKNOWN_MESSAGE_INDEX, "The sender's device has not sent us the keys for this message at this index.", errorDetails);
      case DecryptionErrorCode.SenderIdentityVerificationViolation:
        this.removeEventFromPendingList(event);
        throw new DecryptionError(DecryptionFailureCode.SENDER_IDENTITY_PREVIOUSLY_VERIFIED, "The sender identity is unverified, but was previously verified.");
      case DecryptionErrorCode.UnknownSenderDevice:
        this.removeEventFromPendingList(event);
        throw new DecryptionError(DecryptionFailureCode.UNKNOWN_SENDER_DEVICE, "The sender device is not known.");
      case DecryptionErrorCode.UnsignedSenderDevice:
        this.removeEventFromPendingList(event);
        throw new DecryptionError(DecryptionFailureCode.UNSIGNED_SENDER_DEVICE, "The sender identity is not cross-signed.");
      default:
        throw new DecryptionError(DecryptionFailureCode.UNKNOWN_ERROR, err.description, errorDetails);
    }
  }
  getEncryptionInfoForEvent(event) {
    var _this73 = this;
    return _asyncToGenerator(function* () {
      if (!event.getClearContent() || event.isDecryptionFailure()) {
        return null;
      }
      if (event.status !== null) {
        return {
          shieldColour: EventShieldColour.NONE,
          shieldReason: null
        };
      }
      var encryptionInfo = yield _this73.olmMachine.getRoomEventEncryptionInfo(stringifyEvent(event), new RoomId(event.getRoomId()));
      return rustEncryptionInfoToJsEncryptionInfo(_this73.logger, encryptionInfo);
    })();
  }
  /**
   * Look for events which are waiting for a given megolm session
   *
   * Returns a list of events which were encrypted by `session` and could not be decrypted
   */
  getEventsPendingRoomKey(roomId, sessionId) {
    var roomPendingEvents = this.eventsPendingKey.get(roomId);
    if (!roomPendingEvents) return [];
    var sessionPendingEvents = roomPendingEvents.get(sessionId);
    if (!sessionPendingEvents) return [];
    return [...sessionPendingEvents];
  }
  /**
   * Add an event to the list of those awaiting their session keys.
   */
  addEventToPendingList(event) {
    var roomId = event.getRoomId();
    if (!roomId) return;
    var roomPendingEvents = this.eventsPendingKey.getOrCreate(roomId);
    var sessionPendingEvents = roomPendingEvents.getOrCreate(event.getWireContent().session_id);
    sessionPendingEvents.add(event);
  }
  /**
   * Remove an event from the list of those awaiting their session keys.
   */
  removeEventFromPendingList(event) {
    var roomId = event.getRoomId();
    if (!roomId) return;
    var roomPendingEvents = this.eventsPendingKey.getOrCreate(roomId);
    if (!roomPendingEvents) return;
    var sessionPendingEvents = roomPendingEvents.get(event.getWireContent().session_id);
    if (!sessionPendingEvents) return;
    sessionPendingEvents.delete(event);
    if (sessionPendingEvents.size === 0) {
      roomPendingEvents.delete(event.getWireContent().session_id);
      if (roomPendingEvents.size === 0) {
        this.eventsPendingKey.delete(roomId);
      }
    }
  }
}
function stringifyEvent(event) {
  return JSON.stringify({
    event_id: event.getId(),
    type: event.getWireType(),
    sender: event.getSender(),
    state_key: event.getStateKey(),
    content: event.getWireContent(),
    origin_server_ts: event.getTs()
  });
}
function rustEncryptionInfoToJsEncryptionInfo(logger2, encryptionInfo) {
  if (encryptionInfo === void 0) {
    return null;
  }
  var shieldState = encryptionInfo.shieldState(false);
  var shieldColour;
  switch (shieldState.color) {
    case ShieldColor.Grey:
      shieldColour = EventShieldColour.GREY;
      break;
    case ShieldColor.None:
      shieldColour = EventShieldColour.NONE;
      break;
    default:
      shieldColour = EventShieldColour.RED;
  }
  var shieldReason;
  switch (shieldState.code) {
    case void 0:
    case null:
      shieldReason = null;
      break;
    case ShieldStateCode.AuthenticityNotGuaranteed:
      shieldReason = EventShieldReason.AUTHENTICITY_NOT_GUARANTEED;
      break;
    case ShieldStateCode.UnknownDevice:
      shieldReason = EventShieldReason.UNKNOWN_DEVICE;
      break;
    case ShieldStateCode.UnsignedDevice:
      shieldReason = EventShieldReason.UNSIGNED_DEVICE;
      break;
    case ShieldStateCode.UnverifiedIdentity:
      shieldReason = EventShieldReason.UNVERIFIED_IDENTITY;
      break;
    case ShieldStateCode.SentInClear:
      shieldReason = EventShieldReason.SENT_IN_CLEAR;
      break;
    case ShieldStateCode.VerificationViolation:
      shieldReason = EventShieldReason.VERIFICATION_VIOLATION;
      break;
  }
  return {
    shieldColour,
    shieldReason
  };
}
function migrateFromLegacyCrypto(_x) {
  return _migrateFromLegacyCrypto.apply(this, arguments);
}
function _migrateFromLegacyCrypto() {
  _migrateFromLegacyCrypto = _asyncToGenerator(function* (args) {
    var _args$legacyMigration2;
    var {
      logger: logger2,
      legacyStore
    } = args;
    yield initAsync();
    new Tracing(LoggerLevel.Debug).turnOn();
    if (!(yield legacyStore.containsData())) {
      return;
    }
    yield legacyStore.startup();
    var accountPickle = null;
    yield legacyStore.doTxn("readonly", [IndexedDBCryptoStore.STORE_ACCOUNT], (txn) => {
      legacyStore.getAccount(txn, (acctPickle) => {
        accountPickle = acctPickle;
      });
    });
    if (!accountPickle) {
      logger2.debug("Legacy crypto store is not set up (no account found). Not migrating.");
      return;
    }
    var migrationState = yield legacyStore.getMigrationState();
    if (migrationState >= MigrationState.MEGOLM_SESSIONS_MIGRATED) {
      return;
    }
    var nOlmSessions = yield countOlmSessions(logger2, legacyStore);
    var nMegolmSessions = yield countMegolmSessions(logger2, legacyStore);
    var totalSteps = 1 + nOlmSessions + nMegolmSessions;
    logger2.info("Migrating data from legacy crypto store. ".concat(nOlmSessions, " olm sessions and ").concat(nMegolmSessions, " megolm sessions to migrate."));
    var stepsDone = 0;
    function onProgress(steps) {
      var _args$legacyMigration;
      stepsDone += steps;
      (_args$legacyMigration = args.legacyMigrationProgressListener) === null || _args$legacyMigration === void 0 || _args$legacyMigration.call(args, stepsDone, totalSteps);
    }
    onProgress(0);
    var pickleKey = new TextEncoder().encode(args.legacyPickleKey);
    if (migrationState === MigrationState.NOT_STARTED) {
      logger2.info("Migrating data from legacy crypto store. Step 1: base data");
      yield migrateBaseData(args.http, args.userId, args.deviceId, legacyStore, pickleKey, args.storeHandle, logger2);
      migrationState = MigrationState.INITIAL_DATA_MIGRATED;
      yield legacyStore.setMigrationState(migrationState);
    }
    onProgress(1);
    if (migrationState === MigrationState.INITIAL_DATA_MIGRATED) {
      logger2.info("Migrating data from legacy crypto store. Step 2: olm sessions (".concat(nOlmSessions, " sessions to migrate)."));
      yield migrateOlmSessions(logger2, legacyStore, pickleKey, args.storeHandle, onProgress);
      migrationState = MigrationState.OLM_SESSIONS_MIGRATED;
      yield legacyStore.setMigrationState(migrationState);
    }
    if (migrationState === MigrationState.OLM_SESSIONS_MIGRATED) {
      logger2.info("Migrating data from legacy crypto store. Step 3: megolm sessions (".concat(nMegolmSessions, " sessions to migrate)."));
      yield migrateMegolmSessions(logger2, legacyStore, pickleKey, args.storeHandle, onProgress);
      migrationState = MigrationState.MEGOLM_SESSIONS_MIGRATED;
      yield legacyStore.setMigrationState(migrationState);
    }
    (_args$legacyMigration2 = args.legacyMigrationProgressListener) === null || _args$legacyMigration2 === void 0 || _args$legacyMigration2.call(args, -1, -1);
    logger2.info("Migration from legacy crypto store complete");
  });
  return _migrateFromLegacyCrypto.apply(this, arguments);
}
function migrateBaseData(_x2, _x3, _x4, _x5, _x6, _x7, _x8) {
  return _migrateBaseData.apply(this, arguments);
}
function _migrateBaseData() {
  _migrateBaseData = _asyncToGenerator(function* (http, userId, deviceId, legacyStore, pickleKey, storeHandle, logger2) {
    var migrationData = new BaseMigrationData();
    migrationData.userId = new UserId(userId);
    migrationData.deviceId = new DeviceId(deviceId);
    yield legacyStore.doTxn("readonly", [IndexedDBCryptoStore.STORE_ACCOUNT], (txn) => legacyStore.getAccount(txn, (a) => {
      migrationData.pickledAccount = a !== null && a !== void 0 ? a : "";
    }));
    var recoveryKey = yield getAndDecryptCachedSecretKey(legacyStore, pickleKey, "m.megolm_backup.v1");
    if (recoveryKey) {
      var backupCallDone = false;
      var backupInfo = null;
      while (!backupCallDone) {
        try {
          backupInfo = yield requestKeyBackupVersion(http);
          backupCallDone = true;
        } catch (e) {
          logger2.info("Failed to get backup version during migration, retrying in 2 seconds", e);
          yield sleep(2e3);
        }
      }
      if (backupInfo && backupInfo.algorithm == "m.megolm_backup.v1.curve25519-aes-sha2") {
        try {
          var _backupInfo$auth_data;
          var decryptionKey = BackupDecryptionKey.fromBase64(recoveryKey);
          var publicKey = (_backupInfo$auth_data = backupInfo.auth_data) === null || _backupInfo$auth_data === void 0 ? void 0 : _backupInfo$auth_data.public_key;
          var isValid = decryptionKey.megolmV1PublicKey.publicKeyBase64 == publicKey;
          if (isValid) {
            migrationData.backupVersion = backupInfo.version;
            migrationData.backupRecoveryKey = recoveryKey;
          } else {
            logger2.debug("The backup key to migrate does not match the active backup version", "Cached pub key: ".concat(decryptionKey.megolmV1PublicKey.publicKeyBase64), "Active pub key: ".concat(publicKey));
          }
        } catch (e) {
          logger2.warn("Failed to check if the backup key to migrate matches the active backup version", e);
        }
      }
    }
    migrationData.privateCrossSigningMasterKey = yield getAndDecryptCachedSecretKey(legacyStore, pickleKey, "master");
    migrationData.privateCrossSigningSelfSigningKey = yield getAndDecryptCachedSecretKey(legacyStore, pickleKey, "self_signing");
    migrationData.privateCrossSigningUserSigningKey = yield getAndDecryptCachedSecretKey(legacyStore, pickleKey, "user_signing");
    yield Migration.migrateBaseData(migrationData, pickleKey, storeHandle);
  });
  return _migrateBaseData.apply(this, arguments);
}
function countOlmSessions(_x9, _x10) {
  return _countOlmSessions.apply(this, arguments);
}
function _countOlmSessions() {
  _countOlmSessions = _asyncToGenerator(function* (logger2, legacyStore) {
    logger2.debug("Counting olm sessions to be migrated");
    var nSessions;
    yield legacyStore.doTxn("readonly", [IndexedDBCryptoStore.STORE_SESSIONS], (txn) => legacyStore.countEndToEndSessions(txn, (n) => nSessions = n));
    return nSessions;
  });
  return _countOlmSessions.apply(this, arguments);
}
function countMegolmSessions(_x11, _x12) {
  return _countMegolmSessions.apply(this, arguments);
}
function _countMegolmSessions() {
  _countMegolmSessions = _asyncToGenerator(function* (logger2, legacyStore) {
    logger2.debug("Counting megolm sessions to be migrated");
    return yield legacyStore.countEndToEndInboundGroupSessions();
  });
  return _countMegolmSessions.apply(this, arguments);
}
function migrateOlmSessions(_x13, _x14, _x15, _x16, _x17) {
  return _migrateOlmSessions.apply(this, arguments);
}
function _migrateOlmSessions() {
  _migrateOlmSessions = _asyncToGenerator(function* (logger2, legacyStore, pickleKey, storeHandle, onBatchDone) {
    while (true) {
      var batch = yield legacyStore.getEndToEndSessionsBatch();
      if (batch === null) return;
      logger2.debug("Migrating batch of ".concat(batch.length, " olm sessions"));
      var migrationData = [];
      for (var session of batch) {
        var pickledSession = new PickledSession();
        pickledSession.senderKey = session.deviceKey;
        pickledSession.pickle = session.session;
        pickledSession.lastUseTime = pickledSession.creationTime = new Date(session.lastReceivedMessageTs);
        migrationData.push(pickledSession);
      }
      yield Migration.migrateOlmSessions(migrationData, pickleKey, storeHandle);
      yield legacyStore.deleteEndToEndSessionsBatch(batch);
      onBatchDone(batch.length);
    }
  });
  return _migrateOlmSessions.apply(this, arguments);
}
function migrateMegolmSessions(_x18, _x19, _x20, _x21, _x22) {
  return _migrateMegolmSessions.apply(this, arguments);
}
function _migrateMegolmSessions() {
  _migrateMegolmSessions = _asyncToGenerator(function* (logger2, legacyStore, pickleKey, storeHandle, onBatchDone) {
    while (true) {
      var batch = yield legacyStore.getEndToEndInboundGroupSessionsBatch();
      if (batch === null) return;
      logger2.debug("Migrating batch of ".concat(batch.length, " megolm sessions"));
      var migrationData = [];
      for (var session of batch) {
        var _sessionData$keysClai;
        var sessionData = session.sessionData;
        var pickledSession = new PickledInboundGroupSession();
        pickledSession.pickle = sessionData.session;
        pickledSession.roomId = new RoomId(sessionData.room_id);
        pickledSession.senderKey = session.senderKey;
        pickledSession.senderSigningKey = (_sessionData$keysClai = sessionData.keysClaimed) === null || _sessionData$keysClai === void 0 ? void 0 : _sessionData$keysClai["ed25519"];
        pickledSession.backedUp = !session.needsBackup;
        pickledSession.imported = sessionData.untrusted === true;
        migrationData.push(pickledSession);
      }
      yield Migration.migrateMegolmSessions(migrationData, pickleKey, storeHandle);
      yield legacyStore.deleteEndToEndInboundGroupSessionsBatch(batch);
      onBatchDone(batch.length);
    }
  });
  return _migrateMegolmSessions.apply(this, arguments);
}
function migrateRoomSettingsFromLegacyCrypto(_x23) {
  return _migrateRoomSettingsFromLegacyCrypto.apply(this, arguments);
}
function _migrateRoomSettingsFromLegacyCrypto() {
  _migrateRoomSettingsFromLegacyCrypto = _asyncToGenerator(function* (_ref) {
    var {
      logger: logger2,
      legacyStore,
      olmMachine
    } = _ref;
    if (!(yield legacyStore.containsData())) {
      return;
    }
    var migrationState = yield legacyStore.getMigrationState();
    if (migrationState >= MigrationState.ROOM_SETTINGS_MIGRATED) {
      return;
    }
    var rooms = {};
    yield legacyStore.doTxn("readwrite", [IndexedDBCryptoStore.STORE_ROOMS], (txn) => {
      legacyStore.getEndToEndRooms(txn, (result) => {
        rooms = result;
      });
    });
    logger2.debug("Migrating ".concat(Object.keys(rooms).length, " sets of room settings"));
    for (var [roomId, legacySettings] of Object.entries(rooms)) {
      try {
        var rustSettings = new RoomSettings();
        if (legacySettings.algorithm !== "m.megolm.v1.aes-sha2") {
          logger2.warn("Room ".concat(roomId, ": ignoring room with invalid algorithm ").concat(legacySettings.algorithm));
          continue;
        }
        rustSettings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
        rustSettings.sessionRotationPeriodMs = legacySettings.rotation_period_ms;
        rustSettings.sessionRotationPeriodMessages = legacySettings.rotation_period_msgs;
        yield olmMachine.setRoomSettings(new RoomId(roomId), rustSettings);
      } catch (e) {
        logger2.warn("Room ".concat(roomId, ": ignoring settings ").concat(JSON.stringify(legacySettings), " which caused error ").concat(e));
      }
    }
    logger2.debug("Completed room settings migration");
    yield legacyStore.setMigrationState(MigrationState.ROOM_SETTINGS_MIGRATED);
  });
  return _migrateRoomSettingsFromLegacyCrypto.apply(this, arguments);
}
function getAndDecryptCachedSecretKey(_x24, _x25, _x26) {
  return _getAndDecryptCachedSecretKey.apply(this, arguments);
}
function _getAndDecryptCachedSecretKey() {
  _getAndDecryptCachedSecretKey = _asyncToGenerator(function* (legacyStore, legacyPickleKey, name) {
    var key = yield new Promise((resolve) => {
      legacyStore.doTxn("readonly", [IndexedDBCryptoStore.STORE_ACCOUNT], (txn) => {
        legacyStore.getSecretStorePrivateKey(txn, resolve, name);
      });
    });
    if (key && key.ciphertext && key.iv && key.mac) {
      return yield decryptAESSecretStorageItem(key, legacyPickleKey, name);
    } else if (key instanceof Uint8Array) {
      return encodeBase64(key);
    } else {
      return void 0;
    }
  });
  return _getAndDecryptCachedSecretKey.apply(this, arguments);
}
function migrateLegacyLocalTrustIfNeeded(_x27) {
  return _migrateLegacyLocalTrustIfNeeded.apply(this, arguments);
}
function _migrateLegacyLocalTrustIfNeeded() {
  _migrateLegacyLocalTrustIfNeeded = _asyncToGenerator(function* (args) {
    var {
      legacyCryptoStore,
      rustCrypto,
      logger: logger2
    } = args;
    var rustOwnIdentity = yield rustCrypto.getOwnIdentity();
    if (!rustOwnIdentity) {
      return;
    }
    if (rustOwnIdentity.isVerified()) {
      return;
    }
    var legacyLocallyTrustedMSK = yield getLegacyTrustedPublicMasterKeyBase64(legacyCryptoStore);
    if (!legacyLocallyTrustedMSK) {
      return;
    }
    var mskInfo = JSON.parse(rustOwnIdentity.masterKey);
    if (!mskInfo.keys || Object.keys(mskInfo.keys).length === 0) {
      logger2.error("Post Migration | Unexpected error: no master key in the rust session.");
      return;
    }
    var rustSeenMSK = Object.values(mskInfo.keys)[0];
    if (rustSeenMSK && rustSeenMSK == legacyLocallyTrustedMSK) {
      logger2.info("Post Migration: Migrating legacy trusted MSK: ".concat(legacyLocallyTrustedMSK, " to locally verified."));
      yield rustOwnIdentity.verify();
    }
  });
  return _migrateLegacyLocalTrustIfNeeded.apply(this, arguments);
}
function getLegacyTrustedPublicMasterKeyBase64(_x28) {
  return _getLegacyTrustedPublicMasterKeyBase.apply(this, arguments);
}
function _getLegacyTrustedPublicMasterKeyBase() {
  _getLegacyTrustedPublicMasterKeyBase = _asyncToGenerator(function* (legacyStore) {
    var maybeTrustedKeys = null;
    yield legacyStore.doTxn("readonly", "account", (txn) => {
      legacyStore.getCrossSigningKeys(txn, (keys) => {
        var msk = keys === null || keys === void 0 ? void 0 : keys.master;
        if (msk && Object.keys(msk.keys).length != 0) {
          maybeTrustedKeys = Object.values(msk.keys)[0];
        }
      });
    });
    return maybeTrustedKeys;
  });
  return _getLegacyTrustedPublicMasterKeyBase.apply(this, arguments);
}
function ownKeys(e, r) {
  var t = Object.keys(e);
  if (Object.getOwnPropertySymbols) {
    var o = Object.getOwnPropertySymbols(e);
    r && (o = o.filter(function(r2) {
      return Object.getOwnPropertyDescriptor(e, r2).enumerable;
    })), t.push.apply(t, o);
  }
  return t;
}
function _objectSpread(e) {
  for (var r = 1; r < arguments.length; r++) {
    var t = null != arguments[r] ? arguments[r] : {};
    r % 2 ? ownKeys(Object(t), true).forEach(function(r2) {
      _defineProperty(e, r2, t[r2]);
    }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function(r2) {
      Object.defineProperty(e, r2, Object.getOwnPropertyDescriptor(t, r2));
    });
  }
  return e;
}
function initRustCrypto(_x) {
  return _initRustCrypto.apply(this, arguments);
}
function _initRustCrypto() {
  _initRustCrypto = _asyncToGenerator(function* (args) {
    var {
      logger: logger2
    } = args;
    logger2.debug("Initialising Rust crypto-sdk WASM artifact");
    yield initAsync();
    new Tracing(LoggerLevel.Debug).turnOn();
    logger2.debug("Opening Rust CryptoStore");
    var storeHandle;
    if (args.storePrefix) {
      if (args.storeKey) {
        storeHandle = yield StoreHandle.openWithKey(args.storePrefix, args.storeKey);
      } else {
        storeHandle = yield StoreHandle.open(args.storePrefix, args.storePassphrase);
      }
    } else {
      storeHandle = yield StoreHandle.open();
    }
    if (args.legacyCryptoStore) {
      yield migrateFromLegacyCrypto(_objectSpread({
        legacyStore: args.legacyCryptoStore,
        storeHandle
      }, args));
    }
    var rustCrypto = yield initOlmMachine(logger2, args.http, args.userId, args.deviceId, args.secretStorage, args.cryptoCallbacks, storeHandle, args.legacyCryptoStore);
    storeHandle.free();
    logger2.debug("Completed rust crypto-sdk setup");
    return rustCrypto;
  });
  return _initRustCrypto.apply(this, arguments);
}
function initOlmMachine(_x2, _x3, _x4, _x5, _x6, _x7, _x8, _x9) {
  return _initOlmMachine.apply(this, arguments);
}
function _initOlmMachine() {
  _initOlmMachine = _asyncToGenerator(function* (logger2, http, userId, deviceId, secretStorage, cryptoCallbacks, storeHandle, legacyCryptoStore) {
    logger2.debug("Init OlmMachine");
    var olmMachine = yield OlmMachine.initFromStore(new UserId(userId), new DeviceId(deviceId), storeHandle);
    if (legacyCryptoStore) {
      yield migrateRoomSettingsFromLegacyCrypto({
        logger: logger2,
        legacyStore: legacyCryptoStore,
        olmMachine
      });
    }
    olmMachine.roomKeyRequestsEnabled = false;
    var rustCrypto = new RustCrypto(logger2, olmMachine, http, userId, deviceId, secretStorage, cryptoCallbacks);
    yield olmMachine.registerRoomKeyUpdatedCallback((sessions) => rustCrypto.onRoomKeysUpdated(sessions));
    yield olmMachine.registerRoomKeysWithheldCallback((withheld) => rustCrypto.onRoomKeysWithheld(withheld));
    yield olmMachine.registerUserIdentityUpdatedCallback((userId2) => rustCrypto.onUserIdentityUpdated(userId2));
    yield olmMachine.registerDevicesUpdatedCallback((userIds) => rustCrypto.onDevicesUpdated(userIds));
    rustCrypto.checkSecrets("m.megolm_backup.v1");
    yield olmMachine.registerReceiveSecretCallback((name, _value) => (
      // Instead of directly checking the secret value, we poll the inbox to get all values for that secret type.
      // Once we have all the values, we can safely clear the secret inbox.
      rustCrypto.checkSecrets(name)
    ));
    yield olmMachine.outgoingRequests();
    if (legacyCryptoStore && (yield legacyCryptoStore.containsData())) {
      var migrationState = yield legacyCryptoStore.getMigrationState();
      if (migrationState < MigrationState.INITIAL_OWN_KEY_QUERY_DONE) {
        logger2.debug("Performing initial key query after migration");
        var initialKeyQueryDone = false;
        while (!initialKeyQueryDone) {
          try {
            yield rustCrypto.userHasCrossSigningKeys(userId);
            initialKeyQueryDone = true;
          } catch (e) {
            logger2.error("Failed to check for cross-signing keys after migration, retrying", e);
          }
        }
        yield migrateLegacyLocalTrustIfNeeded({
          legacyCryptoStore,
          rustCrypto,
          logger: logger2
        });
        yield legacyCryptoStore.setMigrationState(MigrationState.INITIAL_OWN_KEY_QUERY_DONE);
      }
    }
    return rustCrypto;
  });
  return _initOlmMachine.apply(this, arguments);
}
export {
  initRustCrypto
};
