/**
 * @witness/verify: the Witness proof verifier for browsers and Node.
 *
 * A line-by-line port of the Python reference (`witness_core`), held to it by
 * the shared vectors in core/tests/vectors. Names follow the Python modules in
 * camelCase; verdict and step strings are identical.
 */

export { blake2b256 } from "./blake2b.js";
export { b64urlDecode, b64urlEncode, fromHex, toHex } from "./bytes.js";
export {
  blockId,
  DecodeError,
  milestoneId,
  parseBlock,
  parseMilestoneEssence,
  parseMilestonePayload,
  type Block,
  type Ed25519Sig,
  type MilestoneEssence,
  type MilestonePayload,
  type OtherPayload,
  type Payload,
  type TaggedData,
} from "./codec.js";
export { auditPath, leafHash, merkleRoot, nodeHash, verifyPath, type PathStep } from "./merkle.js";
export { canonHash, CanonicalizationError, jcs, JCS_MAX_DEPTH, jcsBytes } from "./jcs.js";
export {
  isDict,
  isUint,
  JsonNumber,
  JsonParseError,
  PY_JSON_MAX_DEPTH,
  RecursionError,
  parseJson,
  pyRepr,
  textTooDeep,
  type Json,
  type JsonObject,
  type ParseOptions,
} from "./json.js";
export { ed25519Verify, isWeakPublicKey } from "./ed25519.js";
export {
  FORGED,
  MALFORMED,
  PRODUCER_SIGNED,
  RELAY_ATTESTED,
  REPLAY,
  REVOKED_KEY,
  SEVERITY,
  UNAUTHORIZED_WRITER,
  UNSIGNED_LEGACY,
  type Severity,
  type Verdict,
} from "./verdicts.js";
export {
  isEnvelope,
  sealEnvelope,
  verifyEnvelope,
  type Ed25519PrivateJwk,
  type Envelope,
  type EnvelopeCheck,
  type KeyInfo,
  type KeyResolver,
  type SealOptions,
} from "./envelope.js";
export { blindToken, decryptBody, DecryptError, NotARecipient, type X25519PrivateJwk } from "./sealed.js";
export { commit, newSalt, SALT_LEN, verifyCommitment } from "./commit.js";
export {
  buildCheckpoint,
  CHECKPOINT_KIND,
  CHECKPOINT_VERSION,
  checkpointHash,
  checkpointShapeError,
  membershipPath,
  type BuildCheckpointInput,
  type Checkpoint,
  type CheckpointBound,
} from "./checkpoint.js";
export {
  BUNDLE_VERSION,
  DidSnapshotError,
  pinnedSignatures,
  snapshotResolver,
  STEP_NAMES,
  UNRESOLVED_SIGNER,
  verifyBundle,
  verifyBundleText,
  type Ladder,
  type Overall,
  type StepName,
  type StepResult,
  type VerifierConfig,
  type VerifyOptions,
} from "./bundle.js";
