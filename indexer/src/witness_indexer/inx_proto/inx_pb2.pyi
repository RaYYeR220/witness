from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class NoParams(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class NodeConfiguration(_message.Message):
    __slots__ = ("milestone_public_key_count", "milestone_key_ranges", "base_token", "supported_protocol_versions")
    MILESTONE_PUBLIC_KEY_COUNT_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_KEY_RANGES_FIELD_NUMBER: _ClassVar[int]
    BASE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_PROTOCOL_VERSIONS_FIELD_NUMBER: _ClassVar[int]
    milestone_public_key_count: int
    milestone_key_ranges: _containers.RepeatedCompositeFieldContainer[MilestoneKeyRange]
    base_token: BaseToken
    supported_protocol_versions: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, milestone_public_key_count: _Optional[int] = ..., milestone_key_ranges: _Optional[_Iterable[_Union[MilestoneKeyRange, _Mapping]]] = ..., base_token: _Optional[_Union[BaseToken, _Mapping]] = ..., supported_protocol_versions: _Optional[_Iterable[int]] = ...) -> None: ...

class BaseToken(_message.Message):
    __slots__ = ("name", "ticker_symbol", "unit", "subunit", "decimals", "use_metric_prefix")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TICKER_SYMBOL_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    SUBUNIT_FIELD_NUMBER: _ClassVar[int]
    DECIMALS_FIELD_NUMBER: _ClassVar[int]
    USE_METRIC_PREFIX_FIELD_NUMBER: _ClassVar[int]
    name: str
    ticker_symbol: str
    unit: str
    subunit: str
    decimals: int
    use_metric_prefix: bool
    def __init__(self, name: _Optional[str] = ..., ticker_symbol: _Optional[str] = ..., unit: _Optional[str] = ..., subunit: _Optional[str] = ..., decimals: _Optional[int] = ..., use_metric_prefix: _Optional[bool] = ...) -> None: ...

class MilestoneKeyRange(_message.Message):
    __slots__ = ("public_key", "start_index", "end_index")
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    START_INDEX_FIELD_NUMBER: _ClassVar[int]
    END_INDEX_FIELD_NUMBER: _ClassVar[int]
    public_key: bytes
    start_index: int
    end_index: int
    def __init__(self, public_key: _Optional[bytes] = ..., start_index: _Optional[int] = ..., end_index: _Optional[int] = ...) -> None: ...

class NodeStatus(_message.Message):
    __slots__ = ("is_healthy", "is_synced", "is_almost_synced", "latest_milestone", "confirmed_milestone", "current_protocol_parameters", "tangle_pruning_index", "milestones_pruning_index", "ledger_pruning_index", "ledger_index")
    IS_HEALTHY_FIELD_NUMBER: _ClassVar[int]
    IS_SYNCED_FIELD_NUMBER: _ClassVar[int]
    IS_ALMOST_SYNCED_FIELD_NUMBER: _ClassVar[int]
    LATEST_MILESTONE_FIELD_NUMBER: _ClassVar[int]
    CONFIRMED_MILESTONE_FIELD_NUMBER: _ClassVar[int]
    CURRENT_PROTOCOL_PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    TANGLE_PRUNING_INDEX_FIELD_NUMBER: _ClassVar[int]
    MILESTONES_PRUNING_INDEX_FIELD_NUMBER: _ClassVar[int]
    LEDGER_PRUNING_INDEX_FIELD_NUMBER: _ClassVar[int]
    LEDGER_INDEX_FIELD_NUMBER: _ClassVar[int]
    is_healthy: bool
    is_synced: bool
    is_almost_synced: bool
    latest_milestone: Milestone
    confirmed_milestone: Milestone
    current_protocol_parameters: RawProtocolParameters
    tangle_pruning_index: int
    milestones_pruning_index: int
    ledger_pruning_index: int
    ledger_index: int
    def __init__(self, is_healthy: _Optional[bool] = ..., is_synced: _Optional[bool] = ..., is_almost_synced: _Optional[bool] = ..., latest_milestone: _Optional[_Union[Milestone, _Mapping]] = ..., confirmed_milestone: _Optional[_Union[Milestone, _Mapping]] = ..., current_protocol_parameters: _Optional[_Union[RawProtocolParameters, _Mapping]] = ..., tangle_pruning_index: _Optional[int] = ..., milestones_pruning_index: _Optional[int] = ..., ledger_pruning_index: _Optional[int] = ..., ledger_index: _Optional[int] = ...) -> None: ...

class NodeStatusRequest(_message.Message):
    __slots__ = ("cooldown_in_milliseconds",)
    COOLDOWN_IN_MILLISECONDS_FIELD_NUMBER: _ClassVar[int]
    cooldown_in_milliseconds: int
    def __init__(self, cooldown_in_milliseconds: _Optional[int] = ...) -> None: ...

class RawProtocolParameters(_message.Message):
    __slots__ = ("protocol_version", "params")
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    protocol_version: int
    params: bytes
    def __init__(self, protocol_version: _Optional[int] = ..., params: _Optional[bytes] = ...) -> None: ...

class RawMilestone(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class MilestoneId(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: bytes
    def __init__(self, id: _Optional[bytes] = ...) -> None: ...

class MilestoneRequest(_message.Message):
    __slots__ = ("milestone_index", "milestone_id")
    MILESTONE_INDEX_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_ID_FIELD_NUMBER: _ClassVar[int]
    milestone_index: int
    milestone_id: MilestoneId
    def __init__(self, milestone_index: _Optional[int] = ..., milestone_id: _Optional[_Union[MilestoneId, _Mapping]] = ...) -> None: ...

class MilestoneRangeRequest(_message.Message):
    __slots__ = ("start_milestone_index", "end_milestone_index")
    START_MILESTONE_INDEX_FIELD_NUMBER: _ClassVar[int]
    END_MILESTONE_INDEX_FIELD_NUMBER: _ClassVar[int]
    start_milestone_index: int
    end_milestone_index: int
    def __init__(self, start_milestone_index: _Optional[int] = ..., end_milestone_index: _Optional[int] = ...) -> None: ...

class MilestoneInfo(_message.Message):
    __slots__ = ("milestone_id", "milestone_index", "milestone_timestamp")
    MILESTONE_ID_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_INDEX_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    milestone_id: MilestoneId
    milestone_index: int
    milestone_timestamp: int
    def __init__(self, milestone_id: _Optional[_Union[MilestoneId, _Mapping]] = ..., milestone_index: _Optional[int] = ..., milestone_timestamp: _Optional[int] = ...) -> None: ...

class Milestone(_message.Message):
    __slots__ = ("milestone_info", "milestone")
    MILESTONE_INFO_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_FIELD_NUMBER: _ClassVar[int]
    milestone_info: MilestoneInfo
    milestone: RawMilestone
    def __init__(self, milestone_info: _Optional[_Union[MilestoneInfo, _Mapping]] = ..., milestone: _Optional[_Union[RawMilestone, _Mapping]] = ...) -> None: ...

class MilestoneAndProtocolParameters(_message.Message):
    __slots__ = ("milestone", "current_protocol_parameters")
    MILESTONE_FIELD_NUMBER: _ClassVar[int]
    CURRENT_PROTOCOL_PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    milestone: Milestone
    current_protocol_parameters: RawProtocolParameters
    def __init__(self, milestone: _Optional[_Union[Milestone, _Mapping]] = ..., current_protocol_parameters: _Optional[_Union[RawProtocolParameters, _Mapping]] = ...) -> None: ...

class WhiteFlagRequest(_message.Message):
    __slots__ = ("milestone_index", "milestone_timestamp", "parents", "previous_milestone_id")
    MILESTONE_INDEX_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    PARENTS_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_MILESTONE_ID_FIELD_NUMBER: _ClassVar[int]
    milestone_index: int
    milestone_timestamp: int
    parents: _containers.RepeatedCompositeFieldContainer[BlockId]
    previous_milestone_id: MilestoneId
    def __init__(self, milestone_index: _Optional[int] = ..., milestone_timestamp: _Optional[int] = ..., parents: _Optional[_Iterable[_Union[BlockId, _Mapping]]] = ..., previous_milestone_id: _Optional[_Union[MilestoneId, _Mapping]] = ...) -> None: ...

class WhiteFlagResponse(_message.Message):
    __slots__ = ("milestone_inclusion_merkle_root", "milestone_applied_merkle_root")
    MILESTONE_INCLUSION_MERKLE_ROOT_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_APPLIED_MERKLE_ROOT_FIELD_NUMBER: _ClassVar[int]
    milestone_inclusion_merkle_root: bytes
    milestone_applied_merkle_root: bytes
    def __init__(self, milestone_inclusion_merkle_root: _Optional[bytes] = ..., milestone_applied_merkle_root: _Optional[bytes] = ...) -> None: ...

class RawBlock(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class BlockId(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: bytes
    def __init__(self, id: _Optional[bytes] = ...) -> None: ...

class Block(_message.Message):
    __slots__ = ("block_id", "block")
    BLOCK_ID_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    block_id: BlockId
    block: RawBlock
    def __init__(self, block_id: _Optional[_Union[BlockId, _Mapping]] = ..., block: _Optional[_Union[RawBlock, _Mapping]] = ...) -> None: ...

class BlockWithMetadata(_message.Message):
    __slots__ = ("metadata", "block")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    metadata: BlockMetadata
    block: RawBlock
    def __init__(self, metadata: _Optional[_Union[BlockMetadata, _Mapping]] = ..., block: _Optional[_Union[RawBlock, _Mapping]] = ...) -> None: ...

class BlockMetadata(_message.Message):
    __slots__ = ("block_id", "parents", "solid", "should_promote", "should_reattach", "referenced_by_milestone_index", "milestone_index", "ledger_inclusion_state", "conflict_reason", "white_flag_index")
    class LedgerInclusionState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        LEDGER_INCLUSION_STATE_NO_TRANSACTION: _ClassVar[BlockMetadata.LedgerInclusionState]
        LEDGER_INCLUSION_STATE_INCLUDED: _ClassVar[BlockMetadata.LedgerInclusionState]
        LEDGER_INCLUSION_STATE_CONFLICTING: _ClassVar[BlockMetadata.LedgerInclusionState]
    LEDGER_INCLUSION_STATE_NO_TRANSACTION: BlockMetadata.LedgerInclusionState
    LEDGER_INCLUSION_STATE_INCLUDED: BlockMetadata.LedgerInclusionState
    LEDGER_INCLUSION_STATE_CONFLICTING: BlockMetadata.LedgerInclusionState
    class ConflictReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CONFLICT_REASON_NONE: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INPUT_ALREADY_SPENT: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INPUT_ALREADY_SPENT_IN_THIS_MILESTONE: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INPUT_NOT_FOUND: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INPUT_OUTPUT_SUM_MISMATCH: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INVALID_SIGNATURE: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_TIMELOCK_NOT_EXPIRED: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INVALID_NATIVE_TOKENS: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_RETURN_AMOUNT_NOT_FULFILLED: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INVALID_INPUT_UNLOCK: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INVALID_INPUTS_COMMITMENT: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INVALID_SENDER: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_INVALID_CHAIN_STATE_TRANSITION: _ClassVar[BlockMetadata.ConflictReason]
        CONFLICT_REASON_SEMANTIC_VALIDATION_FAILED: _ClassVar[BlockMetadata.ConflictReason]
    CONFLICT_REASON_NONE: BlockMetadata.ConflictReason
    CONFLICT_REASON_INPUT_ALREADY_SPENT: BlockMetadata.ConflictReason
    CONFLICT_REASON_INPUT_ALREADY_SPENT_IN_THIS_MILESTONE: BlockMetadata.ConflictReason
    CONFLICT_REASON_INPUT_NOT_FOUND: BlockMetadata.ConflictReason
    CONFLICT_REASON_INPUT_OUTPUT_SUM_MISMATCH: BlockMetadata.ConflictReason
    CONFLICT_REASON_INVALID_SIGNATURE: BlockMetadata.ConflictReason
    CONFLICT_REASON_TIMELOCK_NOT_EXPIRED: BlockMetadata.ConflictReason
    CONFLICT_REASON_INVALID_NATIVE_TOKENS: BlockMetadata.ConflictReason
    CONFLICT_REASON_RETURN_AMOUNT_NOT_FULFILLED: BlockMetadata.ConflictReason
    CONFLICT_REASON_INVALID_INPUT_UNLOCK: BlockMetadata.ConflictReason
    CONFLICT_REASON_INVALID_INPUTS_COMMITMENT: BlockMetadata.ConflictReason
    CONFLICT_REASON_INVALID_SENDER: BlockMetadata.ConflictReason
    CONFLICT_REASON_INVALID_CHAIN_STATE_TRANSITION: BlockMetadata.ConflictReason
    CONFLICT_REASON_SEMANTIC_VALIDATION_FAILED: BlockMetadata.ConflictReason
    BLOCK_ID_FIELD_NUMBER: _ClassVar[int]
    PARENTS_FIELD_NUMBER: _ClassVar[int]
    SOLID_FIELD_NUMBER: _ClassVar[int]
    SHOULD_PROMOTE_FIELD_NUMBER: _ClassVar[int]
    SHOULD_REATTACH_FIELD_NUMBER: _ClassVar[int]
    REFERENCED_BY_MILESTONE_INDEX_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_INDEX_FIELD_NUMBER: _ClassVar[int]
    LEDGER_INCLUSION_STATE_FIELD_NUMBER: _ClassVar[int]
    CONFLICT_REASON_FIELD_NUMBER: _ClassVar[int]
    WHITE_FLAG_INDEX_FIELD_NUMBER: _ClassVar[int]
    block_id: BlockId
    parents: _containers.RepeatedCompositeFieldContainer[BlockId]
    solid: bool
    should_promote: bool
    should_reattach: bool
    referenced_by_milestone_index: int
    milestone_index: int
    ledger_inclusion_state: BlockMetadata.LedgerInclusionState
    conflict_reason: BlockMetadata.ConflictReason
    white_flag_index: int
    def __init__(self, block_id: _Optional[_Union[BlockId, _Mapping]] = ..., parents: _Optional[_Iterable[_Union[BlockId, _Mapping]]] = ..., solid: _Optional[bool] = ..., should_promote: _Optional[bool] = ..., should_reattach: _Optional[bool] = ..., referenced_by_milestone_index: _Optional[int] = ..., milestone_index: _Optional[int] = ..., ledger_inclusion_state: _Optional[_Union[BlockMetadata.LedgerInclusionState, str]] = ..., conflict_reason: _Optional[_Union[BlockMetadata.ConflictReason, str]] = ..., white_flag_index: _Optional[int] = ...) -> None: ...

class TipsRequest(_message.Message):
    __slots__ = ("count", "allow_semiLazy")
    COUNT_FIELD_NUMBER: _ClassVar[int]
    ALLOW_SEMILAZY_FIELD_NUMBER: _ClassVar[int]
    count: int
    allow_semiLazy: bool
    def __init__(self, count: _Optional[int] = ..., allow_semiLazy: _Optional[bool] = ...) -> None: ...

class TipsResponse(_message.Message):
    __slots__ = ("tips",)
    TIPS_FIELD_NUMBER: _ClassVar[int]
    tips: _containers.RepeatedCompositeFieldContainer[BlockId]
    def __init__(self, tips: _Optional[_Iterable[_Union[BlockId, _Mapping]]] = ...) -> None: ...

class TipsMetricRequest(_message.Message):
    __slots__ = ("interval_in_milliseconds",)
    INTERVAL_IN_MILLISECONDS_FIELD_NUMBER: _ClassVar[int]
    interval_in_milliseconds: int
    def __init__(self, interval_in_milliseconds: _Optional[int] = ...) -> None: ...

class TipsMetric(_message.Message):
    __slots__ = ("non_lazy_pool_size", "semi_lazy_pool_size")
    NON_LAZY_POOL_SIZE_FIELD_NUMBER: _ClassVar[int]
    SEMI_LAZY_POOL_SIZE_FIELD_NUMBER: _ClassVar[int]
    non_lazy_pool_size: int
    semi_lazy_pool_size: int
    def __init__(self, non_lazy_pool_size: _Optional[int] = ..., semi_lazy_pool_size: _Optional[int] = ...) -> None: ...

class TransactionId(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: bytes
    def __init__(self, id: _Optional[bytes] = ...) -> None: ...

class OutputId(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: bytes
    def __init__(self, id: _Optional[bytes] = ...) -> None: ...

class OutputResponse(_message.Message):
    __slots__ = ("ledger_index", "output", "spent")
    LEDGER_INDEX_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    SPENT_FIELD_NUMBER: _ClassVar[int]
    ledger_index: int
    output: LedgerOutput
    spent: LedgerSpent
    def __init__(self, ledger_index: _Optional[int] = ..., output: _Optional[_Union[LedgerOutput, _Mapping]] = ..., spent: _Optional[_Union[LedgerSpent, _Mapping]] = ...) -> None: ...

class UnspentOutput(_message.Message):
    __slots__ = ("ledgerIndex", "output")
    LEDGERINDEX_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    ledgerIndex: int
    output: LedgerOutput
    def __init__(self, ledgerIndex: _Optional[int] = ..., output: _Optional[_Union[LedgerOutput, _Mapping]] = ...) -> None: ...

class RawOutput(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class LedgerOutput(_message.Message):
    __slots__ = ("output_id", "blockId", "milestone_index_booked", "milestone_timestamp_booked", "output")
    OUTPUT_ID_FIELD_NUMBER: _ClassVar[int]
    BLOCKID_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_INDEX_BOOKED_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_TIMESTAMP_BOOKED_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    output_id: OutputId
    blockId: BlockId
    milestone_index_booked: int
    milestone_timestamp_booked: int
    output: RawOutput
    def __init__(self, output_id: _Optional[_Union[OutputId, _Mapping]] = ..., blockId: _Optional[_Union[BlockId, _Mapping]] = ..., milestone_index_booked: _Optional[int] = ..., milestone_timestamp_booked: _Optional[int] = ..., output: _Optional[_Union[RawOutput, _Mapping]] = ...) -> None: ...

class LedgerSpent(_message.Message):
    __slots__ = ("output", "transaction_id_spent", "milestone_index_spent", "milestone_timestamp_spent")
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_ID_SPENT_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_INDEX_SPENT_FIELD_NUMBER: _ClassVar[int]
    MILESTONE_TIMESTAMP_SPENT_FIELD_NUMBER: _ClassVar[int]
    output: LedgerOutput
    transaction_id_spent: TransactionId
    milestone_index_spent: int
    milestone_timestamp_spent: int
    def __init__(self, output: _Optional[_Union[LedgerOutput, _Mapping]] = ..., transaction_id_spent: _Optional[_Union[TransactionId, _Mapping]] = ..., milestone_index_spent: _Optional[int] = ..., milestone_timestamp_spent: _Optional[int] = ...) -> None: ...

class TreasuryOutput(_message.Message):
    __slots__ = ("milestone_id", "amount")
    MILESTONE_ID_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    milestone_id: MilestoneId
    amount: int
    def __init__(self, milestone_id: _Optional[_Union[MilestoneId, _Mapping]] = ..., amount: _Optional[int] = ...) -> None: ...

class LedgerUpdate(_message.Message):
    __slots__ = ("batch_marker", "consumed", "created")
    class Marker(_message.Message):
        __slots__ = ("milestone_index", "marker_type", "consumed_count", "created_count")
        class MarkerType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            BEGIN: _ClassVar[LedgerUpdate.Marker.MarkerType]
            END: _ClassVar[LedgerUpdate.Marker.MarkerType]
        BEGIN: LedgerUpdate.Marker.MarkerType
        END: LedgerUpdate.Marker.MarkerType
        MILESTONE_INDEX_FIELD_NUMBER: _ClassVar[int]
        MARKER_TYPE_FIELD_NUMBER: _ClassVar[int]
        CONSUMED_COUNT_FIELD_NUMBER: _ClassVar[int]
        CREATED_COUNT_FIELD_NUMBER: _ClassVar[int]
        milestone_index: int
        marker_type: LedgerUpdate.Marker.MarkerType
        consumed_count: int
        created_count: int
        def __init__(self, milestone_index: _Optional[int] = ..., marker_type: _Optional[_Union[LedgerUpdate.Marker.MarkerType, str]] = ..., consumed_count: _Optional[int] = ..., created_count: _Optional[int] = ...) -> None: ...
    BATCH_MARKER_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    batch_marker: LedgerUpdate.Marker
    consumed: LedgerSpent
    created: LedgerOutput
    def __init__(self, batch_marker: _Optional[_Union[LedgerUpdate.Marker, _Mapping]] = ..., consumed: _Optional[_Union[LedgerSpent, _Mapping]] = ..., created: _Optional[_Union[LedgerOutput, _Mapping]] = ...) -> None: ...

class TreasuryUpdate(_message.Message):
    __slots__ = ("milestone_index", "created", "consumed")
    MILESTONE_INDEX_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_FIELD_NUMBER: _ClassVar[int]
    milestone_index: int
    created: TreasuryOutput
    consumed: TreasuryOutput
    def __init__(self, milestone_index: _Optional[int] = ..., created: _Optional[_Union[TreasuryOutput, _Mapping]] = ..., consumed: _Optional[_Union[TreasuryOutput, _Mapping]] = ...) -> None: ...

class RawReceipt(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class APIRouteRequest(_message.Message):
    __slots__ = ("route", "host", "port", "path")
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    route: str
    host: str
    port: int
    path: str
    def __init__(self, route: _Optional[str] = ..., host: _Optional[str] = ..., port: _Optional[int] = ..., path: _Optional[str] = ...) -> None: ...

class APIRequest(_message.Message):
    __slots__ = ("method", "path", "headers", "body")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    METHOD_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    method: str
    path: str
    headers: _containers.ScalarMap[str, str]
    body: bytes
    def __init__(self, method: _Optional[str] = ..., path: _Optional[str] = ..., headers: _Optional[_Mapping[str, str]] = ..., body: _Optional[bytes] = ...) -> None: ...

class APIResponse(_message.Message):
    __slots__ = ("code", "headers", "body")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CODE_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    code: int
    headers: _containers.ScalarMap[str, str]
    body: bytes
    def __init__(self, code: _Optional[int] = ..., headers: _Optional[_Mapping[str, str]] = ..., body: _Optional[bytes] = ...) -> None: ...
