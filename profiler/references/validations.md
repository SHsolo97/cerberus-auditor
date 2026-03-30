# Smart Contract Auditor - Validations

## Potential Reentrancy via ETH Transfer

### **Id**
check-reentrancy-eth-transfer
### **Description**
External ETH transfers before state updates are reentrancy vectors
### **Pattern**
call\{.*value.*\}.*\n(?:(?!\b(balances|_balance|amount|withdrawn)\b.*(-=|= 0|= false)).)*$
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
CRITICAL: ETH transfer detected. Verify state is updated BEFORE external call (CEI pattern)
### **Severity**
error
### **Autofix**


## External Call with Callback Risk

### **Id**
check-reentrancy-callback
### **Description**
Calls to untrusted addresses may trigger callbacks
### **Pattern**
\.call\(|\.delegatecall\(|\.staticcall\(
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
External call detected. Consider reentrancy guard and CEI pattern
### **Severity**
warning
### **Autofix**


## Missing Reentrancy Guard

### **Id**
check-nonreentrant-missing
### **Description**
Functions with external calls should have reentrancy protection
### **Pattern**
function.*external.*\{[^}]*call\{.*value
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
nonReentrant|ReentrancyGuard
### **Context Match**
absent
### **Message**
External payable call without nonReentrant modifier
### **Severity**
error
### **Autofix**


## Unprotected Selfdestruct

### **Id**
check-selfdestruct-unprotected
### **Description**
Selfdestruct without access control
### **Pattern**
selfdestruct\(|SELFDESTRUCT
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
onlyOwner|require.*msg\.sender|onlyRole
### **Context Match**
absent
### **Message**
CRITICAL: selfdestruct without access control
### **Severity**
error
### **Autofix**


## Single-Step Ownership Transfer

### **Id**
check-ownership-transfer
### **Description**
Direct ownership transfers can lock out owner
### **Pattern**
owner\s*=\s*\w+|_transferOwnership\(
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
pendingOwner|acceptOwnership|Ownable2Step
### **Context Match**
absent
### **Message**
Consider two-step ownership transfer to prevent lockout
### **Severity**
warning
### **Autofix**


## tx.origin Authentication

### **Id**
check-tx-origin
### **Description**
tx.origin for auth is vulnerable to phishing
### **Pattern**
require.*tx\.origin|tx\.origin\s*==|==\s*tx\.origin
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
CRITICAL: tx.origin for authentication is vulnerable to phishing attacks. Use msg.sender
### **Severity**
error
### **Autofix**


## Unchecked ERC20 Transfer Return

### **Id**
check-unchecked-transfer
### **Description**
ERC20 transfer may fail silently
### **Pattern**
IERC20.*\.transfer\(|token\.transfer\(
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
require.*transfer|safeTransfer|SafeERC20
### **Context Match**
absent
### **Message**
ERC20 transfer without return value check. Use SafeERC20.safeTransfer
### **Severity**
error
### **Autofix**


## Unchecked ERC20 TransferFrom Return

### **Id**
check-unchecked-transferfrom
### **Description**
ERC20 transferFrom may fail silently
### **Pattern**
IERC20.*\.transferFrom\(|token\.transferFrom\(
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
require.*transferFrom|safeTransferFrom|SafeERC20
### **Context Match**
absent
### **Message**
ERC20 transferFrom without return value check. Use SafeERC20.safeTransferFrom
### **Severity**
error
### **Autofix**


## Unchecked ERC20 Approve

### **Id**
check-unchecked-approve
### **Description**
ERC20 approve may fail or behave unexpectedly
### **Pattern**
IERC20.*\.approve\(|token\.approve\(
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
safeApprove|forceApprove|SafeERC20
### **Context Match**
absent
### **Message**
ERC20 approve without SafeERC20. Some tokens require 0 approval first
### **Severity**
warning
### **Autofix**


## Unchecked Low-Level Call

### **Id**
check-low-level-call-return
### **Description**
Low-level call return value must be checked
### **Pattern**
\.(call|delegatecall|staticcall)\([^)]*\);\s*$
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
Low-level call without return value check
### **Severity**
error
### **Autofix**


## Missing Oracle Freshness Check

### **Id**
check-oracle-stale-price
### **Description**
Oracle prices should be validated for freshness
### **Pattern**
latestRoundData\(\)|latestAnswer\(\)
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
updatedAt|timestamp|stale|freshness
### **Context Match**
absent
### **Message**
Oracle used without freshness check. Stale prices can cause losses
### **Severity**
warning
### **Autofix**


## Spot Price Manipulation Risk

### **Id**
check-spot-price-usage
### **Description**
Spot prices from AMMs are manipulable via flash loans
### **Pattern**
getReserves\(\)|slot0\(\)|price0CumulativeLast|getCurrentPrice
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
TWAP|twap|cumulative|observe
### **Context Match**
absent
### **Message**
Spot price usage detected. Consider TWAP to prevent flash loan manipulation
### **Severity**
warning
### **Autofix**


## Missing Oracle Price Validation

### **Id**
check-oracle-price-validation
### **Description**
Oracle prices should have sanity bounds
### **Pattern**
latestRoundData|getPrice|fetchPrice
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
require.*price.*>|price.*>.*0|MIN_PRICE|MAX_PRICE
### **Context Match**
absent
### **Message**
Oracle price without sanity validation. Check for zero/negative/extreme values
### **Severity**
warning
### **Autofix**


## Unchecked Arithmetic with User Input

### **Id**
check-unchecked-user-input
### **Description**
User-controlled values in unchecked blocks can overflow
### **Pattern**
unchecked\s*\{[^}]*\+[^}]*\}
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
Verify unchecked arithmetic uses only bounded/validated values
### **Severity**
warning
### **Autofix**


## Unsafe Integer Downcast

### **Id**
check-unsafe-downcast
### **Description**
Casting to smaller types can silently truncate
### **Pattern**
uint(8|16|32|64|128)\s*\([^)]+\)|int(8|16|32|64|128)\s*\([^)]+\)
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
Integer downcast detected. Verify value fits in target type
### **Severity**
warning
### **Autofix**


## Unchecked ecrecover Result

### **Id**
check-ecrecover-zero
### **Description**
ecrecover returns zero on invalid signature
### **Pattern**
ecrecover\(
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
!=\s*address\(0\)|recovered.*!=.*0|signer.*!=.*address\(0\)
### **Context Match**
absent
### **Message**
ecrecover without zero address check. Invalid signatures return address(0)
### **Severity**
error
### **Autofix**


## Missing Nonce in Signature

### **Id**
check-signature-replay
### **Description**
Signatures without nonces can be replayed
### **Pattern**
ecrecover|ECDSA\.recover|SignatureChecker
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
nonce|Nonce|NONCE
### **Context Match**
absent
### **Message**
Signature verification without nonce. Vulnerable to replay attacks
### **Severity**
warning
### **Autofix**


## Missing Chain ID in Signature

### **Id**
check-signature-chain-id
### **Description**
Signatures should include chain ID for cross-chain safety
### **Pattern**
DOMAIN_SEPARATOR|EIP712
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
chainid|chainId|block\.chainid
### **Context Match**
absent
### **Message**
Domain separator without chain ID. Signatures may replay on forks
### **Severity**
warning
### **Autofix**


## Swap Without Slippage Protection

### **Id**
check-swap-no-slippage
### **Description**
Swaps without minimum output are sandwich targets
### **Pattern**
swap.*0,|amountOutMin.*=.*0|minAmountOut.*0
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
Swap with zero slippage protection. Will be sandwiched by MEV bots
### **Severity**
error
### **Autofix**


## Swap Without Deadline

### **Id**
check-swap-no-deadline
### **Description**
Swaps without deadline can be held by validators
### **Pattern**
swap|trade|exchange
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
deadline|block\.timestamp|expires
### **Context Match**
absent
### **Message**
Swap without deadline parameter. Transaction can be delayed indefinitely
### **Severity**
warning
### **Autofix**


## Unbounded Loop Over Array

### **Id**
check-unbounded-loop
### **Description**
Loops over dynamic arrays can exceed gas limit
### **Pattern**
for.*<.*\.length|while.*\.length
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
Loop over dynamic array. Ensure bounded or use pagination
### **Severity**
warning
### **Autofix**


## Unbounded Array Push

### **Id**
check-push-unbounded
### **Description**
Unlimited array growth leads to DoS
### **Pattern**
\.push\(
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
MAX_|maxLength|require.*length.*<
### **Context Match**
absent
### **Message**
Array push without length limit. Can grow unbounded causing DoS
### **Severity**
warning
### **Autofix**


## External Call in Loop

### **Id**
check-external-call-in-loop
### **Description**
External calls in loops allow griefing
### **Pattern**
for.*\{[^}]*(\.call|\.transfer|\.send|transfer\(|safeTransfer)
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
External call inside loop. Single failure blocks all. Use pull pattern
### **Severity**
warning
### **Autofix**


## Delegatecall to Non-Constant Address

### **Id**
check-delegatecall-untrusted
### **Description**
Delegatecall to variable address risks storage collision
### **Pattern**
delegatecall\(
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
Delegatecall detected. Verify target is trusted and storage compatible
### **Severity**
warning
### **Autofix**


## Missing Initializer Modifier

### **Id**
check-initializer-missing
### **Description**
Initializer functions can be called multiple times
### **Pattern**
function\s+initialize\s*\(
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
initializer|initialized|Initializable
### **Context Match**
absent
### **Message**
Initialize function without initializer modifier. Can be called multiple times
### **Severity**
error
### **Autofix**


## Constructor in Upgradeable Contract

### **Id**
check-constructor-in-proxy
### **Description**
Constructors don't run in proxy context
### **Pattern**
constructor\s*\(
### **File Glob**
**/*Upgradeable*.sol
### **Match**
present
### **Message**
Constructor in upgradeable contract. State set here won't exist in proxy
### **Severity**
warning
### **Autofix**


## Floating Pragma Version

### **Id**
check-floating-pragma
### **Description**
Contracts should lock pragma for consistent compilation
### **Pattern**
pragma solidity \^|pragma solidity >=|pragma solidity >=
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
Floating pragma. Lock to specific version for production
### **Severity**
info
### **Autofix**


## Magic Numbers in Code

### **Id**
check-magic-numbers
### **Description**
Unexplained numbers make auditing harder
### **Pattern**
\b(1000|10000|100000|86400|3600|1e18|1e6)\b
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
constant|CONSTANT|//.*
### **Context Match**
absent
### **Message**
Magic number detected. Consider using named constants
### **Severity**
info
### **Autofix**


## Assembly Block Detected

### **Id**
check-assembly-present
### **Description**
Assembly requires careful security review
### **Pattern**
assembly\s*\{
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
Assembly block requires thorough security review
### **Severity**
info
### **Autofix**


## Inline Yul Code

### **Id**
check-inline-yul
### **Description**
Yul bypasses Solidity safety features
### **Pattern**
assembly.*\{[^}]*sload|assembly.*\{[^}]*sstore|assembly.*\{[^}]*mstore
### **File Glob**
**/*.sol
### **Match**
present
### **Message**
Direct storage/memory manipulation in assembly. Extra scrutiny needed
### **Severity**
warning
### **Autofix**


## ERC20 Approve Race Condition

### **Id**
check-approve-race
### **Description**
approve() has known race condition
### **Pattern**
\.approve\([^,]+,\s*[^0)]
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
increaseAllowance|safeIncreaseAllowance|forceApprove
### **Context Match**
absent
### **Message**
Direct approve() has race condition. Consider increaseAllowance or set to 0 first
### **Severity**
info
### **Autofix**


## Missing Permit Support

### **Id**
check-permit-support
### **Description**
Modern tokens should support gasless approvals
### **Pattern**
ERC20|IERC20
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
permit|ERC20Permit|IERC2612
### **Context Match**
absent
### **Message**
Consider ERC20Permit for gasless approvals
### **Severity**
info
### **Autofix**


## Missing Signature Deduplication in Multi-Sig

### **Id**
check-multi-sig-signature-dedup
### **Description**
Weighted multi-signature without uniqueness check on signatories allows duplicate voting
### **Pattern**
validateSignatures|signatories|weighted.*quorum|checkpoint.*signature
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
require.*unique|seen\[|sorted|dedup|duplicate.*signatory
### **Context Match**
absent
### **Message**
Multi-sig checkpoint validation without signature deduplication. A single validator can repeat signatures to accumulate weight and pass quorum alone
### **Severity**
error
### **Autofix**


## Xnet Call Messages Bypass Circulating Supply Accounting

### **Id**
check-xnet-call-supply-accounting
### **Description**
Cross-net Call-kind messages with value bypass circulating supply accounting, inflating destination supply
### **Pattern**
circSupply|circulatingSupply|execBottomUpMsgs|kind.*Call|Call.*\.value
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
totalValue.*=.*msgs.*value|kind.*!=.*Call.*totalValue
### **Context Match**
absent
### **Message**
Cross-net message handling that skips Call-kind messages from circulating supply accounting. Destination subnet supply can be inflated without source burn
### **Severity**
error
### **Autofix**


## IPC Handler Hash Inconsistency (toHash vs toTracingId)

### **Id**
check-ipc-hash-mismatch
### **Description**
Inconsistent hash functions used for in-flight message tracking vs result matching
### **Pattern**
toHash|toTracingId|inflightMsgs|result\.id
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
localNonce.*toHash|localNonce.*omitted|toTracingId.*localNonce
### **Context Match**
absent
### **Message**
IPC handler uses different hash functions for send tracking and result matching. Mismatch in localNonce inclusion will cause receipts to fail matching, locking funds in inflight tracking
### **Severity**
error
### **Autofix**


## Bottom-Up Batch Count Overflow

### **Id**
check-bottomup-batch-overflow
### **Description**
Bottom-up message batch count can overflow, halting checkpoint execution
### **Pattern**
bottomUpMsg|batchCount|messageCount|msgBatch|commitBottomUp
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
require.*<=.*MAX|maxBatch|overflow|uint256.*overflow
### **Context Match**
absent
### **Message**
Bottom-up batch message processing without overflow protection. Overflowing the count halts checkpoint execution and freezes subnet operations
### **Severity**
error
### **Autofix**


## Cross-Chain Supply Reconciliation Missing

### **Id**
check-crosschain-supply-reconciliation
### **Description**
Bridging operations do not reconcile circulating supply across subnets atomically
### **Pattern**
lock\(|unlock\(|circSupply.*cross|cross.*circSupply|subnet.*supply|bridge.*mint
### **File Glob**
**/*.sol
### **Match**
present
### **Context Pattern**
totalLocked.*==.*sum|reconcile|invariant|supply.*check|assert.*supply
### **Context Match**
absent
### **Message**
Cross-chain bridging without circulating supply reconciliation. Supply invariant (total locked == total circulating) can be violated, enabling unbacked token creation
### **Severity**
error
### **Autofix**
