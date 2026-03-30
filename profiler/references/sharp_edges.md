# Smart Contract Auditor - Sharp Edges

## Classic Reentrancy Attack

### **Id**
classic-reentrancy
### **Severity**
CRITICAL
### **Description**
External calls before state updates allow recursive exploitation
### **Symptoms**
  - Funds drained in single transaction
  - Balance checks pass multiple times
  - State unchanged after multiple withdrawals
### **Detection Pattern**
call\{.*value.*\}|transfer\(|send\(
### **Solution**
  // The attacker contract:
  contract Attacker {
      Vault victim;
      uint256 count;
  
      receive() external payable {
          if (count < 10 && address(victim).balance >= 1 ether) {
              count++;
              victim.withdraw(1 ether);  // Re-enters!
          }
      }
  }
  
  // FIX 1: Checks-Effects-Interactions
  function withdraw(uint256 amount) external {
      require(balances[msg.sender] >= amount);
      balances[msg.sender] -= amount;  // Update BEFORE call
      (bool success, ) = msg.sender.call{value: amount}("");
      require(success);
  }
  
  // FIX 2: Reentrancy Guard (preferred)
  bool private locked;
  modifier nonReentrant() {
      require(!locked, "Reentrant");
      locked = true;
      _;
      locked = false;
  }
  
  // FIX 3: Transient storage guard (Solidity 0.8.24+)
  modifier nonReentrantTransient() {
      assembly {
          if tload(0) { revert(0, 0) }
          tstore(0, 1)
      }
      _;
      assembly { tstore(0, 0) }
  }
  
### **References**
  - https://swcregistry.io/docs/SWC-107
  - https://github.com/pcaversaccio/reentrancy-attacks

## Read-Only Reentrancy

### **Id**
read-only-reentrancy
### **Severity**
CRITICAL
### **Description**
View functions return stale state during reentrancy window
### **Symptoms**
  - Price oracles return incorrect values during callbacks
  - Other protocols get wrong balances mid-transaction
  - LP token pricing exploited during deposits/withdrawals
### **Detection Pattern**
balanceOf|totalSupply|getReserves|slot0
### **Solution**
  // VULNERABLE: Curve pool read-only reentrancy
  // During remove_liquidity, callback happens BEFORE state update
  // Other protocols reading balances get stale values
  
  // FIX 1: Use reentrancy guard on view functions too
  function getVirtualPrice() external view nonReentrant returns (uint256) {
      return _calculateVirtualPrice();
  }
  
  // FIX 2: Check for reentrancy in consuming protocols
  contract SafeConsumer {
      function getPrice(address pool) external returns (uint256) {
          // Call a mutative function to trigger reentrancy guard
          ICurve(pool).claim_admin_fees();  // Will revert if mid-reentrancy
          return ICurve(pool).get_virtual_price();
      }
  }
  
  // FIX 3: Use time-weighted average prices
  // TWAP resists single-block manipulation including reentrancy
  
### **References**
  - https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/
  - https://blog.openzeppelin.com/read-only-reentrancy

## Cross-Function Reentrancy

### **Id**
cross-function-reentrancy
### **Severity**
CRITICAL
### **Description**
Attacker reenters via different function sharing same state
### **Symptoms**
  - Reentrancy guard on one function bypassed via another
  - State corruption across related functions
  - Invariants broken mid-transaction
### **Detection Pattern**
external.*call|callback|hook
### **Solution**
  // VULNERABLE: Guard on withdraw but not transfer
  function withdraw(uint256 amount) external nonReentrant {
      require(balances[msg.sender] >= amount);
      (bool success, ) = msg.sender.call{value: amount}("");  // Callback here
      require(success);
      balances[msg.sender] -= amount;
  }
  
  function transfer(address to, uint256 amount) external {  // NO GUARD!
      require(balances[msg.sender] >= amount);
      balances[msg.sender] -= amount;
      balances[to] += amount;
  }
  
  // Attacker receives callback, calls transfer() to move funds
  
  // FIX: Apply guard to ALL state-modifying functions
  // Or use a contract-wide guard that covers all entries
  uint256 private constant NOT_ENTERED = 1;
  uint256 private constant ENTERED = 2;
  uint256 private _status = NOT_ENTERED;
  
  modifier globalNonReentrant() {
      require(_status != ENTERED, "Reentrant");
      _status = ENTERED;
      _;
      _status = NOT_ENTERED;
  }
  
  // Apply to ALL external functions that touch shared state
  
### **References**
  - https://inspex.co/blog/cross-function-reentrancy

## Delegatecall Storage Collision

### **Id**
delegatecall-storage-collision
### **Severity**
CRITICAL
### **Description**
Implementation storage layout differs from proxy
### **Symptoms**
  - Admin address overwritten after upgrade
  - Random state corruption
  - Implementation address changed unexpectedly
  - Proxy becomes unusable
### **Detection Pattern**
delegatecall|proxy|implementation|upgrade
### **Solution**
  // VULNERABLE: Different storage layouts
  contract ProxyV1 {
      address public implementation;  // slot 0
      address public admin;           // slot 1
  }
  
  contract ImplementationV1 {
      uint256 public value;  // slot 0 - COLLIDES with implementation!
      address public owner;  // slot 1 - COLLIDES with admin!
  }
  
  // FIX 1: Use EIP-1967 random slots
  contract SafeProxy {
      // Random slot: keccak256("eip1967.proxy.implementation") - 1
      bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
  
      function _getImplementation() internal view returns (address impl) {
          assembly { impl := sload(IMPL_SLOT) }
      }
  
      function _setImplementation(address newImpl) internal {
          assembly { sstore(IMPL_SLOT, newImpl) }
      }
  }
  
  // FIX 2: Inherit storage layout from proxy in implementation
  abstract contract ProxyStorage {
      address internal _implementation;
      address internal _admin;
  }
  
  contract Implementation is ProxyStorage {
      // Add new storage AFTER inherited slots
      uint256 public value;  // Now at slot 2
  }
  
  // FIX 3: Use unstructured storage for all proxy state
  
### **References**
  - https://eips.ethereum.org/EIPS/eip-1967
  - https://blog.openzeppelin.com/proxy-patterns

## Oracle Price Manipulation via Flash Loans

### **Id**
oracle-price-manipulation
### **Severity**
CRITICAL
### **Description**
Spot prices manipulated within single transaction
### **Symptoms**
  - Abnormal trades during price spikes
  - Liquidations at manipulated prices
  - Arbitrage profits from artificial spreads
### **Detection Pattern**
getReserves|slot0|latestAnswer|getPrice
### **Solution**
  // VULNERABLE: Spot price from AMM
  function getPrice() public view returns (uint256) {
      (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
      return reserve1 * 1e18 / reserve0;  // Manipulable!
  }
  
  // ATTACK FLOW:
  // 1. Flash loan huge amount of token0
  // 2. Swap into pair, skewing reserves
  // 3. Call victim contract (uses manipulated price)
  // 4. Swap back
  // 5. Repay flash loan with profit
  
  // FIX 1: Time-Weighted Average Price (TWAP)
  function getTWAP(address pair, uint32 period) public view returns (uint256) {
      (uint256 price0Cumulative, uint256 price1Cumulative, uint32 blockTimestamp) =
          UniswapV2OracleLibrary.currentCumulativePrices(pair);
  
      uint32 timeElapsed = blockTimestamp - lastUpdateTime;
      require(timeElapsed >= period, "TWAP period not elapsed");
  
      return (price0Cumulative - price0CumulativeLast) / timeElapsed;
  }
  
  // FIX 2: Multiple oracle sources
  function getPrice() public view returns (uint256) {
      uint256 chainlinkPrice = getChainlinkPrice();
      uint256 twapPrice = getTWAP();
  
      // Require prices within tolerance
      uint256 deviation = chainlinkPrice > twapPrice
          ? (chainlinkPrice - twapPrice) * 100 / chainlinkPrice
          : (twapPrice - chainlinkPrice) * 100 / twapPrice;
  
      require(deviation <= MAX_DEVIATION, "Price mismatch");
      return (chainlinkPrice + twapPrice) / 2;
  }
  
  // FIX 3: Validate against historical bounds
  require(price >= lastPrice * 95 / 100, "Price dropped too fast");
  require(price <= lastPrice * 105 / 100, "Price rose too fast");
  
### **References**
  - https://samczsun.com/so-you-want-to-use-a-price-oracle/
  - https://www.euler.finance/blog/euler-notes-2-price-oracles

## Signature Replay Attack

### **Id**
signature-replay
### **Severity**
CRITICAL
### **Description**
Same signature valid multiple times or across contexts
### **Symptoms**
  - Transaction replayed after completion
  - Signature works on multiple chains
  - Same permit used multiple times
### **Detection Pattern**
ecrecover|signature|permit|EIP712|signTypedData
### **Solution**
  // VULNERABLE: Missing nonce
  function executeWithSig(address to, uint256 amount, bytes calldata sig) external {
      bytes32 hash = keccak256(abi.encode(to, amount));
      address signer = ECDSA.recover(hash, sig);
      require(signer == authorizedSigner);
      // Execute... but sig can be replayed!
  }
  
  // VULNERABLE: Missing chain ID (cross-chain replay)
  // Same signature works on Mainnet AND Arbitrum
  
  // COMPREHENSIVE FIX:
  contract SecureSignature {
      mapping(address => uint256) public nonces;
      bytes32 public immutable DOMAIN_SEPARATOR;
  
      bytes32 constant EXECUTE_TYPEHASH = keccak256(
          "Execute(address to,uint256 amount,uint256 nonce,uint256 deadline)"
      );
  
      constructor() {
          DOMAIN_SEPARATOR = keccak256(abi.encode(
              keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
              keccak256(bytes("SecureContract")),
              keccak256(bytes("1")),
              block.chainid,      // Chain-specific
              address(this)       // Contract-specific
          ));
      }
  
      function executeWithSig(
          address to,
          uint256 amount,
          uint256 deadline,
          uint8 v, bytes32 r, bytes32 s
      ) external {
          require(block.timestamp <= deadline, "Expired");
  
          bytes32 structHash = keccak256(abi.encode(
              EXECUTE_TYPEHASH,
              to,
              amount,
              nonces[msg.sender]++,  // Nonce prevents replay
              deadline
          ));
  
          bytes32 digest = keccak256(abi.encodePacked(
              "\x19\x01",
              DOMAIN_SEPARATOR,
              structHash
          ));
  
          address signer = ecrecover(digest, v, r, s);
          require(signer != address(0) && signer == msg.sender, "Invalid sig");
  
          // Execute...
      }
  }
  
### **References**
  - https://eips.ethereum.org/EIPS/eip-712
  - https://swcregistry.io/docs/SWC-117

## Front-Running / Sandwich Attacks

### **Id**
front-running
### **Severity**
HIGH
### **Description**
Transaction ordering exploited by MEV bots
### **Symptoms**
  - Worse-than-expected swap rates
  - Transactions fail with slippage errors
  - Unusual activity before large trades
### **Detection Pattern**
swap|trade|exchange|amountOut|slippage
### **Solution**
  // VULNERABLE: No slippage protection
  function swap(uint256 amountIn) external {
      router.swap(amountIn, 0, path, msg.sender, block.timestamp + 1000);
      // Bot sees this, front-runs with own swap, sandwiches victim
  }
  
  // FIX 1: User-specified slippage
  function swap(uint256 amountIn, uint256 minAmountOut, uint256 deadline) external {
      require(block.timestamp <= deadline, "Expired");
      uint256 out = router.swap(amountIn, minAmountOut, path, msg.sender, deadline);
      require(out >= minAmountOut, "Slippage");
  }
  
  // FIX 2: Private mempool (Flashbots Protect)
  // Submit transactions directly to block builders
  
  // FIX 3: Commit-reveal scheme for sensitive operations
  mapping(bytes32 => uint256) public commits;
  
  function commitTrade(bytes32 commitment) external {
      commits[commitment] = block.number;
  }
  
  function revealAndExecute(
      uint256 amountIn,
      uint256 minOut,
      bytes32 salt
  ) external {
      bytes32 commitment = keccak256(abi.encode(msg.sender, amountIn, minOut, salt));
      require(commits[commitment] != 0, "No commit");
      require(block.number > commits[commitment] + 1, "Too soon");
      delete commits[commitment];
      // Execute trade
  }
  
  // FIX 4: Use batch auctions (CoW Protocol style)
  // Trades settled at uniform clearing price, no ordering advantage
  
### **References**
  - https://docs.flashbots.net/flashbots-protect/overview
  - https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest

## Flash Loan Governance Attack

### **Id**
governance-flash-loan-attack
### **Severity**
HIGH
### **Description**
Borrow voting power to pass malicious proposals
### **Symptoms**
  - Proposals pass with sudden vote spike
  - Whale-level votes from empty wallets
  - Treasury drained via governance
### **Detection Pattern**
propose|vote|execute|governance|delegate
### **Solution**
  // VULNERABLE: Snapshot at proposal time
  function propose(uint256 proposalId) external {
      uint256 votes = token.balanceOf(msg.sender);  // Can be flash loaned!
      require(votes >= proposalThreshold);
      // Create proposal...
  }
  
  // ATTACK:
  // 1. Flash loan governance tokens
  // 2. Delegate to self
  // 3. Create proposal to drain treasury
  // 4. Vote immediately
  // 5. Return flash loan
  
  // FIX 1: Time-locked voting power
  function getVotes(address account) public view returns (uint256) {
      // Use checkpoint from previous block
      return token.getPastVotes(account, block.number - 1);
  }
  
  // FIX 2: Voting delay + snapshot at proposal creation
  function propose() external returns (uint256) {
      uint256 proposalId = proposalCount++;
      Proposal storage p = proposals[proposalId];
      p.startBlock = block.number + votingDelay;  // Delay before voting
      p.snapshotBlock = block.number;             // Votes locked at creation
      p.endBlock = p.startBlock + votingPeriod;
      return proposalId;
  }
  
  function castVote(uint256 proposalId) external {
      Proposal storage p = proposals[proposalId];
      require(block.number >= p.startBlock, "Too early");
      require(block.number <= p.endBlock, "Too late");
  
      // Use historical votes from snapshot
      uint256 votes = token.getPastVotes(msg.sender, p.snapshotBlock);
      // Record vote...
  }
  
  // FIX 3: Require token lock during voting period
  // FIX 4: Use vote escrow (veToken) model
  
### **References**
  - https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest
  - https://blog.tally.xyz/how-to-design-governance

## Unchecked External Call Return Values

### **Id**
unchecked-return-values
### **Severity**
HIGH
### **Description**
Ignoring failure of external calls leads to false accounting
### **Symptoms**
  - Balance discrepancies
  - State updated but funds not moved
  - Silent failures in batch operations
### **Detection Pattern**
\.transfer\(|\.send\(|call\(|call\{
### **Solution**
  // VULNERABLE: Ignoring return values
  payable(user).send(amount);  // Returns false on failure
  token.transfer(user, amount);  // Some tokens don't revert
  
  // VULNERABLE: Low-level call without check
  (bool success, ) = target.call(data);
  // success ignored!
  
  // FIX 1: Check return values
  bool sent = payable(user).send(amount);
  require(sent, "Send failed");
  
  // FIX 2: Use transfer() for ETH (but has 2300 gas limit issues)
  // Better: Use call with check
  (bool success, ) = payable(user).call{value: amount}("");
  require(success, "ETH transfer failed");
  
  // FIX 3: SafeERC20 for tokens
  import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
  using SafeERC20 for IERC20;
  
  token.safeTransfer(user, amount);  // Reverts on failure
  token.safeTransferFrom(from, to, amount);
  token.safeApprove(spender, amount);  // Handles weird approval tokens
  
### **References**
  - https://swcregistry.io/docs/SWC-104
  - https://github.com/d-xo/weird-erc20

## Integer Overflow/Underflow

### **Id**
integer-overflow-underflow
### **Severity**
HIGH
### **Description**
Arithmetic operations wrap around without reverting
### **Symptoms**
  - Huge balances appearing from small operations
  - Negative values becoming max uint256
  - Unexpected calculation results
### **Detection Pattern**
unchecked|uint8|uint16|uint32|Solidity.*0\.[0-7]
### **Solution**
  // Solidity 0.8+ has automatic overflow checks
  // BUT unchecked blocks disable them!
  
  // VULNERABLE: Unchecked with user input
  function addReward(uint256 amount) external {
      unchecked {
          // If totalRewards is near max, this wraps to small number!
          totalRewards += amount;
      }
  }
  
  // SAFE: Unchecked only for loop counters
  for (uint256 i = 0; i < length; ) {
      // Process item
      unchecked { ++i; }  // Safe: i < length guarantees no overflow
  }
  
  // VULNERABLE: Casting down
  uint256 bigNumber = type(uint256).max;
  uint128 smallNumber = uint128(bigNumber);  // Silent truncation!
  
  // SAFE: Check before casting
  require(bigNumber <= type(uint128).max, "Value too large");
  uint128 smallNumber = uint128(bigNumber);
  
  // Pre-0.8.0: Use SafeMath everywhere
  using SafeMath for uint256;
  totalRewards = totalRewards.add(amount);  // Reverts on overflow
  
### **References**
  - https://swcregistry.io/docs/SWC-101
  - https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic

## Missing or Incorrect Access Control

### **Id**
access-control-missing
### **Severity**
HIGH
### **Description**
Privileged functions callable by unauthorized users
### **Symptoms**
  - Admin functions called by random addresses
  - Owner changed by attacker
  - Funds withdrawn without authorization
### **Detection Pattern**
onlyOwner|require.*msg\.sender|access|role
### **Solution**
  // VULNERABLE: Missing access control
  function withdrawAll() external {
      payable(msg.sender).transfer(address(this).balance);
      // Anyone can drain!
  }
  
  // VULNERABLE: Incorrect check
  function setOwner(address newOwner) external {
      require(msg.sender != owner);  // WRONG OPERATOR!
      owner = newOwner;
  }
  
  // FIX 1: Simple owner pattern
  address public owner;
  
  modifier onlyOwner() {
      require(msg.sender == owner, "Not owner");
      _;
  }
  
  function withdrawAll() external onlyOwner {
      payable(owner).transfer(address(this).balance);
  }
  
  // FIX 2: Role-based access (OpenZeppelin)
  import "@openzeppelin/contracts/access/AccessControl.sol";
  
  contract Vault is AccessControl {
      bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER");
  
      function withdraw() external onlyRole(WITHDRAWER_ROLE) {
          // Only authorized withdrawers
      }
  }
  
  // FIX 3: Two-step ownership transfer
  address public pendingOwner;
  
  function transferOwnership(address newOwner) external onlyOwner {
      pendingOwner = newOwner;
  }
  
  function acceptOwnership() external {
      require(msg.sender == pendingOwner, "Not pending owner");
      emit OwnershipTransferred(owner, pendingOwner);
      owner = pendingOwner;
      pendingOwner = address(0);
  }
  
### **References**
  - https://swcregistry.io/docs/SWC-105
  - https://docs.openzeppelin.com/contracts/4.x/access-control

## Denial of Service Vulnerabilities

### **Id**
denial-of-service
### **Severity**
HIGH
### **Description**
Contract functions can be made permanently unusable
### **Symptoms**
  - Functions revert for all users
  - State transition impossible
  - Funds locked permanently
### **Detection Pattern**
for.*length|while|push|array\[|external.*loop
### **Solution**
  // VULNERABLE: Unbounded loop
  function distributeRewards() external {
      for (uint i = 0; i < stakers.length; i++) {
          // If stakers grows too large, exceeds gas limit
          stakers[i].transfer(rewards[i]);
      }
  }
  
  // VULNERABLE: External call in loop
  function refundAll() external {
      for (uint i = 0; i < users.length; i++) {
          // One malicious contract can block everyone
          payable(users[i]).transfer(refunds[i]);
      }
  }
  
  // FIX 1: Pull pattern
  mapping(address => uint256) public pendingRewards;
  
  function claimReward() external {
      uint256 reward = pendingRewards[msg.sender];
      require(reward > 0, "No reward");
      pendingRewards[msg.sender] = 0;
      payable(msg.sender).transfer(reward);
  }
  
  // FIX 2: Paginated processing
  function distributeRewards(uint256 start, uint256 end) external {
      require(end <= stakers.length);
      for (uint i = start; i < end; i++) {
          pendingRewards[stakers[i]] += calculateReward(i);
      }
  }
  
  // FIX 3: Gas-bounded loops
  function processQueue() external {
      uint256 gasStart = gasleft();
      while (queue.length > 0 && gasleft() > gasStart / 2) {
          processNext();
      }
  }
  
### **References**
  - https://swcregistry.io/docs/SWC-128
  - https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/

## Precision Loss in Calculations

### **Id**
precision-loss
### **Severity**
MEDIUM
### **Description**
Integer division rounds down, accumulating errors
### **Symptoms**
  - Small deposits receive 0 shares
  - Fees lower than expected
  - Dust amounts accumulating in contract
### **Detection Pattern**
\/ [0-9]|division|precision|shares
### **Solution**
  // VULNERABLE: Division before multiplication
  function calculateFee(uint256 amount) public view returns (uint256) {
      return amount / 10000 * feeBps;  // Loses precision!
      // If amount = 500, feeBps = 30: returns 0 instead of 1
  }
  
  // FIX 1: Multiply before divide
  function calculateFee(uint256 amount) public view returns (uint256) {
      return amount * feeBps / 10000;  // Much more precise
  }
  
  // VULNERABLE: Share calculation with small deposits
  function deposit(uint256 assets) external returns (uint256 shares) {
      shares = assets * totalShares / totalAssets;  // Could be 0!
      // Attacker can donate assets to make shares worthless
  }
  
  // FIX 2: Use minimum share/asset amounts
  uint256 constant MINIMUM_SHARES = 1000;
  
  function deposit(uint256 assets) external returns (uint256 shares) {
      if (totalShares == 0) {
          shares = assets - MINIMUM_SHARES;  // Lock minimum
          _mint(address(0), MINIMUM_SHARES);  // Dead shares
      } else {
          shares = assets * totalShares / totalAssets;
      }
      require(shares > 0, "Zero shares");
  }
  
  // FIX 3: Use higher precision internally
  uint256 constant PRECISION = 1e18;
  
  function calculateReward(uint256 stake) internal view returns (uint256) {
      return stake * rewardRate * PRECISION / totalStaked / PRECISION;
  }
  
### **References**
  - https://blog.openzeppelin.com/a-]udit-of-yearn-finance-vault-contracts
  - https://ethereum.stackexchange.com/questions/55701

## ERC-777 Token Callback Reentrancy

### **Id**
reentrancy-via-erc777
### **Severity**
MEDIUM
### **Description**
ERC-777 tokens call hooks before balance updates
### **Symptoms**
  - Reentrancy despite no ETH transfers
  - Exploits in ERC-20-looking code
  - Callbacks during token transfers
### **Detection Pattern**
IERC20|transfer|transferFrom|ERC20|token
### **Solution**
  // ERC-777 tokens look like ERC-20 but have callbacks!
  // tokensReceived() called BEFORE balance updated
  
  // VULNERABLE: Assumes ERC-20 behavior
  function deposit(IERC20 token, uint256 amount) external {
      uint256 before = token.balanceOf(address(this));
      token.transferFrom(msg.sender, address(this), amount);
      uint256 after = token.balanceOf(address(this));
      // If ERC-777, callback in transferFrom can reenter here
      // with balance already updated but deposit not recorded
      deposited[msg.sender] += after - before;
  }
  
  // FIX 1: Reentrancy guard on all token operations
  function deposit(IERC20 token, uint256 amount) external nonReentrant {
      // Safe even with ERC-777
  }
  
  // FIX 2: Check-Effects-Interactions for tokens too
  function deposit(IERC20 token, uint256 amount) external {
      deposited[msg.sender] += amount;  // Effect first
      token.safeTransferFrom(msg.sender, address(this), amount);
  }
  
  // FIX 3: Whitelist known-safe tokens only
  mapping(address => bool) public allowedTokens;
  
  function deposit(IERC20 token, uint256 amount) external {
      require(allowedTokens[address(token)], "Token not allowed");
      // ...
  }
  
### **References**
  - https://eips.ethereum.org/EIPS/eip-777
  - https://blog.openzeppelin.com/exploiting-uniswap-from-reentrancy-to-actual-profit

## Centralization and Trust Assumptions

### **Id**
centralization-risks
### **Severity**
MEDIUM
### **Description**
Single points of failure in "decentralized" protocols
### **Symptoms**
  - Owner can rug users
  - Admin keys can pause/drain
  - Upgrades can change any logic
### **Detection Pattern**
owner|admin|pause|upgrade|setImplementation|mint\(
### **Solution**
  // RED FLAGS:
  // - Single owner can pause, withdraw, or upgrade
  // - Minting function without cap
  // - No timelock on critical operations
  // - Upgradeable without governance
  
  // FIX 1: Multi-sig for admin operations
  // Use Gnosis Safe with 3/5 or 4/7 threshold
  
  // FIX 2: Timelock for critical changes
  uint256 constant TIMELOCK_DELAY = 2 days;
  mapping(bytes32 => uint256) public timelocks;
  
  function queueUpgrade(address newImpl) external onlyOwner {
      bytes32 id = keccak256(abi.encode(newImpl));
      timelocks[id] = block.timestamp + TIMELOCK_DELAY;
      emit UpgradeQueued(newImpl, timelocks[id]);
  }
  
  function executeUpgrade(address newImpl) external onlyOwner {
      bytes32 id = keccak256(abi.encode(newImpl));
      require(timelocks[id] != 0 && timelocks[id] <= block.timestamp);
      delete timelocks[id];
      _upgradeTo(newImpl);
  }
  
  // FIX 3: Immutable critical parameters
  uint256 public immutable MAX_FEE = 500;  // Can never exceed 5%
  address public immutable TREASURY;       // Can never change
  
  // FIX 4: Renounce ownership when stable
  function renounceOwnership() external onlyOwner {
      owner = address(0);
      // Now no one can change critical parameters
  }
  
  // DOCUMENT: All trust assumptions in README/audit report
  
### **References**
  - https://docs.openzeppelin.com/contracts/4.x/governance
  - https://blog.trailofbits.com/2020/05/21/reinventing-the-weel/

## Hardcoded Chain ID Breaks on Forks

### **Id**
chainid-hardcoding
### **Severity**
MEDIUM
### **Description**
Chain ID should be computed, not stored
### **Symptoms**
  - Signatures valid on wrong chain after fork
  - Contract unusable on forked chain
  - Replay attacks across chains
### **Detection Pattern**
chainId|block\.chainid|DOMAIN_SEPARATOR
### **Solution**
  // VULNERABLE: Stored chain ID
  contract Permit {
      uint256 public immutable CHAIN_ID;
      bytes32 public immutable DOMAIN_SEPARATOR;
  
      constructor() {
          CHAIN_ID = block.chainid;
          DOMAIN_SEPARATOR = computeDomainSeparator();
      }
  }
  // After fork, CHAIN_ID doesn't match block.chainid
  // Signatures valid on both chains!
  
  // FIX: Compute dynamically
  contract SafePermit {
      bytes32 private immutable INITIAL_DOMAIN_SEPARATOR;
      uint256 private immutable INITIAL_CHAIN_ID;
  
      constructor() {
          INITIAL_CHAIN_ID = block.chainid;
          INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();
      }
  
      function DOMAIN_SEPARATOR() public view returns (bytes32) {
          if (block.chainid == INITIAL_CHAIN_ID) {
              return INITIAL_DOMAIN_SEPARATOR;  // Gas optimization
          }
          return computeDomainSeparator();  // Recompute if chain changed
      }
  
      function computeDomainSeparator() internal view returns (bytes32) {
          return keccak256(abi.encode(
              TYPE_HASH,
              keccak256(bytes(name())),
              keccak256(bytes("1")),
              block.chainid,  // Current chain ID
              address(this)
          ));
      }
  }
  
### **References**
  - https://eips.ethereum.org/EIPS/eip-2612
  - https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC20.sol

## Missing Signature Deduplication in Weighted Multi-Sig

### **Id**
missing-signature-deduplication
### **Severity**
HIGH
### **Description**
Weighted multi-signature schemes that allow duplicate signatories enable a single validator to accumulate disproportionate weight, bypassing quorum requirements
### **Symptoms**
  - Single validator passes quorum alone by repeating signatures
  - Checkpoint or governance operations succeed with minimal actual participation
  - Colluding minority controls multi-sig decisions
### **Detection Pattern**
signatories|validateSignatures|weighted|quorum|checkpoint
### **Exploit Flow**
  // Vulnerable: no uniqueness check on signatories array
  function validateSignatures(
      address[] calldata signatories,
      bytes[] calldata signatures,
      bytes32 hash
  ) internal view {
      uint256 totalWeight;
      for (uint256 i = 0; i < signatories.length; i++) {
          address signer = ECDSA.recover(hash, signatures[i]);
          uint256 weight = validatorWeight[signer];
          totalWeight += weight;  // No check: same signer counted multiple times!
      }
      require(totalWeight >= quorumThreshold);
  }

  // Attack: validator with weight 6 signs 10 times = 60 weight
  // If quorum = 51, this single validator passes alone
  address[] memory badSignatories = new address[](10);
  bytes[] memory badSigs = new bytes[](10);
  for (uint i = 0; i < 10; i++) {
      badSignatories[i] = maliciousValidator;
      badSigs[i] = sign(hash, maliciousValidatorKey);
  }
  // validateSignatures() counts weight 10 times
### **Solution**
  // FIX 1: Check uniqueness before accumulating weight
  mapping(address => bool) seen;
  for (uint256 i = 0; i < signatories.length; i++) {
      require(!seen[signatories[i]], "Duplicate signatory");
      seen[signatories[i]] = true;
      totalWeight += validatorWeight[signatories[i]];
  }

  // FIX 2: Sort and compare adjacent entries
  require(isUniqueSorted(signatories), "Signatories not unique");

  // FIX 3: Accumulate per-signer weight once
  for (uint256 i = 0; i < signatories.length; i++) {
      address signer = ECDSA.recover(hash, signatures[i]);
      totalWeight += validatorWeight[signer];  // Deduplicated by recover()
  }

### **References**
  - Code4rena 2025-02-recall H-01

## Xnet Call Value Supply Inflation

### **Id**
xnet-call-value-supply-inflation
### **Severity**
HIGH
### **Description**
Cross-net (xnet) messages of kind Call with non-zero value bypass circulating supply accounting, inflating the destination subnet's circulating supply without a corresponding burn in the source
### **Symptoms**
  - Circulating supply in destination subnet exceeds actual locked value
  - Protocol invariant "total locked == total circulating" is violated
  - Attacker can create value out of thin air via bridging
### **Detection Pattern**
circSupply|circulatingSupply|execBottomUpMsgs|Call.*value|xnet|crossMsg
### **Exploit Flow**
  // Vulnerable: only non-Call messages contribute to totalValue
  function execBottomUpMsgs(IpcEnvelope[] calldata msgs) internal {
      uint256 totalValue;
      for (uint256 i; i < msgs.length; i++) {
          if (msgs[i].kind != IpcMsgKind.Call) {  // BUG: skips Call-kind with value!
              totalValue += msgs[i].value;
          }
      }
      // ... checks totalValue against circSupply
      subnet.circSupply -= totalValue;
      // Call messages with value were never accounted for!
  }

  // If subnet A has 1,000,000 locked and circSupply = 1,000,000
  // Attacker bridges 5,000 via xnet Call message
  // 5,000 is NOT added to totalValue (kind == Call skips it)
  // Destination subnet B circSupply += 5,000 (via TopDown handler)
  // Source subnet A circSupply remains 1,000,000 (should be 995,000)
  // Net effect: 5,000 tokens created from thin air
### **Solution**
  // FIX: Count ALL message values regardless of kind
  for (uint256 i; i < msgs.length; i++) {
      totalValue += msgs[i].value;  // Remove the kind check
  }

  // Or if Call messages should not affect supply:
  // Mint/burn explicitly at the bridging boundary
  // rather than relying on execBottomUpMsgs to handle accounting
### **References**
  - Code4rena 2025-02-recall H-02

## IPC Result Hash Mismatch

### **Id**
ipc-result-hash-mismatch
### **Severity**
HIGH
### **Description**
The hash used to track in-flight IPC messages (toHash) includes localNonce, but the receipt's tracing ID (toTracingId) omits it — causing receipts to never match original messages and permanently locking funds
### **Symptoms**
  - In-flight IPC calls never resolved
  - Funds permanently locked in inflight tracking mapping
  - Receipt messages rejected with UnrecognizedResult
### **Detection Pattern**
toHash|toTracingId|inflight|inFlight|incoming|IPCAddress|result\.id
### **Exploit Flow**
  // Stored with localNonce in the hash:
  function performIpcCall(...) internal returns (IpcEnvelope memory) {
      envelope = gateway.sendContractXnetMessage(...);
      bytes32 id = envelope.toHash();           // Includes localNonce
      inflightMsgs[id] = envelope;              // Stored under this key
  }

  // But toTracingId (used in result) omits localNonce:
  function toTracingId(IpcEnvelope memory crossMsg) internal pure returns (bytes32) {
      return keccak256(abi.encode(
          crossMsg.kind,
          crossMsg.to,
          crossMsg.from,
          crossMsg.value,
          crossMsg.message,
          crossMsg.originalNonce  // localNonce NOT included!
      ));
  }

  // Result.id is computed via toTracingId (no localNonce)
  // But inflightMsgs was stored under toHash (has localNonce)
  // Result.id != stored id -> lookup fails -> UnrecognizedResult
  // Funds locked forever in inflightMsgs[oldId]
### **Solution**
  // FIX: Use consistent hash function for both directions
  // Either both include localNonce or both omit it

  // Recommended: strip nonce for cross-chain idempotency
  function toTracingId(IpcEnvelope memory crossMsg) internal pure returns (bytes32) {
      return keccak256(abi.encode(  // Include localNonce for matching
          crossMsg.kind,
          crossMsg.to,
          crossMsg.from,
          crossMsg.value,
          crossMsg.message,
          crossMsg.localNonce,    // ADD: matches what toHash uses
          crossMsg.originalNonce
      ));
  }

  // Or simpler: store using the same idempotent hash everywhere
  bytes32 id = keccak256(abi.encodePacked(
      crossMsg.from, crossMsg.to, crossMsg.value, crossMsg.message
  ));
### **References**
  - Code4rena 2025-02-recall H-03

## Bottom-Up Message Batch Overflow DoS

### **Id**
bottomup-batch-overflow-dos
### **Severity**
HIGH
### **Description**
The count of messages in a bottom-up batch is stored in a type that can overflow, causing the checkpoint to revert and halting the entire subnet permanently
### **Symptoms**
  - Bottom-up checkpoint execution fails permanently
  - Subnet cannot submit checkpoints to parent
  - All cross-subnet activity halted
  - Potential permanent fund lockup across the subnet
### **Detection Pattern**
msgBatch|commitBottomUp|bottomUpMsg|messageCount|batch.*count|crossMsg.*length
### **Exploit Flow**
  // Vulnerable: unchecked batch message count
  struct BottomUpCheckpoint {
      uint64 start;
      uint64 end;
      BottomUpMessage[] messages;
  }

  function commitBottomUp(BottomUpCheckpoint calldata checkpoint) external {
      uint256 totalMessages = checkpoint.messages.length;
      // If messages.length > type(uint256).max (impossible in practice)
      // or if length is added to existing count without overflow check:
      totalMessageCount += totalMessages;  // No overflow guard
      // Attack: craft a batch that overflows totalMessageCount
      // After overflow, subsequent commits always revert on underflow check
  }

  // Specific variant from Recall:
  // uint256 totalValue accumulates messages[i].value
  // but circSupply -= totalValue can underflow if totalValue > circSupply
  // caused by malicious batch construction
### **Solution**
  // FIX 1: Explicit overflow check on counter
  uint256 newTotal = totalMessageCount + checkpoint.messages.length;
  require(newTotal >= totalMessageCount, "Overflow in message count");
  totalMessageCount = newTotal;

  // FIX 2: Use SafeMath or Solidity 0.8+ arithmetic (with careful overflow checks)
  totalMessageCount += checkpoint.messages.length;  // Reverts on overflow in 0.8+

  // FIX 3: Cap on batch size
  require(checkpoint.messages.length <= MAX_BATCH_SIZE, "Batch too large");

  // FIX 4: Validate totalValue doesn't exceed circSupply before subtraction
  uint256 totalValue = sumMessagesValue(checkpoint.messages);
  require(totalValue <= circSupply, "Insufficient circ supply for batch");
### **References**
  - Code4rena 2025-02-recall H-04

## Cross-Chain Circulating Supply Mismatch

### **Id**
crosschain-supply-mismatch
### **Severity**
HIGH
### **Description**
Cross-chain bridging operations that transfer value between subnets fail to atomically reconcile circulating supply on both sides, creating a discrepancy between total locked value and total circulating supply
### **Symptoms**
  - Protocol invariant broken: total locked != total circulating across subnets
  - Attacker can drain value by bridging in circles
  - Supply inflation in destination chain
  - Unbacked tokens circulating without corresponding lockup
### **Detection Pattern**
circSupply|circulatingSupply|lock\(|unlock\(|burn|mint|cross-chain|bridge|subnet.*supply
### **Exploit Flow**
  // Protocol invariant: SUM(circSupply[all subnets]) == total locked in parent
  // If bridging path A -> B -> A through two routes:
  //
  // A -> B: subnet.circSupply[B] += value; subnet.circSupply[A] -= value
  //         BUT if value > circSupply[A], subtraction underflows
  //         and A's circSupply stays artificially high
  //
  // B -> A: subnet.circSupply[A] += value; subnet.circSupply[B] -= value
  //         Now A has extra supply from the underflow + this mint
  //         B's circSupply also gets extra mint
  //         Attacker bridges back: A's extra supply burns back
  //         B's extra supply burns back
  //         Attacker extracted value without locking equivalent collateral

  // The vulnerability occurs when:
  // 1. Burn/mint is not atomic with lock/unlock
  // 2. Supply updates happen before cross-chain message is confirmed
  // 3. Failed cross-chain message does not roll back local state
### **Solution**
  // FIX 1: Optimistic + confirm/fail pattern
  // State changes are provisional until cross-chain message confirmed
  // If message fails, provisional state rolls back automatically

  // FIX 2: Two-phase commit
  // Phase 1: Lock value in source, emit cross-chain message
  // Phase 2: On receipt confirmation, mint in destination
  //          On receipt failure, unlock in source (no mint)

  // FIX 3: Use cumulative supply tracking
  // Each subnet tracks delta supply relative to parent
  // Final reconciliation done atomically at epoch boundary

  // FIX 4: Invariant monitoring
  // require(
  //     totalLocked == sum(circSupply[all_subnets]),
  //     "Supply invariant violated"
  // );
### **References**
  - Code4rena 2025-09-monad (supply invariant findings)
  - Code4rena 2025-10-sequence (cross-chain accounting)