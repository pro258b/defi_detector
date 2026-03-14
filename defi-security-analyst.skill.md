# DeFi Security Analyst

## Description
Analyzes DeFi protocols for security vulnerabilities based on real exploit patterns from DeFiHackLabs. Identifies common attack vectors including access control flaws, price manipulation, flash loan attacks, and unsafe external calls.

## Trigger
Use when analyzing smart contracts for security vulnerabilities, reviewing DeFi protocols, or investigating potential exploits.

## Core Capabilities

### 1. Vulnerability Pattern Recognition
- **Access Control Bypass**: Missing authentication checks allowing unauthorized function calls
- **Price Oracle Manipulation**: Exploiting price feeds via flash loans or liquidity manipulation
- **Unsafe External Calls**: Arbitrary call execution without proper validation
- **Integer Overflow/Underflow**: Type casting vulnerabilities (e.g., uint256 to uint128)
- **Reentrancy**: State manipulation through callback functions
- **Flash Loan Attacks**: Leveraging temporary capital for market manipulation

### 2. Attack Vector Analysis

**Signature Validation Exploits**
- ERC-6492 signature bypass (ODOS pattern)
- Missing signer verification
- Arbitrary calldata execution in signature validation

**DEX/AMM Manipulation**
- Liquidity pool price manipulation
- Sandwich attacks on swaps
- Curve pool imbalance exploitation

**Lending Protocol Exploits**
- Collateral manipulation
- Liquidation cascades
- Vault pricing arbitrage
- NFT collateral overvaluation
- Bad debt restructuring abuse

**Settlement Contract Flaws**
- Order validation bypass
- Unauthorized token transfers via interactions array
- Missing taker verification
- Unvalidated swap calldata execution

### 3. Code Review Checklist

```solidity
// RED FLAGS
✗ External calls without access control
✗ transferFrom() callable by arbitrary addresses
✗ Price calculations from single DEX
✗ Unsafe type casting (uint256 → uint128)
✗ Missing signature validation
✗ Arbitrary target in delegatecall/call
✗ Flash loan without proper state checks
✗ Oracle price without staleness check
✗ NFT/LP positions used as collateral without valuation
✗ Unvalidated swap router calldata
✗ Bad debt clearing without collateral verification
✗ Precision loss in repeated calculations
```

### 4. Exploit Construction Pattern

```solidity
// Typical exploit flow:
1. Flash loan large capital (Morpho, Aave, Balancer)
2. Manipulate state (price, liquidity, collateral)
3. Execute vulnerable function
4. Profit from state change
5. Repay flash loan
6. Extract profit
```

## Analysis Framework

### Quick Triage
1. **Identify entry points**: Public/external functions
2. **Check access control**: Who can call what?
3. **Trace value flow**: Where do tokens move?
4. **Find state dependencies**: What affects critical calculations?
5. **Test edge cases**: Overflow, underflow, zero values

### Deep Dive
```
Input Validation → State Changes → External Calls → Value Transfer
     ↓                  ↓               ↓                ↓
  Missing?         Manipulable?    Arbitrary?      Authorized?
```

## Common Exploit Patterns

### Pattern 1: Signature Bypass
```solidity
// Vulnerable: ERC-6492 allows arbitrary calls
function isValidSig(address signer, bytes32 hash, bytes calldata sig) {
    if (hasSuffix(sig, ERC6492_SUFFIX)) {
        (address target, bytes memory data,) = abi.decode(sig);
        target.call(data); // ← EXPLOIT: Arbitrary call
    }
}
```

### Pattern 2: Settlement Interaction Exploit
```solidity
// Vulnerable: No validation on interaction targets
function settle(Order order, Interaction[] interactions) {
    for (Interaction i : interactions) {
        i.to.call(i.data); // ← EXPLOIT: Can call token.transferFrom()
    }
}
```

### Pattern 3: Oracle Manipulation
```solidity
// Vulnerable: Single-source price
function getPrice() returns (uint) {
    return uniswapPool.getSpotPrice(); // ← EXPLOIT: Flash loan manipulable
}
// Fix: Use TWAP or multiple oracles
```

### Pattern 4: Type Casting Overflow
```solidity
// Vulnerable: Unsafe downcast
uint256 shares = type(uint128).max + 2;
uint128 safeShares = uint128(shares); // ← EXPLOIT: Wraps to 1
```

### Pattern 5: NFT Collateral Manipulation
```solidity
// Vulnerable: Inflated NFT position used as collateral
function mint(uint256 tokenId) external {
    // Missing validation of NFT value
    collateral[tokenId] = nft.balanceOf(tokenId); // ← EXPLOIT: Manipulated LP position
}
// Attack: Create LP with minimal liquidity, use as collateral, borrow max
```

### Pattern 6: Arbitrary Call via Swap Data
```solidity
// Vulnerable: Unvalidated swap calldata
function leverageUpWithSwap(SwapParams[] swapParams) external {
    (address target, bytes memory data) = abi.decode(swapParams[0].data);
    target.call(data); // ← EXPLOIT: Can call victim.transferFrom()
}
// Fix: Whitelist swap routers, validate calldata structure
```

### Pattern 7: Precision Loss in AMM Math
```solidity
// Vulnerable: Rounding errors accumulate
uint256 amountOutScaled = mulDown(tokenAmountOut, scalingFactor); // ← precision loss
uint256 amountInScaled = calcInGivenOut(..., amountOutScaled, ...);
// Attack: Repeated small swaps exploit rounding to drain pool
// Balancer V2: 100+ swaps with specific amounts trigger invariant violation
```

### Pattern 8: Bad Debt Restructuring
```solidity
// Vulnerable: Liquidation without proper collateral check
function restructureBadDebt(uint tokenId) external {
    // Missing: Verify position is actually underwater
    delete borrowBalance[tokenId]; // ← EXPLOIT: Erase debt without repayment
}
// Attack: Manipulate price oracle, trigger restructure, keep collateral
```

## Response Format

When analyzing a contract, provide:

1. **Vulnerability Summary**: One-line description
2. **Attack Vector**: How it can be exploited
3. **Impact**: Financial loss estimate
4. **Root Cause**: Code-level issue
5. **Proof of Concept**: Minimal exploit code
6. **Remediation**: Specific fix

## Example Analysis

```
Contract: BebopSettlement
Vulnerability: Unauthorized transferFrom via interactions
Attack Vector: Attacker crafts JamOrder with interactions calling
  USDC.transferFrom(victim, attacker, amount) without victim approval check
Impact: $21k stolen from users with token approvals
Root Cause: No validation that interaction.to is whitelisted
Fix: Whitelist allowed interaction targets or remove arbitrary calls
```

## Advanced Attack Patterns

### Lending Protocol Exploits

**Paribus ($86k)**: NFT collateral overvaluation
- Create Uniswap V3 LP position with minimal liquidity
- Deposit LP NFT as collateral without proper valuation
- Borrow maximum against inflated collateral value
- Withdraw borrowed assets, abandon worthless NFT

**Impermax V3 ($300k)**: Fee accumulation + bad debt manipulation
- Flash loan WETH + USDC
- Mint LP position, deposit as collateral
- Execute 100+ swaps to accumulate fees in position
- Call `reinvest()` to compound fees into position value
- Borrow against inflated position
- Call `restructureBadDebt()` to erase debt
- Redeem collateral with profit

### AMM/DEX Exploits

**Balancer V2 ($120M)**: Precision loss via repeated swaps
- Exploit rounding errors in `_calcInGivenOut()`
- Phase 1: Drain pool tokens via BPT swaps
- Phase 2: Execute 25-30 rounds of micro-swaps exploiting `scalingFactor` precision loss
- Phase 3: Large swaps to extract accumulated value
- Key: `trickAmt = 10000 / ((scalingFactor - 1e18) * 10000 / 1e18)`

**Size Credit ($19.7k)**: Calldata manipulation
- Target: `leverageUpWithSwap()` with unvalidated swap data
- Craft malicious `SwapParams.data` with victim's `transferFrom()`
- Modify ABI encoding offset (0x80 → 0x60) to bypass checks
- Execute arbitrary token transfers from approved users

## Tools & Techniques

- **Foundry**: Fork testing at exploit block
- **Tenderly**: Transaction simulation
- **Etherscan**: Contract verification & approval tracking
- **DeFiLlama**: TVL & protocol metrics
- **Phalcon/BlockSec**: Exploit detection

## Key Metrics by Exploit Type

| Attack Type | Avg Loss | Common Chains | Typical Flash Loan |
|-------------|----------|---------------|-------------------|
| Signature Bypass | $20-50k | Base, Arbitrum | No |
| Oracle Manipulation | $50-500k | Ethereum, BSC | Yes (Morpho/Aave) |
| NFT Collateral | $80-300k | Arbitrum, Base | Yes |
| AMM Precision | $100M+ | Ethereum | No (internal balance) |
| Arbitrary Call | $20-100k | All chains | Optional |

## References
- DeFiHackLabs: Real exploit reproductions
- Rekt News: Post-mortems
- Code4rena/Sherlock: Audit reports
- Trail of Bits: Security guides

## Bug Discovery Methodologies (Damn Vulnerable DeFi)

### Core Analysis Approaches

**1. Invariant Breaking**
- Examine strict accounting checks that can be violated through alternative code paths
- Example: Direct token transfers bypass deposit mechanisms, breaking ERC4626 compliance
- Look for: Balance checks that assume only one entry point

**2. Permission Model Gaps**
- Analyze authorization logic for missing actor validation
- Example: `onFlashLoan()` checks if caller is pool, but not if initiator is owner
- Look for: Functions checking `msg.sender` vs actual transaction initiator

**3. State Transition Exploitation**
- Find functions that don't properly mark state changes
- Example: Contract marks batch claimed after processing all claims (replay attack)
- Look for: State updates at end of function instead of beginning

**4. Flash Loan Abuse Patterns**
- Temporary capital for permanent effects (governance voting)
- Accounting confusion between loan repayment and deposits
- Arbitrary function execution during callbacks
- Look for: Functions callable during flash loan callbacks

**5. Oracle Manipulation**
- Identify price feeds relying on single sources without safeguards
- Example: Oracle price from 3 trusted reporters (exploitable if keys leak)
- Look for: `getPrice()` without TWAP or multiple sources

**6. Meta-Transaction Risks**
- Examine `_msgSender()` implementations for address extraction vulnerabilities
- Look for: Caller data appended to transaction payloads

### Discovery Techniques

1. **Code Path Analysis**: Trace all ways state can change (deposits, transfers, approvals)
2. **Callback Inspection**: Review functions invoked during external calls for reentrancy
3. **Accounting Reconciliation**: Compare when balances checked vs updated
4. **Permission Boundary Testing**: Identify `msg.sender` vs `_msgSender()` discrepancies

