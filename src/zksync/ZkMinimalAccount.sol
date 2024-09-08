// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    IAccount,
    ACCOUNT_VALIDATION_SUCCESS_MAGIC
} from "foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {
    Transaction,
    MemoryTransactionHelper
} from "foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";
import {SystemContractsCaller} from
    "foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";
import {
    NONCE_HOLDER_SYSTEM_CONTRACT,
    BOOTLOADER_FORMAL_ADDRESS,
    DEPLOYER_SYSTEM_CONTRACT
} from "foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {INonceHolder} from "foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import {Utils} from "foundry-era-contracts/src/system-contracts/contracts/libraries/Utils.sol";

// openzeppelin
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract ZkMinimalAccount is IAccount, Ownable {
    using MemoryTransactionHelper for Transaction;

    error ZkMinimalAccount__NotEnoughBalance();
    error ZkMinimalAccount__NotFromBootLoader();
    error ZkMinimalAccount__NotFromBootLoaderOrOwner();
    error ZkMinimalAccount__ExecutionFailed();
    error ZkMinimalAccount__FailedToPay();

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier requireFromBootLoader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert ZkMinimalAccount__NotFromBootLoader();
        }
        _;
    }

    modifier requireFromBootLoaderOrOwner() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS && msg.sender != owner()) {
            revert ZkMinimalAccount__NotFromBootLoaderOrOwner();
        }
        _;
    }

    constructor() Ownable(msg.sender) {}

    receive() external payable {}
    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice we must increase the nonce after `validateTransaction` is called.
     * @notice must validate the transaction (check the woner signed the transaction)
     * @notice also check to see if we have enough money in our account
     */
    // very similar to validate user op
    // as zksync has account abstraction built in so it doesn't care what kind of transaction it is

    function validateTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction memory _transaction)
        external
        payable
        requireFromBootLoader
        returns (bytes4 magic)
    {
        return _validateTransaction(hex"", hex"", _transaction);
    }

    function executeTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction memory _transaction)
        external
        payable
        requireFromBootLoaderOrOwner
    {
        _executeTransaction(hex"", hex"", _transaction);
    }

    // There is no point in providing possible signed hash in the `executeTransactionFromOutside` method,
    // since it typically should not be trusted.
    function executeTransactionFromOutside(Transaction memory _transaction) external payable {
        _validateTransaction(hex"", hex"", _transaction);
        _executeTransaction(hex"", hex"", _transaction);
    }

    function payForTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction calldata _transaction)
        external
        payable
    {
        bool success = _transaction.payToTheBootloader();
        if (!success) {
            revert ZkMinimalAccount__FailedToPay();
        }
    }

    function prepareForPaymaster(bytes32 _txHash, bytes32 _possibleSignedHash, Transaction calldata _transaction)
        external
        payable
    {}

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _validateTransaction(
        bytes32, /*_txHash*/
        bytes32, /*_suggestedSignedHash*/
        Transaction memory _transaction
    ) internal returns (bytes4 magic) {
        // call nonceholder & increase old nonce
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (_transaction.nonce))
        );

        // check for fee to pay
        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        if (totalRequiredBalance > address(this).balance) {
            revert ZkMinimalAccount__NotEnoughBalance();
        }

        // check for signature
        bytes32 txHash = _transaction.encodeHash();
        address signer = ECDSA.recover(txHash, _transaction.signature);

        bool isValidSigner = signer == owner();
        if (isValidSigner) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }
        // return the "magic" number
        return magic;
    }

    function _executeTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction memory _transaction)
        internal
    {
        // converting uint256 -> address; uint256 -typecasting-> uint160 -typecasting-> address
        address to = address(uint160(_transaction.to));

        // this typecasting is just so that if at some point we are passing values to system
        // contracts which needs U128 so it is better to cast it using utils
        uint128 value = Utils.safeCastToU128(_transaction.value);
        bytes memory data = _transaction.data;

        // call to system contracts behaves differently than regular ones or should be handled
        // separately than the regular calls that's why we have added following conditional block
        // we can add it for other system contracts too but for this course we don't have to add it

        // following logic is if owner is calling to system contract for contract deployment
        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            uint32 gas = Utils.safeCastToU32(gasleft());
            SystemContractsCaller.systemCallWithPropagatedRevert(gas, to, value, data);
        }

        bool success;
        // this just a way to do delegate call on zksync as it differs from
        // how things works on regular EVM
        assembly {
            success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
        }
        if (!success) {
            revert ZkMinimalAccount__ExecutionFailed();
        }
    }
}
