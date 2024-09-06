// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2 as console} from "forge-std/Test.sol";

import {MinimalAccount} from "src/ethereum/MinimalAccount.sol";
import {DeployMinimal} from "script/DeployMinimal.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";
import {SendPackedUserOp, PackedUserOperation} from "script/SendPackedUserOp.s.sol";

import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract MinimalAccountTest is Test {
    using MessageHashUtils for bytes32;

    HelperConfig helperConfig;
    MinimalAccount minimalAccount;
    ERC20Mock usdc;
    SendPackedUserOp sendPackedUserOp;

    address public randomUser = makeAddr("randomUser");
    uint256 public constant TOKEN_MINT_AMOUNT = 1000e18;

    function setUp() external {
        DeployMinimal deployMinimal = new DeployMinimal();
        (helperConfig, minimalAccount) = deployMinimal.deployMinimal();

        usdc = new ERC20Mock();

        sendPackedUserOp = new SendPackedUserOp();
    }

    function testOwnerCanExecuteCommands() public {
        vm.assertEq(usdc.balanceOf(address(minimalAccount)), 0);

        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData =
            abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), TOKEN_MINT_AMOUNT);

        console.log("[MinimalAccountTest] EntryPoint Contract Address: ", helperConfig.getConfig().entryPoint);
        console.log("[MinimalAccountTest] Owner of MinimalAccount", minimalAccount.owner());

        vm.prank(minimalAccount.owner());
        minimalAccount.execute(dest, value, functionData);

        vm.assertEq(usdc.balanceOf(address(minimalAccount)), TOKEN_MINT_AMOUNT);
    }

    function testExecuteFailsWhenCalledByNonOwnerOrEntryPoint() public {
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData =
            abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), TOKEN_MINT_AMOUNT);

        vm.expectRevert(MinimalAccount.MinimalAccount__NotFromEntryPointOrOwner.selector);
        vm.prank(randomUser);
        minimalAccount.execute(dest, value, functionData);
    }

    function testRecoverSignedOp() public {
        // arrange
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData =
            abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), TOKEN_MINT_AMOUNT);

        bytes memory executeCallData =
            abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, functionData);

        PackedUserOperation memory packedUserOp =
            sendPackedUserOp.generateSignedPackedUserOperation(executeCallData, helperConfig.getConfig(), address(minimalAccount));

        bytes32 userOperationHash = IEntryPoint(helperConfig.getConfig().entryPoint).getUserOpHash(packedUserOp);

        // act
        address acutalSigner = ECDSA.recover(userOperationHash.toEthSignedMessageHash(), packedUserOp.signature);
        // assert

        assertEq(acutalSigner, minimalAccount.owner());
    }

    function testValidationOfUserOps() public {
        // arrange
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData =
            abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), TOKEN_MINT_AMOUNT);

        bytes memory executeCallData =
            abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, functionData);

        PackedUserOperation memory packedUserOp =
            sendPackedUserOp.generateSignedPackedUserOperation(executeCallData, helperConfig.getConfig(), address(minimalAccount));

        bytes32 userOperationHash = IEntryPoint(helperConfig.getConfig().entryPoint).getUserOpHash(packedUserOp);

        uint256 missingAccountFunds = 1e18;

        // act
        vm.prank(helperConfig.getConfig().entryPoint);
        uint256 validationData = minimalAccount.validateUserOp(packedUserOp, userOperationHash, missingAccountFunds);

        assertEq(validationData, 0);
    }

    function testEntryPointCanExecuteCommands() public {
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData =
            abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), TOKEN_MINT_AMOUNT);

        bytes memory executeCallData =
            abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, functionData);

        PackedUserOperation memory packedUserOp =
            sendPackedUserOp.generateSignedPackedUserOperation(executeCallData, helperConfig.getConfig(), address(minimalAccount));

        vm.deal(address(minimalAccount), TOKEN_MINT_AMOUNT);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = packedUserOp;
        // act

        vm.deal(randomUser, 1e18);
        console.log("Balance of Random User: ", randomUser.balance);
        vm.prank(randomUser);
        IEntryPoint(helperConfig.getConfig().entryPoint).handleOps(ops, payable(randomUser));

        // assert
        vm.assertEq(usdc.balanceOf(address(minimalAccount)), TOKEN_MINT_AMOUNT);
    }
}
