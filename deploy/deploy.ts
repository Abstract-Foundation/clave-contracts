/**
 * Copyright Clave - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
import {
    ZeroAddress,
    zeroPadValue
} from 'ethers';
import * as hre from 'hardhat';
import { Contract, Wallet, utils } from 'zksync-ethers';
import { deployContract, getWallet, verifyContract } from '../deploy/utils';
import type { CallStruct } from '../typechain-types/contracts/batch/BatchCaller';
let fundingWallet: Wallet;

let batchCaller: Contract;
let eoaValidator: Contract;
let implementation: Contract;
let factory: Contract;
let registry: Contract;

// An example of a basic deploy script
// Do not push modifications to this file
// Just modify, interact then revert changes
export default async function (): Promise<void> {
    fundingWallet = getWallet(hre);

    const initialOwner = fundingWallet.address;

    batchCaller = await deployContract(hre, 'BatchCaller', undefined, 'create2', {
        wallet: fundingWallet,
        silent: false,
    });

    eoaValidator = await deployContract(hre, 'EOAValidator', undefined, 'create2', {
        wallet: fundingWallet,
        silent: false,
    });

    implementation = await deployContract(
        hre,
        'ClaveImplementation',
        [await batchCaller.getAddress()],
        'create2',
        {
            wallet: fundingWallet,
            silent: false,
        },
    );

    registry = await deployContract(hre, 'ClaveRegistry',
        [
            initialOwner,
        ],
        'create2',
        { wallet: fundingWallet, silent: false,
    });

    // Need this so the ClaveProxy artifact is valid
    await deployContract(
        hre,
        'ClaveProxy',
        [await implementation.getAddress()],
        'create2',
        { wallet: fundingWallet, silent: true, noVerify: true },
    );

    const accountProxyArtifact = await hre.zksyncEthers.loadArtifact('ClaveProxy');
    const bytecodeHash = utils.hashBytecode(accountProxyArtifact.bytecode);
    factory = await deployContract(
        hre,
        'AccountFactory',
        [
            await implementation.getAddress(),
            await registry.getAddress(),
            bytecodeHash,
            fundingWallet.address,
            initialOwner,
        ],
        'create2',
        {
            wallet: fundingWallet,
            silent: false,
        },
    );
    await registry.setFactory(await factory.getAddress());

    const abiCoder = hre.ethers.AbiCoder.defaultAbiCoder();
    const call: CallStruct = {
        target: ZeroAddress,
        allowFailure: false,
        value: 0,
        callData: '0x',
    };

    const salt = initialOwner.padEnd(66, '0');
    const initializer =
        '0xb4e581f5' +
        abiCoder
            .encode(
                [
                    'address',
                    'address',
                    'bytes[]',
                    'tuple(address target,bool allowFailure,uint256 value,bytes calldata)',
                ],
                [
                    initialOwner,
                    await eoaValidator.getAddress(),
                    [],
                    [call.target, call.allowFailure, call.value, call.callData],
                ],
            )
            .slice(2);

    const tx = await factory.deployAccount(salt, initializer);
    await tx.wait();

    const accountAddress = await factory.getAddressForSalt(salt);
    await verifyContract(hre, {
        address: accountAddress,
        contract: "contracts/ClaveProxy.sol:ClaveProxy",
        constructorArguments: zeroPadValue(accountAddress, 32),
        bytecode: accountProxyArtifact.bytecode
    })
    console.log("accountAddress", accountAddress)

    // account = new Contract(
    //     accountAddress,
    //     implementation.interface,
    //     fundingWallet,
    // );
    // // 0.0001 ETH transfered to Account
    // await (
    //     await fundingWallet.sendTransaction({
    //         to: await account.getAddress(),
    //         value: parseEther('0.0001'),
    //     })
    // ).wait();
}
