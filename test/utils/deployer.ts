/**
 * Copyright Clave - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
import { AbiCoder, BaseWallet, BigNumberish, HDNodeWallet, ZeroAddress, keccak256, parseEther } from 'ethers';
import type { HardhatRuntimeEnvironment } from 'hardhat/types';
import type { Wallet } from 'zksync-ethers';
import { Contract, utils } from 'zksync-ethers';

import { deployContract, getWallet } from '../../deploy/utils';
import type { CallStruct } from '../../typechain-types/contracts/batch/BatchCaller';
import { CONTRACT_NAMES, PAYMASTERS, type VALIDATORS } from './names';

// This class helps deploy Clave contracts for the tests
export class ClaveDeployer {
    private hre: HardhatRuntimeEnvironment;
    private deployerWallet: Wallet;

    constructor(
        hre: HardhatRuntimeEnvironment,
        deployerWallet: string | Wallet,
    ) {
        this.hre = hre;

        typeof deployerWallet === 'string'
            ? (this.deployerWallet = getWallet(this.hre, deployerWallet))
            : (this.deployerWallet = deployerWallet);
    }

    public async registry(): Promise<Contract> {
        return await deployContract(
            this.hre,
            CONTRACT_NAMES.REGISTRY,
            [this.deployerWallet.address],
            {
                wallet: this.deployerWallet,
                silent: true,
            },
        );
    }

    public async implementation(): Promise<Contract> {
        return await deployContract(
            this.hre,
            CONTRACT_NAMES.IMPLEMENTATION,
            [],
            {
                wallet: this.deployerWallet,
                silent: true,
            },
        );
    }

    public async factory(
        implementation: Contract,
        registry: Contract,
    ): Promise<Contract> {
        // TODO: WHY DOES THIS HELP
        await deployContract(
            this.hre,
            CONTRACT_NAMES.PROXY,
            [await implementation.getAddress()],
            { wallet: this.deployerWallet, silent: true },
        );

        // Deploy factory contract
        const accountArtifact = await this.hre.zksyncEthers.loadArtifact(
            CONTRACT_NAMES.PROXY,
        );
        const bytecodeHash = utils.hashBytecode(accountArtifact.bytecode);
        const factory = await deployContract(
            this.hre,
            CONTRACT_NAMES.FACTORY,
            [
                await implementation.getAddress(),
                '0xb4e581f5',
                await registry.getAddress(),
                bytecodeHash,
                this.deployerWallet.address,
                this.deployerWallet.address,
            ],
            {
                wallet: this.deployerWallet,
                silent: true,
            },
        );

        // Assign the factory address to the registry
        const factorySetTx = await registry.setFactory(
            await factory.getAddress(),
        );
        await factorySetTx.wait();

        return factory;
    }

    public async setupFactory(): Promise<{
        registry: Contract;
        implementation: Contract;
        factory: Contract;
    }> {
        const registry = await this.registry();
        const implementation = await this.implementation();
        const factory = await this.factory(implementation, registry);

        return { registry, implementation, factory };
    }

    public async validator(name: VALIDATORS): Promise<Contract> {
        return await deployContract(this.hre, name, undefined, {
            wallet: this.deployerWallet,
            silent: true,
        });
    }

    public async account(
        wallet: BaseWallet,
        factory: Contract,
        validator: Contract,
        overrideValues: {
            salt?: string,
            initializer?: string,
            callValue?: BigNumberish,
            initialCall?: CallStruct,
        } = {},
    ): Promise<Contract> {
        let { salt, initializer, callValue, initialCall } = overrideValues;

        if (!salt) {
            salt = keccak256(wallet.address);
        }
        if (callValue === undefined) {
            callValue = 0;
        }
        if (!initialCall) {
            initialCall = {
                target: ZeroAddress,
                allowFailure: false,
                value: 0,
                callData: '0x',
            };
        }

        const abiCoder = AbiCoder.defaultAbiCoder();

        if (!initializer) {
         initializer =
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
                        wallet.address,
                        await validator.getAddress(),
                        [],
                        [
                            initialCall.target,
                            initialCall.allowFailure,
                            initialCall.value,
                            initialCall.callData,
                        ],
                    ],
                )
                .slice(2);
        }

        const deployPromise = await Promise.all([
            // Deploy account
            (async (): Promise<void> => {
                const deployTx = await factory.deployAccount(salt, initializer, { value: callValue });
                await deployTx.wait();
            })(),
            // Calculate  new account address
            (async (): Promise<string> => {
                return await factory.getAddressForSalt(salt);
            })(),
        ]);

        const accountAddress = deployPromise[1];
        const implementationInterface = (
            await this.hre.zksyncEthers.loadArtifact(
                CONTRACT_NAMES.IMPLEMENTATION,
            )
        ).abi;

        const account = new Contract(
            accountAddress,
            implementationInterface,
            this.deployerWallet,
        );

        return account;
    }

    public async paymaster(
        name: PAYMASTERS,
        config:  {
            gasless?: {
                registryAddress: string,
                limit: number
            };
            erc20?: Array<{
                tokenAddress: string;
                decimals: number;
                priceMarkup: number;
            }>;
        },
    ): Promise<Contract> {
        if (
            (name === PAYMASTERS.GASLESS && !config.gasless) ||
            (name === PAYMASTERS.ERC20 && !config.erc20) ||
            (name === PAYMASTERS.ERC20_MOCK && !config.erc20)
        ) {
            throw new Error('Config mismatch.');
        }

        return await deployContract(
            this.hre,
            name,
            [
                ...Object.values(name == PAYMASTERS.GASLESS ? config.gasless! : [config.erc20!]),
                this.deployerWallet.address,
            ],
            {
                wallet: this.deployerWallet,
                silent: true,
            },
        );
    }

    public async fund(
        ethAmount: number | string,
        accountAddress: string,
    ): Promise<void> {
        await (
            await this.deployerWallet.sendTransaction({
                to: accountAddress,
                value: parseEther(ethAmount.toString()),
            })
        ).wait();
    }

    public async deployCustomContract(
        name: string,
        constructorArgs: Array<unknown>,
    ): Promise<Contract> {
        return await deployContract(this.hre, name, constructorArgs, {
            wallet: this.deployerWallet,
            silent: true,
        });
    }
}
