/**
 * Copyright Clave - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
import type { Contract } from 'zksync-ethers';

import type { ClaveDeployer } from './deployer';
import { VALIDATORS } from './names';
import { HDNodeWallet } from 'ethers';
import { genKey } from './p256';
import { ec } from 'elliptic';

export type fixtureTypes = {
    batchCaller: Contract,
    registry: Contract,
    implementation: Contract,
    factory: Contract,
    eoaValidator: Contract,
    teeValidator: Contract,
    passkeyValidator: Contract,
    account: Contract,
    mockValidator: Contract,
    wallet: HDNodeWallet,
    keyPair: ec.KeyPair,
};

export const fixture = async (
    deployer: ClaveDeployer,
    validatorOption: VALIDATORS = VALIDATORS.MOCK,
): Promise<fixtureTypes> => {
    const wallet = HDNodeWallet.createRandom();

    const batchCaller = await deployer.batchCaller();
    const registry = await deployer.registry();
    const implementation = await deployer.implementation(batchCaller);
    const factory = await deployer.factory(implementation, registry);
    const eoaValidator = await deployer.validator(VALIDATORS.EOA);
    const teeValidator = await deployer.validator(VALIDATORS.TEE);
    const mockValidator = await deployer.validator(VALIDATORS.MOCK);
    const passkeyValidator = await deployer.validator(VALIDATORS.PASSKEY);

    const primaryValidator = validatorOption === VALIDATORS.EOA 
        ? eoaValidator 
        : validatorOption === VALIDATORS.TEE 
            ? teeValidator 
            : validatorOption === VALIDATORS.PASSKEY
                ? passkeyValidator
                : mockValidator;

    const account = await deployer.account(wallet, factory, primaryValidator);

    const keyPair = genKey();

    return {
        batchCaller,
        registry,
        implementation,
        factory,
        eoaValidator,
        teeValidator,
        mockValidator,
        passkeyValidator,
        account,
        wallet,
        keyPair
    };
};
