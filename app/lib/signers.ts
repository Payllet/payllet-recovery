import { toKernelSmartAccount } from 'permissionless/accounts';
import {
    Address,
    concatHex,
    encodeAbiParameters,
    encodeFunctionData,
    Hex,
    keccak256,
    parseAbi,
    PublicClient,
    toFunctionSelector,
    toHex,
    zeroAddress,
} from 'viem';
import { getUserOperationHash, toWebAuthnAccount } from 'viem/account-abstraction';
import { privateKeyToAccount } from 'viem/accounts';
import { base64UrlToBytes } from 'webauthn-p256';

import {
    createRecoveryPublicClient,
    createVersionedKernelClient,
    PasskeyCredential,
} from './account';
import { CURRENT_VERSION, entryPoint, RecoveryChain } from './config';

/** Stock Kernel v3 ECDSA validator, deployed at one address on every chain. */
export const ECDSA_VALIDATOR: Address = '0x845ADb2C711129d4f3966735eD98a9F09fC4cE57';
export const WEBAUTHN_VALIDATOR: Address = CURRENT_VERSION.validatorAddress;

const MODULE_TYPE_VALIDATOR = 1n;

const kernelAbi = parseAbi([
    'function installModule(uint256 moduleType, address module, bytes initData)',
    'function uninstallValidation(bytes21 vId, bytes deinitData, bytes hookDeinitData)',
    'function changeRootValidator(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData)',
    'function rootValidator() view returns (bytes21)',
    'function execute(bytes32 execMode, bytes executionCalldata)',
]);

const ecdsaValidatorAbi = parseAbi([
    'function ecdsaValidatorStorage(address kernel) view returns (address owner)',
]);

const webAuthnValidatorAbi = parseAbi([
    'function webAuthnValidatorStorage(address kernel) view returns (uint256 pubKeyX, uint256 pubKeyY)',
]);

/** A Kernel v3 validation ID: the VALIDATOR type byte, then the module address. */
const validationId = (validator: Address): Hex => concatHex(['0x01', validator]);

interface Call {
    readonly to: Address;
    readonly value: bigint;
    readonly data: Hex;
}

export interface PublicKeyXY {
    readonly x: bigint;
    readonly y: bigint;
}

/** Splits an uncompressed P-256 key, 0x04 || x || y, into its coordinates. */
export const publicKeyXY = (publicKey: Hex): PublicKeyXY => {
    const body = publicKey.slice(publicKey.length - 128);
    return {
        x: BigInt(`0x${body.slice(0, 64)}`),
        y: BigInt(`0x${body.slice(64)}`),
    };
};

export interface SignerState {
    readonly deployed: boolean;
    readonly rootValidator: Hex | null;
    readonly ecdsaOwner: Address | null;
    readonly passkey: PublicKeyXY | null;
}

export const readSignerState = async (
    recoveryChain: RecoveryChain,
    account: Address,
): Promise<SignerState> => {
    const client = createRecoveryPublicClient(recoveryChain);
    const code = await client.getCode({ address: account });
    if (!code || code === '0x') {
        return { deployed: false, rootValidator: null, ecdsaOwner: null, passkey: null };
    }

    const [rootValidator, ecdsaOwner, [x, y]] = await Promise.all([
        client.readContract({ address: account, abi: kernelAbi, functionName: 'rootValidator' }),
        client.readContract({
            address: ECDSA_VALIDATOR,
            abi: ecdsaValidatorAbi,
            functionName: 'ecdsaValidatorStorage',
            args: [account],
        }),
        client.readContract({
            address: WEBAUTHN_VALIDATOR,
            abi: webAuthnValidatorAbi,
            functionName: 'webAuthnValidatorStorage',
            args: [account],
        }),
    ]);

    return {
        deployed: true,
        rootValidator,
        ecdsaOwner: ecdsaOwner === zeroAddress ? null : ecdsaOwner,
        passkey: x === 0n ? null : { x, y },
    };
};

export const describeValidator = (vId: Hex | null): string => {
    if (!vId) return '—';
    const address = `0x${vId.slice(4)}`.toLowerCase();
    if (address === WEBAUTHN_VALIDATOR.toLowerCase()) return `WebAuthn (${vId})`;
    if (address === ECDSA_VALIDATOR.toLowerCase()) return `ECDSA (${vId})`;
    return vId;
};

/**
 * Kernel's installModule takes the hook address, then the ABI-encoded
 * validator data, hook data and selector data. Hook zero means no hook.
 */
const validatorInitData = (validatorData: Hex, selector: Hex): Hex =>
    concatHex([
        zeroAddress,
        encodeAbiParameters(
            [{ type: 'bytes' }, { type: 'bytes' }, { type: 'bytes' }],
            [validatorData, '0x', selector],
        ),
    ]);

/**
 * A validator other than the root may only call the selectors it was installed
 * with. `execute` is enough for the EOA to reach everything else, because the
 * Smart account may always call itself.
 */
export const buildInstallEcdsaCalls = (account: Address, owner: Address): Call[] => [
    {
        to: account,
        value: 0n,
        data: encodeFunctionData({
            abi: kernelAbi,
            functionName: 'installModule',
            args: [MODULE_TYPE_VALIDATOR, ECDSA_VALIDATOR, validatorInitData(owner, toFunctionSelector('execute(bytes32,bytes)'))],
        }),
    },
];

export const webAuthnValidatorData = (credential: PasskeyCredential): Hex => {
    const { x, y } = publicKeyXY(credential.publicKey);
    return encodeAbiParameters(
        [
            { type: 'tuple', components: [{ type: 'uint256' }, { type: 'uint256' }] },
            { type: 'bytes32' },
        ],
        [[x, y], keccak256(toHex(base64UrlToBytes(credential.id)))],
    );
};

/**
 * The WebAuthn validator holds one key per Smart account and refuses a second
 * install, and Kernel refuses to uninstall the root validator. So the EOA
 * becomes root for the length of the batch: WebAuthn is uninstalled, installed
 * again with the new key, and made root again.
 *
 * installModule, not changeRootValidator, reinstalls it: the uninstalled
 * validator keeps its config nonce, which equals Kernel's current nonce, and
 * changeRootValidator's install reverts with InvalidNonce on that.
 */
export const buildReplacePasskeyCalls = (
    account: Address,
    credential: PasskeyCredential,
): Call[] =>
    [
        encodeFunctionData({
            abi: kernelAbi,
            functionName: 'changeRootValidator',
            args: [validationId(ECDSA_VALIDATOR), zeroAddress, '0x', '0x'],
        }),
        encodeFunctionData({
            abi: kernelAbi,
            functionName: 'uninstallValidation',
            args: [validationId(WEBAUTHN_VALIDATOR), '0x', '0x'],
        }),
        encodeFunctionData({
            abi: kernelAbi,
            functionName: 'installModule',
            args: [
                MODULE_TYPE_VALIDATOR,
                WEBAUTHN_VALIDATOR,
                validatorInitData(webAuthnValidatorData(credential), '0x'),
            ],
        }),
        encodeFunctionData({
            abi: kernelAbi,
            functionName: 'changeRootValidator',
            args: [validationId(WEBAUTHN_VALIDATOR), zeroAddress, '0x', '0x'],
        }),
    ].map((data) => ({ to: account, value: 0n, data }));

const passkeyAccount = (
    publicClient: PublicClient,
    address: Address,
    credential: PasskeyCredential,
    rpId: string,
) =>
    toKernelSmartAccount({
        client: publicClient,
        entryPoint,
        address,
        owners: [toWebAuthnAccount({ credential, rpId })],
        version: CURRENT_VERSION.kernelVersion,
        validatorAddress: WEBAUTHN_VALIDATOR,
    });

/**
 * permissionless signs only with the root validator, so the EOA account keeps
 * its call encoding and swaps the nonce key for one that names the ECDSA
 * validator in plain validator mode.
 */
export const eoaAccount = async (
    publicClient: PublicClient,
    address: Address,
    privateKey: Hex,
) => {
    const owner = privateKeyToAccount(privateKey);
    const account = await toKernelSmartAccount({
        client: publicClient,
        entryPoint,
        address,
        owners: [owner],
        version: CURRENT_VERSION.kernelVersion,
        validatorAddress: ECDSA_VALIDATOR,
    });

    const nonceKey = BigInt(concatHex(['0x00', '0x01', ECDSA_VALIDATOR, '0x0000']));

    account.getNonce = async () =>
        publicClient.readContract({
            address: entryPoint.address,
            abi: parseAbi(['function getNonce(address sender, uint192 key) view returns (uint256)']),
            functionName: 'getNonce',
            args: [address, nonceKey],
        });

    account.getFactoryArgs = async () => ({ factory: undefined, factoryData: undefined });

    account.signUserOperation = async ({ chainId, ...userOperation }) =>
        owner.signMessage({
            message: {
                raw: getUserOperationHash({
                    userOperation: { ...userOperation, sender: address, signature: '0x' },
                    entryPointAddress: entryPoint.address,
                    entryPointVersion: entryPoint.version,
                    chainId: chainId ?? publicClient.chain!.id,
                }),
            },
        });

    return account;
};

export type Signer =
    | { kind: 'passkey'; credential: PasskeyCredential; rpId: string }
    | { kind: 'eoa'; privateKey: Hex };

export interface SendResult {
    readonly userOpHash: Hex;
    readonly txHash: Hex;
    readonly success: boolean;
}

export const sendCalls = async ({
    recoveryChain,
    address,
    signer,
    calls,
    bundlerOverride,
    onStatus,
}: {
    recoveryChain: RecoveryChain;
    address: Address;
    signer: Signer;
    calls: Call[];
    bundlerOverride?: string;
    onStatus: (status: string) => void;
}): Promise<SendResult> => {
    const publicClient = createRecoveryPublicClient(recoveryChain);
    const account =
        signer.kind === 'passkey'
            ? await passkeyAccount(publicClient, address, signer.credential, signer.rpId)
            : await eoaAccount(publicClient, address, signer.privateKey);

    const client = createVersionedKernelClient({
        account: account as Awaited<ReturnType<typeof passkeyAccount>>,
        recoveryChain,
        publicClient,
        bundlerOverride,
    });

    onStatus(signer.kind === 'passkey' ? 'Sign with the passkey' : 'Signing with the EOA');
    const userOpHash = await client.sendUserOperation({ calls });

    onStatus('Submitted, waiting for inclusion');
    const receipt = await client.waitForUserOperationReceipt({ hash: userOpHash });

    return {
        userOpHash,
        txHash: receipt.receipt.transactionHash,
        success: receipt.success,
    };
};

/**
 * The COSE_Key an authenticator reports for an ES256 credential:
 * {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
 */
export const coseKeyHex = (publicKey: Hex): string => {
    const { x, y } = publicKeyXY(publicKey);
    return concatHex([
        '0xa5010203262001215820',
        toHex(x, { size: 32 }),
        '0x225820',
        toHex(y, { size: 32 }),
    ]).slice(2);
};

export const authenticatorUpdateSql = ({
    userId,
    credential,
    transports,
}: {
    userId: string;
    credential: PasskeyCredential;
    transports: readonly string[];
}): string =>
    [
        'UPDATE authenticators SET',
        `  credential_id = '${credential.id}',`,
        `  credential_public_key = decode('${coseKeyHex(credential.publicKey)}', 'hex'),`,
        '  counter = 0,',
        `  transports = ${transports.length ? `'${transports.join(',')}'` : 'NULL'},`,
        '  updated_at = now()',
        `WHERE user_id = ${userId || '<user id>'};`,
    ].join('\n');
