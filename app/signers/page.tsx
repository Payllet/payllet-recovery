"use client";

import { useCallback, useEffect, useState } from "react";
import { Address, Hex, isAddress, isHex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createCredential } from "webauthn-p256";

import { deriveVersionAddress, PasskeyCredential } from "../lib/account";
import {
    CURRENT_VERSION,
    getRpId,
    hasBuiltInBundler,
    RECOVERY_CHAINS,
} from "../lib/config";
import {
    authenticatorUpdateSql,
    buildInstallEcdsaCalls,
    buildReplacePasskeyCalls,
    describeValidator,
    publicKeyXY,
    readSignerState,
    sendCalls,
    SendResult,
    Signer,
    SignerState,
} from "../lib/signers";
import { extractCredential } from "../lib/webauthn";

interface NewPasskey {
    readonly credential: PasskeyCredential;
    readonly transports: readonly string[];
}

interface Persisted {
    chainId: number;
    address: string;
    eoaKey: string;
    newPasskey: NewPasskey | null;
    userId: string;
}

type Action =
    | { status: "idle" }
    | { status: "busy"; label: string; message: string }
    | { status: "done"; label: string; result: SendResult }
    | { status: "error"; label: string; message: string };

// The EOA key and the new passkey are the only way back into the Smart
// account once the old passkey is gone, so a reload must not lose them.
const STORAGE_KEY = "payllet-signers-sandbox";

const loadPersisted = (): Partial<Persisted> => {
    try {
        return JSON.parse(window.localStorage.getItem(STORAGE_KEY) || "{}");
    } catch {
        return {};
    }
};

const errorMessage = (err: unknown): string => {
    if (err && typeof err === "object" && "shortMessage" in err) {
        const details = "details" in err ? `\n${String((err as { details: unknown }).details)}` : "";
        return String((err as { shortMessage: unknown }).shortMessage) + details;
    }
    return err instanceof Error ? err.message : String(err);
};

const sameKey = (a: { x: bigint; y: bigint } | null, b: PasskeyCredential | null) => {
    if (!a || !b) return false;
    const { x, y } = publicKeyXY(b.publicKey);
    return a.x === x && a.y === y;
};

const Button = ({
    onClick,
    disabled,
    primary,
    children,
}: {
    onClick: () => void;
    disabled?: boolean;
    primary?: boolean;
    children: React.ReactNode;
}) => (
    <button
        type="button"
        onClick={onClick}
        disabled={disabled}
        className={
            primary
                ? "rounded bg-neutral-900 px-3 py-1.5 text-white disabled:opacity-45"
                : "rounded border px-3 py-1.5 disabled:opacity-45"
        }
    >
        {children}
    </button>
);

export default function Signers() {
    const [rpId, setRpId] = useState("");
    const [chainId, setChainId] = useState(RECOVERY_CHAINS[2].chain.id);
    const [bundlerOverride, setBundlerOverride] = useState("");
    const [address, setAddress] = useState("");
    const [credential, setCredential] = useState<PasskeyCredential | null>(null);
    const [eoaKey, setEoaKey] = useState("");
    const [newPasskey, setNewPasskey] = useState<NewPasskey | null>(null);
    const [newPasskeyName, setNewPasskeyName] = useState("");
    const [userId, setUserId] = useState("");
    const [state, setState] = useState<SignerState | null>(null);
    const [stateError, setStateError] = useState<string | null>(null);
    const [action, setAction] = useState<Action>({ status: "idle" });
    const [hydrated, setHydrated] = useState(false);

    const recoveryChain =
        RECOVERY_CHAINS.find((c) => c.chain.id === chainId) ?? RECOVERY_CHAINS[0];
    const validAddress = isAddress(address) ? (address as Address) : null;
    const validEoaKey = isHex(eoaKey) && eoaKey.length === 66 ? (eoaKey as Hex) : null;
    const eoaAddress = validEoaKey ? privateKeyToAccount(validEoaKey).address : null;
    const busy = action.status === "busy";
    const canSend = hasBuiltInBundler || bundlerOverride.trim().length > 0;

    useEffect(() => {
        setRpId(getRpId());
        const saved = loadPersisted();
        if (saved.chainId) setChainId(saved.chainId);
        if (saved.address) setAddress(saved.address);
        if (saved.eoaKey) setEoaKey(saved.eoaKey);
        if (saved.newPasskey) setNewPasskey(saved.newPasskey);
        if (saved.userId) setUserId(saved.userId);
        setHydrated(true);
    }, []);

    useEffect(() => {
        if (!hydrated) return;
        const persisted: Persisted = { chainId, address, eoaKey, newPasskey, userId };
        try {
            window.localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
        } catch {
            // Private windows may refuse storage; the page still works for one visit.
        }
    }, [hydrated, chainId, address, eoaKey, newPasskey, userId]);

    const refresh = useCallback(async () => {
        if (!validAddress) return;
        setStateError(null);
        try {
            setState(await readSignerState(recoveryChain, validAddress));
        } catch (err) {
            setState(null);
            setStateError(errorMessage(err));
        }
    }, [recoveryChain, validAddress]);

    useEffect(() => {
        setState(null);
        void refresh();
    }, [refresh]);

    const identify = async () => {
        setAction({ status: "idle" });
        try {
            const extracted = await extractCredential(rpId);
            const passkey = { id: extracted.credentialId, publicKey: extracted.publicKey };
            setCredential(passkey);
            if (!validAddress) {
                setAddress(await deriveVersionAddress(CURRENT_VERSION, passkey, 0n, rpId));
            }
        } catch (err) {
            setAction({ status: "error", label: "Identify passkey", message: errorMessage(err) });
        }
    };

    const createNewPasskey = async () => {
        setAction({ status: "idle" });
        try {
            // A random user handle, so the platform keeps the old passkey
            // instead of overwriting the one with the same handle.
            const created = await createCredential({
                rp: { id: rpId, name: "Payllet" },
                user: {
                    id: crypto.getRandomValues(new Uint8Array(16)),
                    name: newPasskeyName.trim() || "Payllet",
                },
            });
            const response = created.raw.response as AuthenticatorAttestationResponse;
            setNewPasskey({
                credential: {
                    id: created.id,
                    publicKey: `0x04${created.publicKey.slice(-128)}` as Hex,
                },
                transports: response.getTransports?.() ?? [],
            });
        } catch (err) {
            const cause = err instanceof Error && err.cause ? `: ${errorMessage(err.cause)}` : "";
            setAction({
                status: "error",
                label: "Create passkey",
                message: errorMessage(err) + cause,
            });
        }
    };

    const run = async (
        label: string,
        signer: Signer,
        calls: Parameters<typeof sendCalls>[0]["calls"],
    ) => {
        if (!validAddress) return;
        setAction({ status: "busy", label, message: "Preparing" });
        try {
            const result = await sendCalls({
                recoveryChain,
                address: validAddress,
                signer,
                calls,
                bundlerOverride,
                onStatus: (message) => setAction({ status: "busy", label, message }),
            });
            setAction({ status: "done", label, result });
        } catch (err) {
            setAction({ status: "error", label, message: errorMessage(err) });
        } finally {
            void refresh();
        }
    };

    const installEoa = () => {
        if (!credential || !validAddress || !eoaAddress) return;
        void run(
            "Attach EOA",
            { kind: "passkey", credential, rpId },
            buildInstallEcdsaCalls(validAddress, eoaAddress),
        );
    };

    const replacePasskey = () => {
        if (!validEoaKey || !validAddress || !newPasskey) return;
        void run(
            "Replace passkey",
            { kind: "eoa", privateKey: validEoaKey },
            buildReplacePasskeyCalls(validAddress, newPasskey.credential),
        );
    };

    const testNewPasskey = () => {
        if (!newPasskey || !validAddress) return;
        void run(
            "Test new passkey",
            { kind: "passkey", credential: newPasskey.credential, rpId },
            [{ to: validAddress, value: 0n, data: "0x" }],
        );
    };

    const explorer = recoveryChain.chain.blockExplorers?.default.url;
    const eoaAttached =
        !!state?.ecdsaOwner &&
        !!eoaAddress &&
        state.ecdsaOwner.toLowerCase() === eoaAddress.toLowerCase();
    const newPasskeyOnChain = sameKey(state?.passkey ?? null, newPasskey?.credential ?? null);

    return (
        <main className="mx-auto max-w-5xl p-6 text-sm text-neutral-900">
            <h1 className="text-xl font-semibold">Signer sandbox</h1>
            <p className="mt-2 max-w-3xl text-neutral-700">
                Attach an EOA to a Smart account as a second signer, drop the passkey,
                and put a new passkey in its place with the EOA. The address does not
                change. Everything happens on one chain: signers are per chain.
            </p>
            <p className="mt-2 text-neutral-600">
                Passkeys for{" "}
                <code className="rounded bg-neutral-100 px-1">{rpId || "…"}</code>.
            </p>

            <section className="mt-6 border-t pt-5">
                <h2 className="font-semibold">Smart account</h2>
                <div className="mt-3 flex flex-wrap items-center gap-3">
                    <select
                        value={chainId}
                        onChange={(e) => setChainId(Number(e.target.value))}
                        className="rounded border px-2 py-1"
                    >
                        {RECOVERY_CHAINS.map(({ chain }) => (
                            <option key={chain.id} value={chain.id}>
                                {chain.name}
                            </option>
                        ))}
                    </select>
                    <input
                        placeholder="Smart account address (0x…)"
                        value={address}
                        onChange={(e) => setAddress(e.target.value.trim())}
                        className="w-[26rem] rounded border px-2 py-1 font-mono text-xs"
                    />
                    <Button onClick={() => void refresh()} disabled={!validAddress}>
                        refresh
                    </Button>
                </div>
                {!hasBuiltInBundler && (
                    <input
                        placeholder="Bundler URL: https://api.pimlico.io/v2/{chainId}/rpc?apikey=…"
                        value={bundlerOverride}
                        onChange={(e) => setBundlerOverride(e.target.value)}
                        className="mt-2 w-full max-w-2xl rounded border px-2 py-1 font-mono text-xs"
                    />
                )}

                {stateError && <p className="mt-3 text-red-600">{stateError}</p>}
                {state && (
                    <dl className="mt-3 grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1 break-all font-mono text-xs">
                        <dt className="text-neutral-500">deployed</dt>
                        <dd>{state.deployed ? "yes" : "no"}</dd>
                        <dt className="text-neutral-500">root validator</dt>
                        <dd>{describeValidator(state.rootValidator)}</dd>
                        <dt className="text-neutral-500">passkey x</dt>
                        <dd>{state.passkey ? `0x${state.passkey.x.toString(16)}` : "—"}</dd>
                        <dt className="text-neutral-500">passkey y</dt>
                        <dd>{state.passkey ? `0x${state.passkey.y.toString(16)}` : "—"}</dd>
                        <dt className="text-neutral-500">EOA signer</dt>
                        <dd>{state.ecdsaOwner ?? "—"}</dd>
                    </dl>
                )}
            </section>

            <section className="mt-6 border-t pt-5">
                <h2 className="font-semibold">1. Attach an EOA</h2>
                <div className="mt-3 flex flex-wrap items-center gap-3">
                    <Button onClick={identify} disabled={busy || !rpId}>
                        {credential ? "Passkey identified" : "Identify current passkey"}
                    </Button>
                    <input
                        placeholder="EOA private key (0x…)"
                        value={eoaKey}
                        onChange={(e) => setEoaKey(e.target.value.trim())}
                        className="w-[34rem] rounded border px-2 py-1 font-mono text-xs"
                    />
                    <Button onClick={() => setEoaKey(generatePrivateKey())} disabled={busy}>
                        generate
                    </Button>
                </div>
                {credential && (
                    <div className="mt-2 break-all font-mono text-xs text-neutral-600">
                        <div>passkey id: {credential.id}</div>
                        <div>
                            on chain:{" "}
                            {sameKey(state?.passkey ?? null, credential)
                                ? "this is the root passkey"
                                : "not the key stored on chain"}
                        </div>
                    </div>
                )}
                {eoaAddress && (
                    <div className="mt-2 break-all font-mono text-xs text-neutral-600">
                        EOA: {eoaAddress} {eoaAttached && "(attached)"}
                    </div>
                )}
                <p className="mt-2 text-neutral-600">
                    The key is kept in this browser&apos;s storage. Copy it somewhere: it is
                    the way back in after step 2.
                </p>
                <div className="mt-3">
                    <Button
                        primary
                        onClick={installEoa}
                        disabled={
                            busy || !canSend || !credential || !validAddress || !eoaAddress || eoaAttached
                        }
                    >
                        Attach EOA (signed with the passkey)
                    </Button>
                </div>
            </section>

            <section className="mt-6 border-t pt-5">
                <h2 className="font-semibold">2. Lose the passkey</h2>
                <p className="mt-2 text-neutral-600">
                    Nothing changes on chain here: Kernel never lets the root validator be
                    removed on its own. The page forgets the passkey and from now on signs
                    only with the EOA.
                </p>
                <div className="mt-3">
                    <Button onClick={() => setCredential(null)} disabled={busy || !credential}>
                        Forget passkey
                    </Button>
                </div>
            </section>

            <section className="mt-6 border-t pt-5">
                <h2 className="font-semibold">3. Replace the passkey with the EOA</h2>
                <div className="mt-3 flex flex-wrap items-center gap-3">
                    <input
                        placeholder="Name for the new passkey"
                        value={newPasskeyName}
                        onChange={(e) => setNewPasskeyName(e.target.value)}
                        className="w-64 rounded border px-2 py-1"
                    />
                    <Button onClick={createNewPasskey} disabled={busy || !rpId}>
                        {newPasskey ? "Create another passkey" : "Create new passkey"}
                    </Button>
                </div>
                {newPasskey && (
                    <div className="mt-2 break-all font-mono text-xs text-neutral-600">
                        <div>id: {newPasskey.credential.id}</div>
                        <div>key: {newPasskey.credential.publicKey}</div>
                        <div>transports: {newPasskey.transports.join(",") || "—"}</div>
                        <div>on chain: {newPasskeyOnChain ? "yes, root" : "not yet"}</div>
                    </div>
                )}
                <div className="mt-3 flex flex-wrap gap-3">
                    <Button
                        primary
                        onClick={replacePasskey}
                        disabled={
                            busy || !canSend || !validAddress || !validEoaKey || !newPasskey || !eoaAttached || newPasskeyOnChain
                        }
                    >
                        Replace passkey (signed with the EOA)
                    </Button>
                    <Button
                        onClick={testNewPasskey}
                        disabled={busy || !canSend || !validAddress || !newPasskeyOnChain}
                    >
                        Test: send an empty operation with the new passkey
                    </Button>
                </div>
            </section>

            <section className="mt-6 border-t pt-5">
                <h2 className="font-semibold">4. Point the API at the new passkey</h2>
                <p className="mt-2 text-neutral-600">
                    Login looks the passkey up in <code>authenticators</code>, one row per
                    User. Run this against the production database once the new passkey is
                    root on chain.
                </p>
                <input
                    placeholder="users.id"
                    value={userId}
                    onChange={(e) => setUserId(e.target.value.trim())}
                    className="mt-3 w-32 rounded border px-2 py-1 font-mono text-xs"
                />
                {newPasskey && (
                    <pre className="mt-3 overflow-x-auto rounded bg-neutral-100 p-3 font-mono text-xs">
                        {authenticatorUpdateSql({
                            userId,
                            credential: newPasskey.credential,
                            transports: newPasskey.transports,
                        })}
                    </pre>
                )}
            </section>

            {action.status !== "idle" && (
                <section className="mt-6 border-t pt-5 font-mono text-xs">
                    <div className="font-semibold">{action.label}</div>
                    {action.status === "busy" && <div className="mt-1">{action.message}…</div>}
                    {action.status === "error" && (
                        <div className="mt-1 whitespace-pre-wrap break-all text-red-600">
                            {action.message}
                        </div>
                    )}
                    {action.status === "done" && (
                        <div className="mt-1 break-all">
                            <div className={action.result.success ? "text-emerald-600" : "text-red-600"}>
                                {action.result.success ? "included, succeeded" : "included, reverted"}
                            </div>
                            <div>userOp: {action.result.userOpHash}</div>
                            <div>
                                tx:{" "}
                                {explorer ? (
                                    <a
                                        className="underline"
                                        href={`${explorer}/tx/${action.result.txHash}`}
                                        target="_blank"
                                        rel="noreferrer"
                                    >
                                        {action.result.txHash}
                                    </a>
                                ) : (
                                    action.result.txHash
                                )}
                            </div>
                        </div>
                    )}
                </section>
            )}
        </main>
    );
}
