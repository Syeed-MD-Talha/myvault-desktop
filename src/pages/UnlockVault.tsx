import { useEffect, useRef, useState } from "react";
import { ArrowLeft, KeyRound, LockKeyhole, Unlock } from "lucide-react";
import { api, CommandError } from "../services/api";
import { Alert, Button, Field, Spinner, TextInput } from "../components/ui";
import type { UnlockResult } from "../types";

export function UnlockVault({
  vaultName,
  vaultPath,
  onUnlocked,
  onBack,
}: {
  vaultName: string;
  vaultPath: string;
  onUnlocked: (result: UnlockResult) => void;
  onBack: () => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    input.current?.focus();
  }, []);

  const submit = async () => {
    if (busy || password.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.unlockVault(password);
      // Clear the password as soon as the backend has processed it.
      setPassword("");
      onUnlocked(result);
    } catch (e) {
      // Generic message: never reveal whether the password or the data failed.
      setError(
        e instanceof CommandError && e.code === "invalid_password"
          ? "The master password is incorrect."
          : e instanceof CommandError
            ? e.message
            : "The vault could not be unlocked.",
      );
      setPassword("");
      input.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-full items-center justify-center p-8">
      <div className="w-full max-w-sm">
        <button
          type="button"
          className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink"
          onClick={onBack}
          disabled={busy}
        >
          <ArrowLeft className="h-4 w-4" /> Back
        </button>

        <div className="card p-6 text-center">
          <div className="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-2xl bg-accent/15 text-accent">
            <LockKeyhole className="h-7 w-7" aria-hidden />
          </div>
          <h1 className="font-display text-lg font-semibold">{vaultName}</h1>
          <p
            className="mx-auto mt-1 max-w-[22rem] truncate text-xs text-muted"
            title={vaultPath}
          >
            {vaultPath}
          </p>

          <form
            className="mt-5 space-y-3 text-left"
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <Field label="Master password" htmlFor="unlock-password">
              <TextInput
                id="unlock-password"
                ref={input}
                type="password"
                value={password}
                onChange={setPassword}
                autoComplete="off"
                autoFocus
                disabled={busy}
                placeholder="Enter your master password"
              />
            </Field>

            {error ? (
              <Alert tone="danger" title="Unlock failed">
                {error}
              </Alert>
            ) : null}

            <Button
              variant="primary"
              className="w-full"
              onClick={submit}
              disabled={busy || password.length === 0}
              icon={busy ? <Spinner /> : <Unlock className="h-4 w-4" />}
            >
              {busy ? "Deriving key..." : "Unlock"}
            </Button>
          </form>

          <p className="mt-4 flex items-center justify-center gap-1.5 text-[11px] text-muted">
            <KeyRound className="h-3.5 w-3.5" aria-hidden />
            Nothing is decrypted until authentication succeeds.
          </p>
        </div>
      </div>
    </div>
  );
}
