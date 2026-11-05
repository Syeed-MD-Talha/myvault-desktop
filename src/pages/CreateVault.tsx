import { useState } from "react";
import { ArrowLeft, FolderSearch, ShieldAlert } from "lucide-react";
import { api, CommandError } from "../services/api";
import { pickNewVaultLocation } from "../services/dialogs";
import { Alert, Button, Field, Spinner, TextInput } from "../components/ui";
import type { OpenedSummary } from "../types";

const MIN_LENGTH = 10;

function passwordScore(password: string): number {
  let score = 0;
  if (password.length >= MIN_LENGTH) score += 1;
  if (password.length >= 16) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return Math.min(score, 5);
}

export function CreateVault({
  onCancel,
  onCreated,
}: {
  onCancel: () => void;
  onCreated: (summary: OpenedSummary) => void;
}) {
  const [name, setName] = useState("Personal");
  const [location, setLocation] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const score = passwordScore(password);
  const mismatch = confirm.length > 0 && confirm !== password;
  const canSubmit =
    !busy &&
    acknowledged &&
    name.trim().length > 0 &&
    location.trim().length > 0 &&
    password.length >= MIN_LENGTH &&
    password === confirm;

  const browse = async () => {
    setError(null);
    try {
      const path = await pickNewVaultLocation(name);
      if (path) setLocation(path.endsWith(".vault") ? path : `${path}.vault`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not open the file dialog.");
    }
  };

  const submit = async () => {
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const summary = await api.createVault(location.trim(), password);
      setPassword("");
      setConfirm("");
      onCreated(summary);
    } catch (e) {
      setError(
        e instanceof CommandError ? e.message : "The vault could not be created.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto flex min-h-full w-full max-w-2xl flex-col justify-center p-8">
      <button
        type="button"
        className="mb-4 inline-flex w-fit items-center gap-1.5 text-sm text-muted hover:text-ink"
        onClick={onCancel}
      >
        <ArrowLeft className="h-4 w-4" /> Back
      </button>

      <div className="card p-6">
        <h1 className="font-display text-xl font-semibold">Create a new vault</h1>
        <p className="mt-1 text-sm text-muted">
          The container is a single file. Keep it on a drive you trust and back
          it up regularly.
        </p>

        <div className="mt-5 space-y-4">
          <Field label="Vault name" htmlFor="vault-name">
            <TextInput
              id="vault-name"
              value={name}
              onChange={setName}
              placeholder="Personal"
              maxLength={64}
            />
          </Field>

          <Field
            label="Storage location"
            htmlFor="vault-location"
            hint="The .vault file must not already exist."
          >
            <div className="flex gap-2">
              <TextInput
                id="vault-location"
                value={location}
                onChange={setLocation}
                placeholder="D:\Private\Personal.vault"
                spellCheck={false}
              />
              <Button
                variant="default"
                icon={<FolderSearch className="h-4 w-4" />}
                onClick={browse}
                disabled={busy}
              >
                Browse
              </Button>
            </div>
          </Field>

          <Field
            label="Master password"
            htmlFor="vault-password"
            hint="Use a passphrase of several words. Longer is stronger."
            error={
              password.length > 0 && password.length < MIN_LENGTH
                ? `Use at least ${MIN_LENGTH} characters.`
                : null
            }
          >
            <TextInput
              id="vault-password"
              type="password"
              value={password}
              onChange={setPassword}
              autoComplete="new-password"
              placeholder="Enter a strong passphrase"
            />
          </Field>

          <div aria-hidden className="flex gap-1">
            {Array.from({ length: 5 }).map((_, index) => (
              <span
                key={index}
                className={`h-1.5 flex-1 rounded-full ${
                  index < score
                    ? score >= 4
                      ? "bg-success"
                      : score >= 3
                        ? "bg-amber-400"
                        : "bg-danger"
                    : "bg-line"
                }`}
              />
            ))}
          </div>

          <Field
            label="Confirm password"
            htmlFor="vault-confirm"
            error={mismatch ? "The passwords do not match." : null}
          >
            <TextInput
              id="vault-confirm"
              type="password"
              value={confirm}
              onChange={setConfirm}
              autoComplete="new-password"
            />
          </Field>

          <Alert tone="warning" title="There is no password recovery">
            MyVault does not store the password and has no backdoor or reset
            option. If you forget it, the encrypted files are permanently
            inaccessible. Keep a backup of the container and a safe record of the
            passphrase.
          </Alert>

          <label className="flex items-start gap-2.5 text-sm">
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 rounded border-line"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
            />
            <span className="text-muted">
              I understand that losing the master password means losing the data.
            </span>
          </label>

          {error ? (
            <Alert tone="danger" title="Could not create the vault">
              {error}
            </Alert>
          ) : null}

          <div className="flex items-center justify-between gap-3 pt-1">
            <span className="flex items-center gap-1.5 text-xs text-muted">
              <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
              Argon2id + XChaCha20-Poly1305
            </span>
            <div className="flex gap-2">
              <Button onClick={onCancel} disabled={busy}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={submit}
                disabled={!canSubmit}
                icon={busy ? <Spinner /> : undefined}
              >
                {busy ? "Creating..." : "Create Vault"}
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
