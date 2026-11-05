import { useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Database,
  HardDriveDownload,
  KeyRound,
  Monitor,
  MoonStar,
  ShieldCheck,
  Sun,
} from "lucide-react";
import { api, CommandError, onProgress } from "../services/api";
import { pickBackupLocation } from "../services/dialogs";
import {
  Alert,
  Button,
  Field,
  formatBytes,
  formatDate,
  ProgressBar,
  Spinner,
  TextInput,
} from "../components/ui";
import type { AppSettings, IntegrityReport, ThemeMode, VaultInfo } from "../types";

const THEMES: { value: ThemeMode; label: string; icon: React.ReactNode }[] = [
  { value: "system", label: "System", icon: <Monitor className="h-4 w-4" /> },
  { value: "light", label: "Light", icon: <Sun className="h-4 w-4" /> },
  { value: "dark", label: "Dark", icon: <MoonStar className="h-4 w-4" /> },
];

const AUTO_LOCK_OPTIONS = [0, 1, 5, 10, 15, 30];

export function SettingsPage({
  info,
  settings,
  onSettingsChange,
  onBack,
}: {
  info: VaultInfo | null;
  settings: AppSettings;
  onSettingsChange: (settings: AppSettings) => void;
  onBack: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState<{
    tone: "success" | "danger";
    text: string;
  } | null>(null);

  const [verifyBusy, setVerifyBusy] = useState(false);
  const [verifyProgress, setVerifyProgress] = useState(0);
  const [report, setReport] = useState<IntegrityReport | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupMessage, setBackupMessage] = useState<{
    tone: "success" | "danger";
    text: string;
  } | null>(null);

  const update = async (patch: Partial<AppSettings>) => {
    const merged = { ...settings, ...patch };
    onSettingsChange(merged);
    try {
      const saved = await api.saveSettings(merged);
      onSettingsChange(saved);
    } catch {
      /* settings are non-critical; keep the in-memory value */
    }
  };

  const changePassword = async () => {
    if (!info || next.length < 10 || next !== confirm) return;
    setPasswordBusy(true);
    setPasswordMessage(null);
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setPasswordMessage({
        tone: "success",
        text: "The master password was changed. Only the key envelope was rewritten; no file data was re-encrypted.",
      });
    } catch (e) {
      setPasswordMessage({
        tone: "danger",
        text:
          e instanceof CommandError
            ? e.message
            : "The password could not be changed.",
      });
    } finally {
      setPasswordBusy(false);
    }
  };

  const backup = async () => {
    if (!info) return;
    const destination = await pickBackupLocation(info.name);
    if (!destination) return;
    setBackupBusy(true);
    setBackupMessage(null);
    try {
      const saved = await api.backupVault(destination);
      setBackupMessage({
        tone: "success",
        text: `Encrypted backup written to ${saved}. It is protected by the same master password.`,
      });
    } catch (e) {
      setBackupMessage({
        tone: "danger",
        text:
          e instanceof CommandError ? e.message : "The backup could not be written.",
      });
    } finally {
      setBackupBusy(false);
    }
  };

  const verify = async () => {
    setVerifyBusy(true);
    setVerifyError(null);
    setReport(null);
    setVerifyProgress(0);
    let stop: (() => void) | undefined;
    try {
      const unlisten = await onProgress((progress) => {
        if (progress.total > 0) {
          setVerifyProgress((progress.current / progress.total) * 100);
        }
      });
      stop = unlisten;
      setReport(await api.verifyIntegrity());
    } catch (e) {
      setVerifyError(
        e instanceof CommandError ? e.message : "The verification failed.",
      );
    } finally {
      stop?.();
      setVerifyBusy(false);
    }
  };

  return (
    <div className="mx-auto w-full max-w-3xl p-8">
      <button
        type="button"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink"
        onClick={onBack}
      >
        <ArrowLeft className="h-4 w-4" /> Back
      </button>

      <h1 className="font-display text-2xl font-semibold">Settings</h1>
      <p className="mt-1 text-sm text-muted">
        Preferences are stored outside the vault and contain no file data.
      </p>

      <section className="card mt-5 p-5">
        <h2 className="font-display text-sm font-semibold">Appearance</h2>
        <div className="mt-3 flex gap-2">
          {THEMES.map((theme) => (
            <button
              key={theme.value}
              type="button"
              onClick={() => void update({ theme: theme.value })}
              className={`flex flex-1 items-center justify-center gap-2 rounded-lg border px-3 py-2 text-sm transition ${
                settings.theme === theme.value
                  ? "border-accent bg-accent/10 font-medium"
                  : "border-line hover:bg-elevated"
              }`}
              aria-pressed={settings.theme === theme.value}
            >
              {theme.icon}
              {theme.label}
            </button>
          ))}
        </div>
      </section>

      <section className="card mt-4 p-5">
        <h2 className="font-display text-sm font-semibold">Automatic locking</h2>
        <p className="mt-1 text-xs text-muted">
          Inactivity means no interaction with MyVault, not with Windows.
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          {AUTO_LOCK_OPTIONS.map((minutes) => (
            <button
              key={minutes}
              type="button"
              onClick={() => void update({ autoLockMinutes: minutes })}
              className={`rounded-lg border px-3 py-1.5 text-sm transition ${
                settings.autoLockMinutes === minutes
                  ? "border-accent bg-accent/10 font-medium"
                  : "border-line hover:bg-elevated"
              }`}
              aria-pressed={settings.autoLockMinutes === minutes}
            >
              {minutes === 0 ? "Off" : `${minutes} min`}
            </button>
          ))}
        </div>
      </section>

      <section className="card mt-4 p-5">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-accent" aria-hidden />
          <h2 className="font-display text-sm font-semibold">Master password</h2>
        </div>
        {info ? (
          <>
            <p className="mt-1 text-xs text-muted">
              Changing the password rewraps the vault master key with a new salt.
              Existing files are not re-encrypted.
            </p>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <Field label="Current password" htmlFor="current-password">
                <TextInput
                  id="current-password"
                  type="password"
                  value={current}
                  onChange={setCurrent}
                  autoComplete="off"
                />
              </Field>
              <Field label="New password" htmlFor="new-password">
                <TextInput
                  id="new-password"
                  type="password"
                  value={next}
                  onChange={setNext}
                  autoComplete="new-password"
                />
              </Field>
              <Field
                label="Confirm"
                htmlFor="confirm-password"
                error={
                  confirm.length > 0 && confirm !== next
                    ? "The passwords do not match."
                    : null
                }
              >
                <TextInput
                  id="confirm-password"
                  type="password"
                  value={confirm}
                  onChange={setConfirm}
                  autoComplete="new-password"
                />
              </Field>
            </div>
            <div className="mt-3 flex items-center justify-between gap-3">
              <span className="text-xs text-muted">
                {next.length > 0 && next.length < 10
                  ? "Use at least 10 characters."
                  : ""}
              </span>
              <Button
                variant="primary"
                onClick={() => void changePassword()}
                disabled={
                  passwordBusy ||
                  current.length === 0 ||
                  next.length < 10 ||
                  next !== confirm
                }
                icon={passwordBusy ? <Spinner /> : undefined}
              >
                {passwordBusy ? "Rewrapping key..." : "Change password"}
              </Button>
            </div>
            {passwordMessage ? (
              <div className="mt-3">
                <Alert tone={passwordMessage.tone}>{passwordMessage.text}</Alert>
              </div>
            ) : null}
          </>
        ) : (
          <p className="mt-2 text-sm text-muted">
            Unlock a vault to change its master password.
          </p>
        )}
      </section>

      <section className="card mt-4 p-5">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-accent" aria-hidden />
          <h2 className="font-display text-sm font-semibold">Integrity verification</h2>
        </div>
        <p className="mt-1 text-xs text-muted">
          Verifies the SQLite structure, decrypts the manifest, and authenticates
          every stored chunk. Nothing is repaired automatically.
        </p>
        <div className="mt-3 flex items-center gap-3">
          <Button
            onClick={() => void verify()}
            disabled={!info || verifyBusy}
            icon={verifyBusy ? <Spinner /> : undefined}
          >
            {verifyBusy ? "Verifying..." : "Verify vault"}
          </Button>
          {verifyBusy ? (
            <div className="flex-1">
              <ProgressBar percent={verifyProgress} />
            </div>
          ) : null}
        </div>

        {verifyError ? (
          <div className="mt-3">
            <Alert tone="danger">{verifyError}</Alert>
          </div>
        ) : null}

        {report ? (
          <div className="mt-3 space-y-2">
            <Alert tone={report.ok ? "success" : "danger"}>
              {report.ok
                ? "All checked data authenticated correctly."
                : `${report.issues.length} problem(s) found. Do not modify the container; restore a backup if possible.`}
            </Alert>
            <ul className="space-y-1 text-xs text-muted">
              <li>{report.entriesChecked} entries checked</li>
              <li>{report.chunksChecked} chunks authenticated</li>
              <li>{formatBytes(report.bytesChecked)} of file data verified</li>
              <li>{report.orphanChunks} unreferenced chunk(s)</li>
              {report.issues.map((issue) => (
                <li key={issue} className="text-danger">
                  {issue}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>

      <section className="card mt-4 p-5">
        <div className="flex items-center gap-2">
          <HardDriveDownload className="h-4 w-4 text-accent" aria-hidden />
          <h2 className="font-display text-sm font-semibold">Backup</h2>
        </div>
        <p className="mt-1 text-xs text-muted">
          Writes a transactionally consistent copy of the container. The copy is
          encrypted with the same master password and can be opened on any
          MyVault installation. Restoring is a matter of replacing the container
          file while the vault is locked.
        </p>
        <div className="mt-3 flex items-center gap-3">
          <Button
            onClick={() => void backup()}
            disabled={!info || backupBusy}
            icon={backupBusy ? <Spinner /> : <HardDriveDownload className="h-4 w-4" />}
          >
            {backupBusy ? "Copying..." : "Backup vault..."}
          </Button>
        </div>
        {backupMessage ? (
          <div className="mt-3">
            <Alert tone={backupMessage.tone}>{backupMessage.text}</Alert>
          </div>
        ) : null}
      </section>

      <section className="card mt-4 p-5">
        <div className="flex items-center gap-2">
          <Database className="h-4 w-4 text-accent" aria-hidden />
          <h2 className="font-display text-sm font-semibold">Vault storage</h2>
        </div>
        {info ? (
          <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
            <Stat label="Container" value={info.name} />
            <Stat label="Format version" value={`v${info.formatVersion}`} />
            <Stat label="Created" value={formatDate(info.createdMs)} />
            <Stat label="Entries" value={String(info.entries)} />
            <Stat label="Files" value={String(info.files)} />
            <Stat label="Folders" value={String(info.directories)} />
            <Stat label="Chunks" value={String(info.chunks)} />
            <Stat label="Encrypted size" value={formatBytes(info.storedBytes)} />
            <Stat label="Plaintext size" value={formatBytes(info.plaintextBytes)} />
            <Stat label="Chunk size" value={formatBytes(info.chunkSize)} />
            <Stat label="Key derivation" value={info.kdf} />
            <Stat label="Vault id" value={`${info.vaultId.slice(0, 12)}...`} />
          </dl>
        ) : (
          <p className="mt-2 text-sm text-muted">No vault is unlocked.</p>
        )}
      </section>

      <div className="mt-5 flex items-center gap-2 rounded-lg border border-line bg-surface px-4 py-3 text-xs text-muted">
        <CheckCircle2 className="h-4 w-4 shrink-0 text-success" aria-hidden />
        Theme and auto-lock apply immediately and are remembered on this
        computer.
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-wide text-muted">{label}</dt>
      <dd className="truncate" title={value}>
        {value}
      </dd>
    </div>
  );
}
