import { ArrowLeft, Cpu, LockKeyhole, ShieldAlert, WifiOff } from "lucide-react";
import { formatBytes } from "../components/ui";
import type { AppInfo } from "../types";

const LIMITATIONS = [
  "Malware that runs with your permissions while the vault is unlocked.",
  "An administrator who can inspect the application's process memory.",
  "AI agents or other software reading files after you export them.",
  "Keyloggers that capture the master password as you type it.",
  "Destruction or corruption of the container by a process with write access.",
];

export function About({ appInfo, onBack }: { appInfo: AppInfo | null; onBack: () => void }) {
  return (
    <div className="mx-auto w-full max-w-3xl p-8">
      <button
        type="button"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink"
        onClick={onBack}
      >
        <ArrowLeft className="h-4 w-4" /> Back
      </button>

      <div className="flex items-start gap-4">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-accent/15 text-accent">
          <LockKeyhole className="h-7 w-7" aria-hidden />
        </div>
        <div>
          <h1 className="font-display text-2xl font-semibold">MyVault</h1>
          <p className="text-sm text-muted">
            Version {appInfo?.version ?? "1.0.0"} - offline encrypted vault for
            Windows
          </p>
        </div>
      </div>

      <section className="card mt-6 p-5">
        <h2 className="font-display text-sm font-semibold">Cryptography</h2>
        <dl className="mt-3 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
          <Row label="Password key derivation" value={appInfo?.kdf ?? "argon2id, 64 MiB, 3 iterations"} />
          <Row label="Authenticated encryption" value="XChaCha20-Poly1305 (24-byte random nonce)" />
          <Row label="Key wrapping" value="KEK wraps a random 256-bit vault master key" />
          <Row label="Subkeys" value="HKDF-SHA256 per purpose (file / manifest)" />
          <Row label="Container format" value={`v${appInfo?.formatVersion ?? 1}`} />
          <Row label="Chunk size" value={formatBytes(appInfo?.chunkSize ?? 1048576)} />
          <Row label="Storage engine" value="SQLite (ciphertext, nonces and the header only)" />
          <Row label="Key handling" value="secrecy + zeroize; keys never leave Rust" />
        </dl>
      </section>

      <section className="card mt-4 p-5">
        <h2 className="flex items-center gap-2 font-display text-sm font-semibold">
          <ShieldAlert className="h-4 w-4 text-amber-500" aria-hidden />
          What MyVault does protect
        </h2>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
          <li>File contents, names, folder structure and timestamps at rest.</li>
          <li>
            Everything stays encrypted while the vault is locked, including from
            tools that open the container file directly.
          </li>
          <li>The master password is never stored and cannot be recovered.</li>
        </ul>

        <h2 className="mt-5 flex items-center gap-2 font-display text-sm font-semibold">
          <ShieldAlert className="h-4 w-4 text-danger" aria-hidden />
          What it does not protect against
        </h2>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
          {LIMITATIONS.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-muted">
          Opening a file writes a decrypted copy to
          %LOCALAPPDATA%\MyVault\open so Windows can start the default
          application. That copy is deleted when you lock the vault or close
          MyVault, but other programs can read it while it exists, and a crash or
          another application's temporary files can keep a copy.
        </p>
        <p className="mt-2 text-xs text-muted">
          Exported files are plaintext copies. Windows indexing, backups, cloud
          sync and SSD wear levelling can retain copies that ordinary deletion
          does not remove.
        </p>
      </section>

      <section className="card mt-4 flex flex-col gap-3 p-5 text-sm sm:flex-row sm:items-center">
        <div className="flex flex-1 items-center gap-2">
          <WifiOff className="h-4 w-4 text-success" aria-hidden />
          <span>
            Fully offline: no network requests, no accounts, no telemetry.
          </span>
        </div>
        <div className="flex items-center gap-2 text-muted">
          <Cpu className="h-4 w-4" aria-hidden />
          <span>
            {appInfo?.platform === "windows" ? "Windows 11" : appInfo?.platform ?? "desktop"} build
          </span>
        </div>
      </section>

      <p className="mt-5 text-center text-xs text-muted">
        MyVault is an offline tool. Security and recoverability take priority over
        visual polish and extra features.
      </p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-muted">{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}
