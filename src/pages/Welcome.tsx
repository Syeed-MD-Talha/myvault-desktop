import {
  FolderPlus,
  FolderOpen,
  Info,
  LockKeyhole,
  Settings as SettingsIcon,
  ShieldCheck,
} from "lucide-react";
import type { Screen } from "../types";
import { Button } from "../components/ui";

export function Welcome({
  version,
  onNavigate,
  onOpenVault,
}: {
  version: string;
  onNavigate: (screen: Screen) => void;
  onOpenVault: () => void;
}) {
  return (
    <div className="flex min-h-full items-center justify-center p-8">
      <div className="w-full max-w-xl">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-accent/15 text-accent">
            <LockKeyhole className="h-8 w-8" aria-hidden />
          </div>
          <h1 className="font-display text-3xl font-semibold tracking-tight">
            MyVault
          </h1>
          <p className="mt-2 max-w-md text-sm text-muted">
            An offline encrypted container for your sensitive files. Everything
            stays on this computer and is protected by a master password that
            MyVault never stores.
          </p>
        </div>

        <div className="card divide-y divide-line overflow-hidden">
          <Action
            icon={<FolderPlus className="h-5 w-5" />}
            title="Create New Vault"
            description="Choose a location and a master password."
            onClick={() => onNavigate("create")}
            primary
          />
          <Action
            icon={<FolderOpen className="h-5 w-5" />}
            title="Open Existing Vault"
            description="Select a .vault container to unlock."
            onClick={onOpenVault}
          />
          <Action
            icon={<SettingsIcon className="h-5 w-5" />}
            title="Settings"
            description="Theme, automatic locking, and integrity checks."
            onClick={() => onNavigate("settings")}
          />
          <Action
            icon={<Info className="h-5 w-5" />}
            title="About"
            description={`MyVault ${version} - security boundaries and format.`}
            onClick={() => onNavigate("about")}
          />
        </div>

        <div className="mt-6 flex items-start gap-2 rounded-lg border border-line bg-surface/70 px-3.5 py-3 text-xs text-muted">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
          <p>
            Works entirely offline. No account, no cloud, no telemetry. If you
            forget the master password, the data cannot be recovered.
          </p>
        </div>
      </div>
    </div>
  );
}

function Action({
  icon,
  title,
  description,
  onClick,
  primary = false,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  onClick: () => void;
  primary?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-center gap-4 px-5 py-4 text-left transition-colors hover:bg-elevated"
    >
      <span
        className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${
          primary ? "bg-accent text-white dark:text-slate-900" : "bg-elevated text-accent"
        }`}
      >
        {icon}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block font-medium">{title}</span>
        <span className="block text-xs text-muted">{description}</span>
      </span>
      <Button variant="ghost" size="sm" tabIndex={-1} aria-hidden>
        Open
      </Button>
    </button>
  );
}
