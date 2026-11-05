import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import type {
  AppInfo,
  AppSettings,
  Crumb,
  DeleteReport,
  EntryView,
  ExportReport,
  ImportReport,
  IntegrityReport,
  OpenedSummary,
  OpenEntryResult,
  Progress,
  UnlockResult,
  VaultInfo,
} from "../types";

/** Structured error returned by every command. */
export class CommandError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "CommandError";
    this.code = code;
  }
}

function isVaultErrorPayload(value: unknown): value is { code: string; message: string } {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { code?: unknown }).code === "string" &&
    typeof (value as { message?: unknown }).message === "string"
  );
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    if (isVaultErrorPayload(error)) {
      throw new CommandError(error.code, error.message);
    }
    throw new CommandError(
      "unexpected_error",
      typeof error === "string" ? error : "The operation failed unexpectedly.",
    );
  }
}

export const api = {
  appInfo: () => call<AppInfo>("app_info"),

  createVault: (path: string, password: string) =>
    call<OpenedSummary>("create_vault", { path, password }),

  openVault: (path: string) => call<OpenedSummary>("open_vault", { path }),

  unlockVault: (password: string) => call<UnlockResult>("unlock_vault", { password }),

  lockVault: () => call<void>("lock_vault"),

  vaultInfo: () => call<VaultInfo>("vault_info"),

  changePassword: (currentPassword: string, newPassword: string) =>
    call<void>("change_password", { currentPassword, newPassword }),

  verifyIntegrity: () => call<IntegrityReport>("verify_vault_integrity"),

  backupVault: (destinationPath: string) =>
    call<string>("backup_vault", { destinationPath }),

  listDirectory: (directoryId: string | null) =>
    call<EntryView[]>("list_directory", { directoryId }),

  listDirectories: () => call<EntryView[]>("list_directories"),

  breadcrumbs: (id: string) => call<Crumb[]>("breadcrumbs", { id }),

  search: (query: string) => call<EntryView[]>("search_entries", { query }),

  createDirectory: (parentId: string, name: string) =>
    call<EntryView>("create_directory", { parentId, name }),

  renameEntry: (id: string, newName: string) =>
    call<EntryView>("rename_entry", { id, newName }),

  deleteEntry: (id: string) => call<DeleteReport>("delete_entry", { id }),

  moveEntry: (id: string, destinationId: string) =>
    call<EntryView>("move_entry", { id, destinationId }),

  importFiles: (paths: string[], destinationId: string, renameOnConflict = true) =>
    call<ImportReport>("import_files", { paths, destinationId, renameOnConflict }),

  exportEntries: (ids: string[], destinationPath: string, overwrite = false) =>
    call<ExportReport>("export_entries", { ids, destinationPath, overwrite }),

  openEntry: (id: string) => call<OpenEntryResult>("open_entry", { id }),

  cancelOperation: () => call<void>("cancel_operation"),

  getSettings: () => call<AppSettings>("get_settings"),

  saveSettings: (settings: AppSettings) =>
    call<AppSettings>("save_settings", { settings }),
};

/** Progress events from the Rust backend for long-running operations. */
export function onProgress(handler: (progress: Progress) => void): Promise<UnlistenFn> {
  return listen<Progress>("vault://progress", (event) => handler(event.payload));
}

/** Native drag-and-drop of physical files onto the window. */
export function onFileDrop(handler: (paths: string[]) => void): Promise<UnlistenFn> {
  return getCurrentWebview().onDragDropEvent((event) => {
    if (event.payload.type === "drop") {
      handler(event.payload.paths);
    }
  });
}
