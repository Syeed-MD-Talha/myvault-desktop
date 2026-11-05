export interface EntryView {
  id: string;
  parentId: string;
  name: string;
  kind: "file" | "directory";
  size: number;
  createdMs: number;
  modifiedMs: number;
  chunkCount: number;
  path: string;
}

export interface Crumb {
  id: string;
  name: string;
}

export interface VaultInfo {
  path: string;
  name: string;
  vaultId: string;
  rootId: string;
  formatVersion: number;
  createdMs: number;
  entries: number;
  files: number;
  directories: number;
  chunks: number;
  storedBytes: number;
  plaintextBytes: number;
  chunkSize: number;
  kdf: string;
}

export interface UnlockResult {
  unlockMs: number;
  info: VaultInfo;
}

export interface OpenedSummary {
  path: string;
  name: string;
  formatVersion: number;
}

export interface ImportReport {
  importedFiles: number;
  importedDirectories: number;
  importedBytes: number;
  skipped: string[];
  renamed: string[];
}

export interface ExportReport {
  exportedFiles: number;
  exportedDirectories: number;
  exportedBytes: number;
  destination: string;
}

export interface DeleteReport {
  deletedEntries: number;
  deletedChunks: number;
}export interface IntegrityReport {
  ok: boolean;
  entriesChecked: number;
  chunksChecked: number;
  bytesChecked: number;
  orphanChunks: number;
  issues: string[];
}

export interface OpenEntryResult {
  path: string;
  name: string;
  temporaryRoot: string;
  warnings: string[];
}

export interface Progress {
  phase: "import" | "export" | "verify";
  current: number;
  total: number;
  item: string;
}

export interface AppInfo {
  version: string;
  formatVersion: number;
  platform: string;
  chunkSize: number;
  kdf: string;
}

export type ThemeMode = "system" | "light" | "dark";

export interface AppSettings {
  theme: ThemeMode;
  autoLockMinutes: number;
  confirmDelete: boolean;
}

export type Screen =
  | "welcome"
  | "create"
  | "unlock"
  | "files"
  | "settings"
  | "about";
