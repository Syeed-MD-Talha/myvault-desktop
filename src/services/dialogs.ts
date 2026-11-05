import { open, save } from "@tauri-apps/plugin-dialog";

const VAULT_FILTER = [{ name: "MyVault container", extensions: ["vault"] }];

export async function pickNewVaultLocation(defaultName: string): Promise<string | null> {
  const clean = defaultName.trim() || "Personal";
  const path = await save({
    title: "Choose where to store the encrypted vault",
    defaultPath: `${clean}.vault`,
    filters: VAULT_FILTER,
  });
  return path ?? null;
}

export async function pickExistingVault(): Promise<string | null> {
  const path = await open({
    title: "Open an existing MyVault container",
    multiple: false,
    directory: false,
    filters: VAULT_FILTER,
  });
  return typeof path === "string" ? path : null;
}

export async function pickFilesToImport(): Promise<string[]> {
  const selection = await open({
    title: "Select files to encrypt",
    multiple: true,
    directory: false,
  });
  if (!selection) return [];
  return Array.isArray(selection) ? selection : [selection];
}

export async function pickFolderToImport(): Promise<string | null> {
  const selection = await open({
    title: "Select a folder to encrypt (its structure is preserved)",
    multiple: false,
    directory: true,
  });
  return typeof selection === "string" ? selection : null;
}

export async function pickExportDestination(): Promise<string | null> {
  const selection = await open({
    title: "Choose a destination folder",
    multiple: false,
    directory: true,
  });
  return typeof selection === "string" ? selection : null;
}

export async function pickBackupLocation(defaultName: string): Promise<string | null> {
  const path = await save({
    title: "Save an encrypted backup copy",
    defaultPath: `${defaultName}-backup.vault`,
    filters: [{ name: "MyVault container", extensions: ["vault"] }],
  });
  return path ?? null;
}
