import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowUpDown,
  Download,
  ExternalLink,
  File as FileIcon,
  Folder,
  FolderInput,
  FolderPlus,
  HardDrive,
  Lock,
  Pencil,
  Search,
  Settings as SettingsIcon,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { api, CommandError, onFileDrop, onProgress } from "../services/api";
import {
  pickExportDestination,
  pickFilesToImport,
  pickFolderToImport,
} from "../services/dialogs";
import {
  Alert,
  Button,
  describeType,
  Field,
  formatBytes,
  formatDate,
  Modal,
  ProgressBar,
  Spinner,
  TextInput,
} from "../components/ui";
import type { Crumb, EntryView, Progress, VaultInfo } from "../types";
type DialogState =
  | { kind: "new-folder" }
  | { kind: "rename"; entry: EntryView }
  | { kind: "delete"; entries: EntryView[] }
  | { kind: "move"; entries: EntryView[] }
  | null;

export function FileManager({
  info,
  onLock,
  onSettings,
  onInfoChange,
  onLockedNotice,
}: {
  info: VaultInfo;
  onLock: () => void;
  onSettings: () => void;
  onInfoChange: (info: VaultInfo) => void;
  onLockedNotice: (message: string) => void;
}) {
  const [directoryId, setDirectoryId] = useState(info.rootId);
  const [entries, setEntries] = useState<EntryView[]>([]);
  const [crumbs, setCrumbs] = useState<Crumb[]>([]);
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<EntryView[] | null>(null);
  const [dialog, setDialog] = useState<DialogState>(null);
  const [busy, setBusy] = useState<{ label: string } | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [pendingExport, setPendingExport] = useState<{
    ids: string[];
    destination: string;
  } | null>(null);
  const [openTarget, setOpenTarget] = useState<EntryView | null>(null);
  const [openWarnings, setOpenWarnings] = useState<string[] | null>(null);
  const [opening, setOpening] = useState(false);
  const currentId = useRef(directoryId);
  const isBusy = useRef(false);
  const dragDepth = useRef(0);

  currentId.current = directoryId;
  isBusy.current = busy !== null;

  const refreshInfo = useCallback(async () => {
    try {
      onInfoChange(await api.vaultInfo());
    } catch {
      /* the next command will surface a real error */
    }
  }, [onInfoChange]);

  const load = useCallback(
    async (id: string) => {
      setLoading(true);
      try {
        const [list, trail] = await Promise.all([
          api.listDirectory(id),
          api.breadcrumbs(id),
        ]);
        setEntries(list);
        setCrumbs(trail);
        setSelection(new Set());
        setError(null);
      } catch (e) {
        if (e instanceof CommandError && e.code === "vault_locked") {
          onLockedNotice("The vault is locked.");
          return;
        }
        setError(e instanceof Error ? e.message : "Could not read the folder.");
      } finally {
        setLoading(false);
      }
    },
    [onLockedNotice],
  );

  useEffect(() => {
    setDirectoryId(info.rootId);
  }, [info.rootId]);

  useEffect(() => {
    void load(directoryId);
  }, [directoryId, load]);

  useEffect(() => {
    const stop = onProgress(setProgress);
    return () => {
      void stop.then((fn) => fn());
    };
  }, []);

  useEffect(() => {
    const stop = onFileDrop((paths) => {
      if (isBusy.current || paths.length === 0) return;
      void runImport("files", paths);
    });
    return () => {
      void stop.then((fn) => fn());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (query.trim().length === 0) {
      setResults(null);
      return;
    }
    const handle = window.setTimeout(async () => {
      try {
        setResults(await api.search(query));
      } catch {
        setResults([]);
      }
    }, 180);
    return () => window.clearTimeout(handle);
  }, [query]);

  const withError = (e: unknown, fallback: string) => {
    if (e instanceof CommandError) {
      if (e.code === "vault_locked") {
        onLockedNotice("The vault is locked.");
      } else {
        setError(e.message);
      }
    } else {
      setError(fallback);
    }
  };

  const selectedEntries = () =>
    entries.filter((entry) => selection.has(entry.id));

  async function runImport(mode: "files" | "folder", preset?: string[]) {
    if (busy) return;
    const paths =
      preset ??
      (mode === "files" ? await pickFilesToImport() : [await pickFolderToImport()].filter(
        (p): p is string => typeof p === "string",
      ));
    if (paths.length === 0) return;
    setBusy({ label: mode === "files" ? "Encrypting files" : "Encrypting folder" });
    setProgress(null);
    setError(null);
    try {
      const report = await api.importFiles(paths, directoryId);
      const notes: string[] = [];
      notes.push(
        `Imported ${report.importedFiles} file(s) and ${report.importedDirectories} folder(s), ${formatBytes(
          report.importedBytes,
        )}.`,
      );
      if (report.renamed.length > 0) {
        notes.push(`${report.renamed.length} item(s) were renamed to avoid a conflict.`);
      }
      if (report.skipped.length > 0) {
        notes.push(`${report.skipped.length} item(s) were skipped (links or unsupported).`);
      }
      setStatus(notes.join(" "));
      await load(directoryId);
      await refreshInfo();
    } catch (e) {
      withError(e, "The import failed.");
    } finally {
      setBusy(null);
      setProgress(null);
    }
  }

  async function runExport(ids: string[], destination: string, overwrite = false) {
    setBusy({ label: "Decrypting to disk" });
    setProgress(null);
    setError(null);
    try {
      const report = await api.exportEntries(ids, destination, overwrite);
      setStatus(
        `Exported ${report.exportedFiles} file(s) to ${report.destination}. The exported copies are no longer encrypted.`,
      );
      setPendingExport(null);
    } catch (e) {
      if (e instanceof CommandError && e.code === "name_conflict" && !overwrite) {
        setPendingExport({ ids, destination });
      } else {
        withError(e, "The export failed.");
      }
    } finally {
      setBusy(null);
      setProgress(null);
    }
  }

  const startExport = async () => {
    const chosen = selectedEntries();
    if (chosen.length === 0) return;
    const destination = await pickExportDestination();
    if (!destination) return;
    await runExport(
      chosen.map((entry) => entry.id),
      destination,
    );
  };

  const openEntry = (entry: EntryView) => {
    if (entry.kind === "directory") {
      setDirectoryId(entry.id);
      setQuery("");
      return;
    }
    setOpenTarget(entry);
  };

  const runOpen = async (entry: EntryView) => {
    setOpening(true);
    setError(null);
    try {
      const result = await api.openEntry(entry.id);
      setOpenTarget(null);
      setOpenWarnings(result.warnings);
      setStatus(
        `Opened "${result.name}" with its default application. The decrypted copy is deleted when you lock MyVault or close it.`,
      );
    } catch (e) {
      setOpenTarget(null);
      withError(e, "The file could not be opened.");
    } finally {
      setOpening(false);
    }
  };

  const navigateUp = () => {
    if (crumbs.length > 1) {
      const parent = crumbs[crumbs.length - 2];
      if (parent) setDirectoryId(parent.id);
    }
  };

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "F2" && selectedEntries().length === 1) {
      event.preventDefault();
      const entry = selectedEntries()[0];
      if (entry) setDialog({ kind: "rename", entry });
    } else if (event.key === "Delete" && selectedEntries().length > 0) {
      event.preventDefault();
      setDialog({ kind: "delete", entries: selectedEntries() });
    } else if (event.key === "Enter" && selectedEntries().length === 1) {
      const entry = selectedEntries()[0];
      if (entry) openEntry(entry);
    }
  };

  const toggle = (id: string) => {
    setSelection((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const shown = results ?? entries;
  const percent =
    progress && progress.total > 0 ? (progress.current / progress.total) * 100 : 0;

  return (
    <div
      className="flex h-full min-h-0 flex-col"
      onKeyDown={onKeyDown}
      onDragEnter={() => {
        dragDepth.current += 1;
      }}
      onDragLeave={() => {
        dragDepth.current = Math.max(0, dragDepth.current - 1);
      }}
      onDragOver={(event) => event.preventDefault()}
      onDrop={(event) => event.preventDefault()}
      tabIndex={-1}
    >
      {/* header */}
      <header className="flex items-center gap-3 border-b border-line bg-surface px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <HardDrive className="h-4 w-4 shrink-0 text-accent" aria-hidden />
          <span className="truncate font-display text-sm font-semibold" title={info.path}>
            {info.name}
          </span>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <Button
            size="sm"
            variant="ghost"
            icon={<SettingsIcon className="h-4 w-4" />}
            onClick={onSettings}
            disabled={busy !== null}
          >
            Settings
          </Button>
          <Button
            size="sm"
            variant="default"
            icon={<Lock className="h-4 w-4" />}
            onClick={onLock}
            disabled={busy !== null}
          >
            Lock
          </Button>
        </div>
      </header>

      {/* breadcrumbs + search */}
      <div className="flex items-center gap-3 border-b border-line bg-surface/60 px-4 py-2">
        <button
          type="button"
          className="rounded p-1 text-muted hover:bg-elevated disabled:opacity-40"
          onClick={navigateUp}
          disabled={crumbs.length < 2}
          aria-label="Go to parent folder"
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <nav aria-label="Breadcrumb" className="flex min-w-0 flex-1 items-center gap-1 overflow-hidden">
          {crumbs.map((crumb, index) => (
            <span key={crumb.id} className="flex items-center gap-1 truncate">
              {index > 0 ? <span className="text-muted">/</span> : null}
              <button
                type="button"
                className={`truncate rounded px-1 py-0.5 text-sm hover:bg-elevated ${
                  index === crumbs.length - 1 ? "font-medium" : "text-muted"
                }`}
                onClick={() => {
                  setDirectoryId(crumb.id);
                  setQuery("");
                }}
              >
                {crumb.name}
              </button>
            </span>
          ))}
        </nav>
        <div className="relative w-64 shrink-0">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" aria-hidden />
          <input
            className="input pl-8 pr-8"
            placeholder="Search encrypted names"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            aria-label="Search file names"
          />
          {query ? (
            <button
              type="button"
              className="absolute right-2 top-2 rounded p-0.5 text-muted hover:text-ink"
              onClick={() => setQuery("")}
              aria-label="Clear search"
            >
              <X className="h-4 w-4" />
            </button>
          ) : null}
        </div>
      </div>

      {/* toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-surface px-4 py-2">
        <Button
          size="sm"
          icon={<FolderPlus className="h-4 w-4" />}
          onClick={() => setDialog({ kind: "new-folder" })}
          disabled={busy !== null || results !== null}
        >
          New Folder
        </Button>
        <Button
          size="sm"
          icon={<Upload className="h-4 w-4" />}
          onClick={() => void runImport("files")}
          disabled={busy !== null}
        >
          Import Files
        </Button>
        <Button
          size="sm"
          icon={<FolderInput className="h-4 w-4" />}
          onClick={() => void runImport("folder")}
          disabled={busy !== null}
        >
          Import Folder
        </Button>
        <Button
          size="sm"
          icon={<ExternalLink className="h-4 w-4" />}
          onClick={() => {
            const entry = selectedEntries()[0];
            if (entry && selection.size === 1) openEntry(entry);
          }}
          disabled={
            busy !== null ||
            selection.size !== 1 ||
            selectedEntries()[0]?.kind === "directory"
          }
        >
          Open
        </Button>
        <Button
          size="sm"
          icon={<Download className="h-4 w-4" />}
          onClick={() => void startExport()}
          disabled={busy !== null || selection.size === 0}
        >
          Export
        </Button>
        <Button
          size="sm"
          icon={<Pencil className="h-4 w-4" />}
          onClick={() => {
            const entry = selectedEntries()[0];
            if (entry && selection.size === 1) setDialog({ kind: "rename", entry });
          }}
          disabled={busy !== null || selection.size !== 1}
        >
          Rename
        </Button>
        <Button
          size="sm"
          icon={<ArrowUpDown className="h-4 w-4" />}
          onClick={() => setDialog({ kind: "move", entries: selectedEntries() })}
          disabled={busy !== null || selection.size === 0}
        >
          Move
        </Button>
        <Button
          size="sm"
          variant="danger"
          icon={<Trash2 className="h-4 w-4" />}
          onClick={() => setDialog({ kind: "delete", entries: selectedEntries() })}
          disabled={busy !== null || selection.size === 0}
        >
          Delete
        </Button>
        <span className="ml-auto text-xs text-muted">
          {selection.size > 0 ? `${selection.size} selected` : ""}
        </span>
      </div>

      {/* messages */}
      {error ? (
        <div className="px-4 pt-3">
          <Alert tone="danger" title="Something went wrong" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      ) : null}
      {status ? (
        <div className="px-4 pt-3">
          <Alert tone="success" onDismiss={() => setStatus(null)}>
            {status}
          </Alert>
        </div>
      ) : null}
      {results !== null ? (
        <div className="px-4 pt-3">
          <Alert tone="info">
            Showing {results.length} match(es) across the whole vault. Clear the
            search to browse folders again.
          </Alert>
        </div>
      ) : null}
      {openWarnings ? (
        <div className="px-4 pt-3">
          <Alert
            tone="warning"
            title="A decrypted copy exists while the file is open"
            onDismiss={() => setOpenWarnings(null)}
          >
            <ul className="list-disc space-y-1 pl-4">
              {openWarnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </Alert>
        </div>
      ) : null}

      {/* listing */}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-separate border-spacing-0 text-sm">
          <thead>
            <tr>
              <th className="table-head w-10 px-3 py-2">
                <input
                  type="checkbox"
                  aria-label="Select all"
                  className="h-4 w-4 rounded border-line"
                  checked={shown.length > 0 && selection.size === shown.length}
                  onChange={(event) =>
                    setSelection(
                      event.target.checked
                        ? new Set(shown.map((entry) => entry.id))
                        : new Set(),
                    )
                  }
                />
              </th>
              <th className="table-head px-3 py-2">Name</th>
              <th className="table-head w-28 px-3 py-2">Type</th>
              <th className="table-head w-28 px-3 py-2 text-right">Size</th>
              <th className="table-head w-48 px-3 py-2">Modified</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((entry) => (
              <tr
                key={entry.id}
                className={`row-hover cursor-default ${
                  selection.has(entry.id) ? "bg-accent/10" : ""
                }`}
                onClick={() => toggle(entry.id)}
                onDoubleClick={() => openEntry(entry)}
                tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === "Enter") openEntry(entry);
                }}
                aria-selected={selection.has(entry.id)}
              >
                <td className="border-b border-line px-3 py-2">
                  <input
                    type="checkbox"
                    aria-label={`Select ${entry.name}`}
                    className="h-4 w-4 rounded border-line"
                    checked={selection.has(entry.id)}
                    onChange={() => toggle(entry.id)}
                    onClick={(event) => event.stopPropagation()}
                  />
                </td>
                <td className="border-b border-line px-3 py-2">
                  <div className="flex min-w-0 items-center gap-2">
                    {entry.kind === "directory" ? (
                      <Folder className="h-4 w-4 shrink-0 text-accent" aria-hidden />
                    ) : (
                      <FileIcon className="h-4 w-4 shrink-0 text-muted" aria-hidden />
                    )}
                    <span className="truncate" title={entry.path || entry.name}>
                      {entry.name}
                    </span>
                    {results !== null && entry.path ? (
                      <span className="truncate text-xs text-muted">in {entry.path.split("/").slice(0, -1).join("/") || "Home"}</span>
                    ) : null}
                  </div>
                </td>
                <td className="border-b border-line px-3 py-2 text-muted">
                  {describeType(entry.name, entry.kind)}
                </td>
                <td className="border-b border-line px-3 py-2 text-right tabular-nums text-muted">
                  {entry.kind === "directory" ? "--" : formatBytes(entry.size)}
                </td>
                <td className="border-b border-line px-3 py-2 text-muted">
                  {formatDate(entry.modifiedMs)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!loading && shown.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-6 py-16 text-center">
            <Folder className="h-8 w-8 text-muted/60" aria-hidden />
            <p className="text-sm font-medium">
              {results !== null ? "No matching items" : "This folder is empty"}
            </p>
            <p className="max-w-sm text-xs text-muted">
              {results !== null
                ? "Search covers file and folder names, and only works while the vault is unlocked."
                : "Drag files or folders onto this window, or use Import Files / Import Folder."}
            </p>
          </div>
        ) : null}
        {loading ? (
          <div className="flex items-center justify-center gap-2 px-6 py-12 text-sm text-muted">
            <Spinner /> Reading the encrypted index...
          </div>
        ) : null}
      </div>

      {/* footer */}
      <footer className="flex items-center justify-between gap-3 border-t border-line bg-surface px-4 py-2 text-xs text-muted">
        <span>
          {shown.length} item{shown.length === 1 ? "" : "s"}
        </span>
        <span className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <ShieldCheck className="h-3.5 w-3.5 text-success" aria-hidden /> Vault unlocked
          </span>
          <span className="hidden sm:inline">
            {formatBytes(info.storedBytes)} encrypted / {formatBytes(info.plaintextBytes)} plaintext
          </span>
        </span>
      </footer>

      {/* dialogs */}
      <NewFolderDialog
        open={dialog?.kind === "new-folder"}
        onClose={() => setDialog(null)}
        onCreate={async (name) => {
          try {
            await api.createDirectory(directoryId, name);
            setDialog(null);
            await load(directoryId);
            await refreshInfo();
            setStatus(`Folder "${name}" created.`);
          } catch (e) {
            withError(e, "The folder could not be created.");
          }
        }}
      />

      {dialog?.kind === "rename" ? (
        <RenameDialog
          entry={dialog.entry}
          onClose={() => setDialog(null)}
          onRename={async (name) => {
            try {
              await api.renameEntry(dialog.entry.id, name);
              setDialog(null);
              await load(directoryId);
              await refreshInfo();
              setStatus(`Renamed to "${name}".`);
            } catch (e) {
              withError(e, "The item could not be renamed.");
            }
          }}
        />
      ) : null}

      {dialog?.kind === "delete" ? (
        <DeleteDialog
          entries={dialog.entries}
          onClose={() => setDialog(null)}
          onDelete={async () => {
            try {
              for (const entry of dialog.entries) {
                await api.deleteEntry(entry.id);
              }
              setDialog(null);
              await load(directoryId);
              await refreshInfo();
              setStatus("Deleted. The encrypted data was removed from the container.");
            } catch (e) {
              withError(e, "The item could not be deleted.");
            }
          }}
        />
      ) : null}

      {dialog?.kind === "move" ? (
        <MoveDialog
          entries={dialog.entries}
          rootId={info.rootId}
          onClose={() => setDialog(null)}
          onMove={async (destination) => {
            try {
              for (const entry of dialog.entries) {
                await api.moveEntry(entry.id, destination);
              }
              setDialog(null);
              await load(directoryId);
              setStatus("Moved.");
            } catch (e) {
              withError(e, "The item could not be moved.");
            }
          }}
        />
      ) : null}

      <Modal
        open={openTarget !== null}
        title={openTarget ? `Open "${openTarget.name}"?` : "Open file"}
        description="Windows applications cannot read an encrypted container, so MyVault will decrypt a copy to a temporary folder and start the default application."
        onClose={() => setOpenTarget(null)}
        footer={
          <>
            <Button onClick={() => setOpenTarget(null)} disabled={opening}>
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={opening}
              icon={opening ? <Spinner /> : <ExternalLink className="h-4 w-4" />}
              onClick={() => {
                if (openTarget) void runOpen(openTarget);
              }}
            >
              {opening ? "Opening..." : "Open anyway"}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Alert tone="warning" title="The decrypted copy is not protected">
            While the file is open, any program running as you can read it. The
            copy is deleted when you lock MyVault or close it, but a crash, a
            system shutdown or another application's own temporary files can keep
            a copy.
          </Alert>
          {openTarget ? (
            <p className="text-xs text-muted">
              {openTarget.name} - {formatBytes(openTarget.size)}
            </p>
          ) : null}
        </div>
      </Modal>

      <Modal
        open={pendingExport !== null}
        title="Destination already contains these items"
        description="Exporting will replace the existing files on disk. This cannot be undone."
        onClose={() => setPendingExport(null)}
        footer={
          <>
            <Button onClick={() => setPendingExport(null)}>Cancel</Button>
            <Button
              variant="danger"
              onClick={() => {
                if (pendingExport) {
                  void runExport(
                    pendingExport.ids,
                    pendingExport.destination,
                    true,
                  );
                }
              }}
            >
              Replace files
            </Button>
          </>
        }
      />

      {busy ? (
        <Modal
          open
          title={busy.label}
          description="The operation is streamed in 1 MiB chunks. You can cancel safely."
          onClose={() => undefined}
          width="max-w-md"
        >
          <div className="space-y-3">
            <ProgressBar percent={percent} />
            <div className="flex items-center justify-between text-xs text-muted">
              <span className="truncate pr-3">
                {progress?.item ?? "Preparing..."}
              </span>
              <span className="tabular-nums">
                {progress ? `${Math.round(percent)}%` : ""}
              </span>
            </div>
            <div className="flex justify-end">
              <Button size="sm" onClick={() => void api.cancelOperation()}>
                Cancel
              </Button>
            </div>
          </div>
        </Modal>
      ) : null}
    </div>
  );
}

function NewFolderDialog({
  open,
  onClose,
  onCreate,
}: {
  open: boolean;
  onClose: () => void;
  onCreate: (name: string) => void;
}) {
  const [name, setName] = useState("");
  useEffect(() => {
    if (open) setName("");
  }, [open]);

  return (
    <Modal
      open={open}
      title="New folder"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={name.trim().length === 0}
            onClick={() => onCreate(name.trim())}
          >
            Create
          </Button>
        </>
      }
    >
      <Field label="Folder name" htmlFor="new-folder-name">
        <TextInput
          id="new-folder-name"
          value={name}
          onChange={setName}
          autoFocus
          onKeyDown={(event) => {
            if (event.key === "Enter" && name.trim()) onCreate(name.trim());
          }}
        />
      </Field>
    </Modal>
  );
}

function RenameDialog({
  entry,
  onClose,
  onRename,
}: {
  entry: EntryView;
  onClose: () => void;
  onRename: (name: string) => void;
}) {
  const [name, setName] = useState(entry.name);
  return (
    <Modal
      open
      title="Rename"
      description={entry.path}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={name.trim().length === 0 || name.trim() === entry.name}
            onClick={() => onRename(name.trim())}
          >
            Rename
          </Button>
        </>
      }
    >
      <Field label="New name" htmlFor="rename-input">
        <TextInput
          id="rename-input"
          value={name}
          onChange={setName}
          autoFocus
          onKeyDown={(event) => {
            if (event.key === "Enter" && name.trim()) onRename(name.trim());
          }}
        />
      </Field>
    </Modal>
  );
}

function DeleteDialog({
  entries,
  onClose,
  onDelete,
}: {
  entries: EntryView[];
  onClose: () => void;
  onDelete: () => void;
}) {
  const folders = entries.filter((entry) => entry.kind === "directory").length;
  const totalBytes = entries.reduce((sum, entry) => sum + entry.size, 0);
  return (
    <Modal
      open
      title={
        entries.length === 1 ? `Delete "${entries[0]?.name}"?` : `Delete ${entries.length} items?`
      }
      description={
        folders > 0
          ? "Folders are deleted together with everything inside them."
          : "The encrypted data is removed from the container."
      }
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="danger" onClick={onDelete}>
            Delete
          </Button>
        </>
      }
    >
      <Alert tone="warning">
        This permanently removes {entries.length} item{entries.length === 1 ? "" : "s"}
        {totalBytes > 0 ? ` (${formatBytes(totalBytes)})` : ""} from the vault.
        Exported copies on disk are not affected.
      </Alert>
    </Modal>
  );
}

function MoveDialog({
  entries,
  rootId,
  onClose,
  onMove,
}: {
  entries: EntryView[];
  rootId: string;
  onClose: () => void;
  onMove: (destinationId: string) => void;
}) {
  const [folders, setFolders] = useState<EntryView[] | null>(null);
  const [destination, setDestination] = useState<string>("");

  useEffect(() => {
    let cancelled = false;
    void api
      .listDirectories()
      .then((list) => {
        if (!cancelled) setFolders(list);
      })
      .catch(() => {
        if (!cancelled) setFolders([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const blocked = (folder: EntryView) =>
    entries.some(
      (entry) =>
        entry.id === folder.id ||
        (entry.kind === "directory" && folder.path.startsWith(`${entry.path}/`)),
    );

  return (
    <Modal
      open
      title="Move to folder"
      description="Choose a destination inside this vault."
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={!destination}
            onClick={() => destination && onMove(destination)}
          >
            Move
          </Button>
        </>
      }
    >
      {folders === null ? (
        <div className="flex items-center gap-2 text-sm text-muted">
          <Spinner /> Loading folders...
        </div>
      ) : (
        <div className="max-h-64 space-y-1 overflow-auto pr-1">
          {folders.map((folder) => (
            <label
              key={folder.id}
              className={`flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm ${
                blocked(folder)
                  ? "cursor-not-allowed border-transparent opacity-40"
                  : destination === folder.id
                    ? "border-accent bg-accent/10"
                    : "border-line hover:bg-elevated"
              }`}
            >
              <input
                type="radio"
                name="move-destination"
                className="h-3.5 w-3.5"
                disabled={blocked(folder)}
                checked={destination === folder.id}
                onChange={() => setDestination(folder.id)}
              />
              <Folder className="h-4 w-4 text-accent" aria-hidden />
              <span className="truncate">
                {folder.path || "Home"}
                {folder.id === rootId ? " (root)" : ""}
              </span>
            </label>
          ))}
        </div>
      )}
    </Modal>
  );
}
