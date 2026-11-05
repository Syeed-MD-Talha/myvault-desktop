import { useCallback, useEffect, useState } from "react";
import { FileManager } from "./pages/FileManager";
import { Welcome } from "./pages/Welcome";
import { CreateVault } from "./pages/CreateVault";
import { UnlockVault } from "./pages/UnlockVault";
import { SettingsPage } from "./pages/SettingsPage";
import { About } from "./pages/About";
import { api, CommandError } from "./services/api";
import { pickExistingVault } from "./services/dialogs";
import { useTheme } from "./hooks/useTheme";
import { useAutoLock } from "./hooks/useAutoLock";
import { Alert } from "./components/ui";
import type {
  AppInfo,
  AppSettings,
  OpenedSummary,
  Screen,
  VaultInfo,
} from "./types";

const DEFAULT_SETTINGS: AppSettings = {
  theme: "system",
  autoLockMinutes: 5,
  confirmDelete: true,
};

export default function App() {
  const [screen, setScreen] = useState<Screen>("welcome");
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [opened, setOpened] = useState<OpenedSummary | null>(null);
  const [info, setInfo] = useState<VaultInfo | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useTheme(settings.theme);

  useEffect(() => {
    void api.appInfo().then(setAppInfo).catch(() => undefined);
    void api.getSettings().then(setSettings).catch(() => undefined);
  }, []);

  const lock = useCallback(async () => {
    try {
      await api.lockVault();
    } catch {
      /* the state is cleared locally regardless */
    }
    setInfo(null);
    setOpened(null);
    setScreen("welcome");
  }, []);

  const handleLockedNotice = useCallback(
    (message: string) => {
      setNotice(message);
      void lock();
    },
    [lock],
  );

  useAutoLock({
    minutes: settings.autoLockMinutes,
    enabled: info !== null,
    onLock: () => {
      setNotice("The vault was locked automatically after a period of inactivity.");
      void lock();
    },
  });

  const handleOpenExisting = async () => {
    setNotice(null);
    try {
      const path = await pickExistingVault();
      if (!path) return;
      const summary = await api.openVault(path);
      setOpened(summary);
      setScreen("unlock");
    } catch (e) {
      setNotice(
        e instanceof CommandError ? e.message : "The vault could not be opened.",
      );
    }
  };

  const handleNavigate = (next: Screen) => {
    setNotice(null);
    setScreen(next);
    if (next === "welcome") setOpened(null);
  };

  return (
    <div className="flex h-full min-h-0 flex-col bg-app">
      {notice ? (
        <div className="px-4 pt-3">
          <Alert tone="info" onDismiss={() => setNotice(null)}>
            {notice}
          </Alert>
        </div>
      ) : null}

      <main className="min-h-0 flex-1 overflow-auto">
        {screen === "welcome" ? (
          <Welcome
            version={appInfo?.version ?? "1.0.0"}
            onNavigate={handleNavigate}
            onOpenVault={() => void handleOpenExisting()}
          />
        ) : null}

        {screen === "create" ? (
          <CreateVault
            onCancel={() => handleNavigate("welcome")}
            onCreated={async (summary) => {
              setOpened(summary);
              try {
                setInfo(await api.vaultInfo());
                setScreen("files");
              } catch (e) {
                setNotice(
                  e instanceof CommandError
                    ? e.message
                    : "The vault was created but could not be opened.",
                );
                handleNavigate("welcome");
              }
            }}
          />
        ) : null}

        {screen === "unlock" && opened ? (
          <UnlockVault
            vaultName={opened.name}
            vaultPath={opened.path}
            onBack={() => handleNavigate("welcome")}
            onUnlocked={(result) => {
              setInfo(result.info);
              setScreen("files");
            }}
          />
        ) : null}

        {screen === "files" && info ? (
          <FileManager
            info={info}
            onLock={() => void lock()}
            onSettings={() => setScreen("settings")}
            onInfoChange={setInfo}
            onLockedNotice={handleLockedNotice}
          />
        ) : null}

        {screen === "settings" ? (
          <SettingsPage
            info={info}
            settings={settings}
            onSettingsChange={setSettings}
            onBack={() => setScreen(info ? "files" : "welcome")}
          />
        ) : null}

        {screen === "about" ? (
          <About appInfo={appInfo} onBack={() => setScreen(info ? "files" : "welcome")} />
        ) : null}
      </main>
    </div>
  );
}
