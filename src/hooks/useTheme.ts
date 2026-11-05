import { useEffect } from "react";
import type { ThemeMode } from "../types";

/**
 * Applies the theme to the document root. `system` follows the Windows
 * setting live, so the application never forces a theme the user did not ask
 * for.
 */
export function useTheme(mode: ThemeMode) {
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const dark = mode === "dark" || (mode === "system" && media.matches);
      document.documentElement.dataset.theme = dark ? "dark" : "light";
    };
    apply();
    if (mode !== "system") return;
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [mode]);
}
