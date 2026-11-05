import { useEffect, useRef } from "react";

const ACTIVITY_EVENTS = [
  "mousemove",
  "mousedown",
  "keydown",
  "wheel",
  "touchstart",
  "pointerdown",
] as const;

/**
 * Locks the vault after a period of inactivity *inside MyVault*. Per the SRS,
 * "inactivity" means no interaction with this application, not with Windows.
 */
export function useAutoLock({
  minutes,
  enabled,
  onLock,
}: {
  minutes: number;
  enabled: boolean;
  onLock: () => void;
}) {
  const lockRef = useRef(onLock);
  lockRef.current = onLock;

  useEffect(() => {
    if (!enabled || minutes <= 0) return;
    let timer: number | undefined;

    const schedule = () => {
      if (timer !== undefined) window.clearTimeout(timer);
      timer = window.setTimeout(
        () => {
          lockRef.current();
        },
        minutes * 60_000,
      );
    };

    for (const event of ACTIVITY_EVENTS) {
      window.addEventListener(event, schedule, { passive: true });
    }
    schedule();

    return () => {
      for (const event of ACTIVITY_EVENTS) {
        window.removeEventListener(event, schedule);
      }
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [minutes, enabled]);
}
