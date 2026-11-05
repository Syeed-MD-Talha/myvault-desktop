import {
  createContext,
  forwardRef,
  useContext,
  useEffect,
  useId,
  useRef,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";
import { AlertTriangle, CheckCircle2, Info, Loader2, X } from "lucide-react";

/* ---------------------------------------------------------------- formatting */

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "--";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(
    units.length - 1,
    Math.floor(Math.log(bytes) / Math.log(1024)),
  );
  const value = bytes / 1024 ** exponent;
  const digits = exponent === 0 ? 0 : value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[exponent] ?? "B"}`;
}

export function formatDate(ms: number): string {
  if (!ms) return "--";
  try {
    return new Date(ms).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "--";
  }
}

export function describeType(name: string, kind: "file" | "directory"): string {
  if (kind === "directory") return "Folder";
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || dot === name.length - 1) return "File";
  return name.slice(dot + 1).toUpperCase();
}

/* -------------------------------------------------------------------- button */

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "danger" | "ghost";
  size?: "sm" | "md";
  icon?: ReactNode;
};

export function Button({
  variant = "default",
  size = "md",
  icon,
  className = "",
  children,
  ...rest
}: ButtonProps) {
  const variants = {
    default: "btn",
    primary: "btn btn-primary",
    danger: "btn btn-danger",
    ghost: "btn btn-ghost",
  } as const;
  const sizes = { sm: "btn-sm", md: "" } as const;
  return (
    <button
      type="button"
      className={`${variants[variant]} ${sizes[size]} ${className}`}
      {...rest}
    >
      {icon}
      {children}
    </button>
  );
}

/* --------------------------------------------------------------------- input */

export function Field({
  label,
  hint,
  error,
  children,
  htmlFor,
}: {
  label: string;
  hint?: string;
  error?: string | null;
  children: ReactNode;
  htmlFor?: string;
}) {
  return (
    <div>
      <label className="label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {error ? (
        <p className="mt-1.5 text-xs text-danger" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p className="mt-1.5 text-xs text-muted">{hint}</p>
      ) : null}
    </div>
  );
}

export const TextInput = forwardRef<
  HTMLInputElement,
  { value: string; onChange: (value: string) => void } & Omit<
    React.InputHTMLAttributes<HTMLInputElement>,
    "value" | "onChange"
  >
>(function TextInput({ value, onChange, className = "", ...rest }, ref) {
  return (
    <input
      ref={ref}
      className={`input ${className}`}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      {...rest}
    />
  );
});

/* -------------------------------------------------------------------- alerts */

export function Alert({
  tone = "info",
  title,
  children,
  onDismiss,
}: {
  tone?: "info" | "warning" | "success" | "danger";
  title?: string;
  children?: ReactNode;
  onDismiss?: () => void;
}) {
  const styles = {
    info: "border-accent/30 bg-accent/10 text-ink",
    warning: "border-amber-400/40 bg-amber-400/10 text-ink",
    success: "border-success/30 bg-success/10 text-ink",
    danger: "border-danger/30 bg-danger/10 text-ink",
  } as const;
  const Icon =
    tone === "success"
      ? CheckCircle2
      : tone === "warning" || tone === "danger"
        ? AlertTriangle
        : Info;
  const iconColor =
    tone === "success"
      ? "text-success"
      : tone === "danger"
        ? "text-danger"
        : tone === "warning"
          ? "text-amber-500"
          : "text-accent";
  return (
    <div
      className={`flex items-start gap-3 rounded-lg border px-3.5 py-3 text-sm ${styles[tone]}`}
      role={tone === "danger" ? "alert" : "status"}
    >
      <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${iconColor}`} aria-hidden />
      <div className="min-w-0 flex-1">
        {title ? <p className="font-semibold">{title}</p> : null}
        {children ? <div className="mt-0.5 text-muted">{children}</div> : null}
      </div>
      {onDismiss ? (
        <button
          type="button"
          className="rounded p-1 text-muted hover:bg-elevated"
          aria-label="Dismiss"
          onClick={onDismiss}
        >
          <X className="h-3.5 w-3.5" />
        </button>
      ) : null}
    </div>
  );
}

/* --------------------------------------------------------------------- modal */

export function Modal({
  open,
  title,
  description,
  onClose,
  children,
  footer,
  width = "max-w-lg",
}: {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children?: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    panel.current?.focus();
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-slate-950/45 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden
      />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={`relative z-10 w-full ${width} rounded-xl2 border border-line bg-surface p-5 shadow-pop`}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id={titleId} className="font-display text-base font-semibold">
              {title}
            </h2>
            {description ? (
              <p className="mt-1 text-sm text-muted">{description}</p>
            ) : null}
          </div>
          <button
            type="button"
            className="rounded p-1 text-muted hover:bg-elevated"
            aria-label="Close"
            onClick={onClose}
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        {children ? <div className="mt-4">{children}</div> : null}
        {footer ? <div className="mt-5 flex justify-end gap-2">{footer}</div> : null}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------- spinner */

export function Spinner({ className = "" }: { className?: string }) {
  return <Loader2 className={`h-4 w-4 animate-spin ${className}`} aria-hidden />;
}

export function ProgressBar({ percent }: { percent: number }) {
  const value = Math.max(0, Math.min(100, percent));
  return (
    <div
      className="h-2 w-full overflow-hidden rounded-full bg-line"
      role="progressbar"
      aria-valuenow={Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="h-full rounded-full bg-accent transition-[width] duration-150"
        style={{ width: `${value}%` }}
      />
    </div>
  );
}

/* --------------------------------------------------------------- status pill */

export const StatusContext = createContext<{
  setStatus: (message: string | null, tone?: "info" | "danger" | "success") => void;
}>({ setStatus: () => undefined });

export function useStatus() {
  return useContext(StatusContext);
}
