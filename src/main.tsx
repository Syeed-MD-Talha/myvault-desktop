import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("The root element is missing from index.html");
}

// StrictMode is intentionally not used in production: it double-invokes
// effects, which is undesirable for commands that touch the vault.
ReactDOM.createRoot(container).render(<App />);
