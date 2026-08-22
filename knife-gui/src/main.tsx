import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./theme.css";

// This runs inside a WebView2 (the Edge engine), which brings browser reflexes
// that do not belong in a native tool: a right-click menu full of "Reload" and
// "Save as", F5 to reload (which would drop the loaded binary), and Ctrl+scroll
// page zoom. Suppress them so the window behaves like an application. The
// pseudocode line menu is unaffected — it is rendered by React, not the
// browser, so preventing the browser's own menu does not touch it.
window.addEventListener("contextmenu", (e) => e.preventDefault());

window.addEventListener("keydown", (e) => {
  const reload = e.key === "F5" || (e.ctrlKey && (e.key === "r" || e.key === "R"));
  if (reload) e.preventDefault();
});

window.addEventListener(
  "wheel",
  (e) => {
    if (e.ctrlKey) e.preventDefault();
  },
  { passive: false },
);

// Dropping a file on a plain web page navigates to it; here it should do nothing
// (opening a target goes through the native picker). Guard both events.
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => e.preventDefault());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
