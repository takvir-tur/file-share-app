import React from "react";
import ReactDOM from "react-dom/client";
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import App from "./App";
import { IncomingBannerPopup } from "./components/IncomingTransferBanner";
import "./styles.css";

if (typeof HTMLInputElement !== "undefined" && !("switch" in HTMLInputElement.prototype)) {
  document.documentElement.dataset.switchFallback = "1";
}

const isIncomingBannerWindow =
  isTauri() && getCurrentWebviewWindow().label === "incoming-banner";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {isIncomingBannerWindow ? <IncomingBannerPopup /> : <App />}
  </React.StrictMode>
);
