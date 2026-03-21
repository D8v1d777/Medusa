import { app, BrowserWindow } from "electron";
import * as path from "path";
import { BackendManager } from "./backend";

let mainWindow: BrowserWindow | null = null;
const backend = new BackendManager();

function createWindow(): BrowserWindow {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });
  mainWindow = win;
  win.on("closed", () => { mainWindow = null; });
  return win;
}

app.whenReady().then(async () => {
  const baseUrl = await backend.start();
  const win = createWindow();
  const htmlPath = path.join(__dirname, "../../index.html");
  win.loadURL(`file://${htmlPath.replace(/\\/g, "/")}?apiUrl=${encodeURIComponent(baseUrl)}`);
});

app.on("window-all-closed", async () => {
  await backend.stop();
  app.quit();
});
