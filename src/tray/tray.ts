import { invoke } from "@tauri-apps/api/core";

export interface TrayState {
  riskLevel: "Safe" | "Suspicious" | "High Risk" | "Critical";
  ssid: string | null;
}

let currentState: TrayState = {
  riskLevel: "Safe",
  ssid: null,
};

export function getState(): TrayState {
  return currentState;
}

export async function refreshState(): Promise<TrayState> {
  try {
    const logs: any[] = await invoke("get_scan_logs");
    const ssid: string | null = await invoke("get_current_ssid");

    if (logs.length > 0) {
      currentState = {
        riskLevel: logs[0].risk_level as TrayState["riskLevel"],
        ssid,
      };
    } else {
      currentState = { riskLevel: "Safe", ssid };
    }
  } catch {
    currentState = { riskLevel: "Safe", ssid: null };
  }

  return currentState;
}
