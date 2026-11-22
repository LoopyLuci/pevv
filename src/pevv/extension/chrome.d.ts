/**
 * The slice of the Chrome extension API the PEVV extension uses. Kept local so
 * the project does not need @types/chrome; only what is called is typed.
 */
declare namespace chrome {
  namespace runtime {
    interface MessageSender {
      id?: string;
      tab?: chrome.tabs.Tab;
      frameId?: number;
      url?: string;
      origin?: string;
    }
    const id: string;
    const lastError: { message?: string } | undefined;
    function getURL(path: string): string;
    function getPlatformInfo(): Promise<unknown>;
    function sendMessage<T = unknown>(message: unknown): Promise<T>;
    interface Port {
      postMessage(message: unknown): void;
      disconnect(): void;
      readonly onMessage: { addListener(cb: (message: unknown) => void): void };
      readonly onDisconnect: { addListener(cb: () => void): void };
    }
    function connectNative(application: string): Port;
    const onMessage: {
      addListener(cb: (message: unknown, sender: MessageSender, sendResponse: (r: unknown) => void) => boolean | void): void;
    };
    const onSuspend: { addListener(cb: () => void): void };
    const onStartup: { addListener(cb: () => void): void };
    const onInstalled: { addListener(cb: () => void): void };
  }
  namespace storage {
    interface StorageChange { oldValue?: unknown; newValue?: unknown }
    interface StorageArea {
      get(keys: string | string[] | null): Promise<Record<string, unknown>>;
      set(items: Record<string, unknown>): Promise<void>;
      remove(keys: string | string[]): Promise<void>;
    }
    const local: StorageArea;
    const onChanged: { addListener(cb: (changes: Record<string, StorageChange>, area: string) => void): void };
  }
  namespace tabs {
    interface Tab { id?: number; url?: string; active?: boolean; windowId?: number }
    function query(q: { active?: boolean; currentWindow?: boolean }): Promise<Tab[]>;
    function create(p: { url: string }): Promise<Tab>;
    function sendMessage<T = unknown>(tabId: number, message: unknown, options?: { frameId?: number }): Promise<T>;
    const onRemoved: { addListener(cb: (tabId: number) => void): void };
    const onUpdated: { addListener(cb: (tabId: number, info: { url?: string; status?: string }) => void): void };
  }
  namespace scripting {
    interface RegisteredContentScript { id: string; matches?: string[]; js?: string[]; runAt?: 'document_idle' | 'document_end' | 'document_start'; allFrames?: boolean; persistAcrossSessions?: boolean }
    function executeScript(p: { target: { tabId: number; frameIds?: number[] }; files: string[] }): Promise<unknown[]>;
    function registerContentScripts(s: RegisteredContentScript[]): Promise<void>;
    function unregisterContentScripts(f?: { ids?: string[] }): Promise<void>;
    function getRegisteredContentScripts(f?: { ids?: string[] }): Promise<RegisteredContentScript[]>;
  }
  namespace permissions {
    interface Permissions { origins?: string[]; permissions?: string[] }
    function request(p: Permissions): Promise<boolean>;
    function remove(p: Permissions): Promise<boolean>;
    function contains(p: Permissions): Promise<boolean>;
    function getAll(): Promise<Permissions>;
    const onRemoved: { addListener(cb: (p: Permissions) => void): void };
    const onAdded: { addListener(cb: (p: Permissions) => void): void };
  }
  namespace alarms {
    interface Alarm { name: string; scheduledTime: number }
    function create(name: string, info: { when?: number; delayInMinutes?: number; periodInMinutes?: number }): Promise<void>;
    function clear(name: string): Promise<boolean>;
    const onAlarm: { addListener(cb: (a: Alarm) => void): void };
  }
  namespace idle {
    type IdleState = 'active' | 'idle' | 'locked';
    function setDetectionInterval(seconds: number): void;
    const onStateChanged: { addListener(cb: (s: IdleState) => void): void };
  }
  namespace windows {
    function getAll(): Promise<unknown[]>;
    const onRemoved: { addListener(cb: (windowId: number) => void): void };
  }
  namespace action {
    function setBadgeText(p: { text: string; tabId?: number }): Promise<void>;
    function setBadgeBackgroundColor(p: { color: string; tabId?: number }): Promise<void>;
  }
}
