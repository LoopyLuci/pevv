/**
 * The language store PEVV needs: `locale` ('en' | 'es') and a setter, saved on this device.
 * The first run follows the browser language. Strings live in ../i18n.ts.
 */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type LocaleId = 'en' | 'es';

function detect(): LocaleId {
  try {
    return typeof navigator !== 'undefined' && /^es\b/i.test(navigator.language) ? 'es' : 'en';
  } catch {
    return 'en';
  }
}

function applyDocumentLocale(id: LocaleId): void {
  if (typeof document === 'undefined') return;
  document.documentElement.lang = id;
  document.documentElement.dir = 'ltr';
  document.documentElement.dataset.locale = id;
}

interface LocaleState {
  locale: LocaleId;
  setLocale: (id: LocaleId) => void;
}

export const useLocaleStore = create<LocaleState>()(
  persist(
    (set) => ({
      locale: detect(),
      setLocale: (id) => {
        applyDocumentLocale(id);
        set({ locale: id });
      },
    }),
    {
      name: 'pevv-locale',
      partialize: (s) => ({ locale: s.locale }),
      onRehydrateStorage: () => (state) => { if (state) applyDocumentLocale(state.locale); },
    },
  ),
);

/** Apply the saved language to the page (call once at start-up). */
export function initLocale(): Promise<void> {
  applyDocumentLocale(useLocaleStore.getState().locale);
  return Promise.resolve();
}
