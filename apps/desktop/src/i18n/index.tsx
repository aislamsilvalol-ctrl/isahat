import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { en, type Dictionary } from "./en";
import { pt } from "./pt";

export type Language = "en" | "pt";

const DICTIONARIES: Record<Language, Dictionary> = { en, pt };
const STORAGE_KEY = "isahat.lang";

function initialLanguage(): Language {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "en" || stored === "pt") return stored;
  } catch {
    // storage unavailable (e.g. restricted webview) — fall through
  }
  return navigator.language.toLowerCase().startsWith("pt") ? "pt" : "en";
}

interface I18nContextValue {
  lang: Language;
  t: Dictionary;
  setLang: (lang: Language) => void;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }): JSX.Element {
  const [lang, setLangState] = useState<Language>(initialLanguage);

  const value = useMemo<I18nContextValue>(
    () => ({
      lang,
      t: DICTIONARIES[lang],
      setLang: (next: Language) => {
        setLangState(next);
        try {
          window.localStorage.setItem(STORAGE_KEY, next);
        } catch {
          // ignore — preference just won't persist
        }
      },
    }),
    [lang],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used inside <I18nProvider>");
  return ctx;
}
