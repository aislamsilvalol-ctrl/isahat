import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { api } from "./api/client";
import { I18nProvider, useI18n } from "./i18n";
import Compare from "./screens/Compare";
import Dashboard from "./screens/Dashboard";
import NewScan from "./screens/NewScan";
import ScanDetail from "./screens/ScanDetail";

function BridgeBanner(): JSX.Element {
  const { t } = useI18n();
  const [state, setState] = useState<"checking" | "ok" | "down">("checking");

  useEffect(() => {
    let alive = true;
    const check = (): void => {
      api
        .health()
        .then(() => alive && setState("ok"))
        .catch(() => alive && setState("down"));
    };
    check();
    // Keep retrying while down so the banner clears when `isahat serve`
    // comes up after the UI, without a manual reload.
    const timer = setInterval(check, 4000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  if (state === "ok") return <></>;
  return (
    <div className={`bridge-banner ${state}`}>
      {state === "checking" ? t.bridge.checking : t.bridge.down}
    </div>
  );
}

function LanguageSwitch(): JSX.Element {
  const { lang, setLang, t } = useI18n();
  return (
    <div className="lang-switch" role="group" aria-label={t.lang.label}>
      <button className={lang === "en" ? "on" : ""} onClick={() => setLang("en")}>
        EN
      </button>
      <button className={lang === "pt" ? "on" : ""} onClick={() => setLang("pt")}>
        PT
      </button>
    </div>
  );
}

function Shell(): JSX.Element {
  const { t } = useI18n();
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">◈</span>
          <span>
            <div className="brand-name">IsaHat</div>
            <div className="brand-tag">{t.brand.tagline}</div>
          </span>
        </div>
        <nav>
          <NavLink to="/" end>
            <span className="nav-icon">◫</span>
            {t.nav.dashboard}
          </NavLink>
          <NavLink to="/new">
            <span className="nav-icon">＋</span>
            {t.nav.newScan}
          </NavLink>
          <NavLink to="/compare">
            <span className="nav-icon">⇄</span>
            {t.nav.compare}
          </NavLink>
        </nav>
        <footer className="sidebar-footer">
          <LanguageSwitch />
          {t.footer.notice}
          <br />
          {t.footer.link}
        </footer>
      </aside>
      <main className="content">
        <BridgeBanner />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/new" element={<NewScan />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/compare" element={<Compare />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App(): JSX.Element {
  return (
    <I18nProvider>
      <Shell />
    </I18nProvider>
  );
}
