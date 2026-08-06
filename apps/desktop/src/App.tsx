import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { api } from "./api/client";
import Compare from "./screens/Compare";
import Dashboard from "./screens/Dashboard";
import NewScan from "./screens/NewScan";
import ScanDetail from "./screens/ScanDetail";

function BridgeBanner(): JSX.Element {
  const [state, setState] = useState<"checking" | "ok" | "down">("checking");

  useEffect(() => {
    let alive = true;
    api
      .health()
      .then(() => alive && setState("ok"))
      .catch(() => alive && setState("down"));
    return () => {
      alive = false;
    };
  }, []);

  if (state === "ok") return <></>;
  return (
    <div className={`bridge-banner ${state}`}>
      {state === "checking"
        ? "Connecting to the local engine…"
        : "Engine offline — start it with `isahat serve` in a terminal."}
    </div>
  );
}

export default function App(): JSX.Element {
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">⛨</span>
          <span className="brand-name">IsaHat</span>
        </div>
        <nav>
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/new">New audit</NavLink>
          <NavLink to="/compare">Compare</NavLink>
        </nav>
        <footer className="sidebar-footer">
          Authorised targets only.
          <br />
          See RESPONSIBLE-USE.md.
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
