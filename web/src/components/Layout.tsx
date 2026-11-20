import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { LogOut } from "lucide-react";
import { clearToken, getToken } from "../api";
import { cx } from "./ui";

export default function Layout() {
  const [signedOut, setSignedOut] = useState(false);
  useEffect(() => {
    if (signedOut) window.dispatchEvent(new Event("libella:unauthorized"));
  }, [signedOut]);

  return (
    <div className="min-h-screen bg-white">
      <header className="sticky top-0 z-40 border-b border-line bg-white/95 backdrop-blur-[2px]">
        <div className="mx-auto flex max-w-[1240px] items-center gap-8 px-6" style={{ height: 52 }}>
          <NavLink to="/" className="flex items-baseline gap-2">
            <span className="text-[15px] font-semibold tracking-tight text-ink-900">Libella</span>
            <span className="hidden text-2xs uppercase tracking-widest text-ink-300 sm:inline">pentest workbench</span>
          </NavLink>
          <nav className="no-scrollbar flex items-center gap-1 overflow-x-auto">
            {[
              { to: "/", label: "Command center", end: true },
              { to: "/engagements", label: "Engagements" },
              { to: "/tools", label: "Tools" },
              { to: "/models", label: "Models" },
              { to: "/compare", label: "Compare" },
              { to: "/coverage", label: "Coverage" },
              { to: "/settings", label: "Settings" },
            ].map((l) => (
              <NavLink key={l.to} to={l.to} end={l.end}
                className={({ isActive }) => cx("whitespace-nowrap rounded px-2.5 py-1.5 text-sm transition-colors",
                  isActive ? "bg-ink-100 font-medium text-ink-900" : "text-ink-500 hover:text-ink-900")}>
                {l.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3">
            <span className="hidden items-center gap-1.5 text-xs text-ink-500 sm:flex">
              <span className={cx("h-1.5 w-1.5 rounded-full", getToken() ? "bg-sev-low" : "bg-ink-300")} />
              local
            </span>
            <button onClick={() => { clearToken(); setSignedOut(true); }} aria-label="Sign out and clear token"
              className="rounded p-1.5 text-ink-500 transition-colors hover:bg-ink-100 hover:text-ink-900">
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-[1240px] px-6 py-7">
        <Outlet />
      </main>
    </div>
  );
}