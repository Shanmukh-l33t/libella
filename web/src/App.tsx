import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import TokenScreen from "./components/TokenScreen";
import { ToastProvider } from "./components/ui";
import CommandCenter from "./pages/CommandCenter";
import Engagements from "./pages/Engagements";
import NewEngagement from "./pages/NewEngagement";
import Engagement from "./pages/Engagement";
import Finding from "./pages/Finding";
import Tools from "./pages/Tools";
import Models from "./pages/Models";
import Compare from "./pages/Compare";
import Settings from "./pages/Settings";
import { getToken } from "./api";

export default function App() {
  const [authed, setAuthed] = useState(!!getToken());
  useEffect(() => {
    const onUnauth = () => setAuthed(false);
    window.addEventListener("libella:unauthorized", onUnauth);
    return () => window.removeEventListener("libella:unauthorized", onUnauth);
  }, []);

  if (!authed) return <TokenScreen onAuthed={() => setAuthed(true)} />;

  return (
    <ToastProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<CommandCenter />} />
          <Route path="/engagements" element={<Engagements />} />
          <Route path="/engagements/new" element={<NewEngagement />} />
          <Route path="/engagements/:id" element={<Engagement />} />
          <Route path="/findings/:id" element={<Finding />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/models" element={<Models />} />
          <Route path="/compare" element={<Compare />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </ToastProvider>
  );
}