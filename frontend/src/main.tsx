import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/instrument-sans";
import "@fontsource/ibm-plex-mono/latin-400.css";
import { AttackLab, Dashboard, DocumentScanner, ModelLab, Playground, Rules } from "./pages";
import { useData } from "./useRequest";
import "./style.css";

const routes = {
  playground: ["Playground", "Send a message through the firewall and inspect each layer’s verdict.", Playground],
  lab: ["Attack Lab", "Compare how the local mock responds to bundled synthetic scenarios.", AttackLab],
  dashboard: ["Dashboard", "Watch decisions and latency from recent chat requests.", Dashboard],
  scanner: ["Document Scanner", "See what the firewall removes or withholds before retrieval reaches the model.", DocumentScanner],
  model: ["Model Lab", "Explore the classifier’s precision and recall on held-out synthetic fixtures.", ModelLab],
  rules: ["Rules", "Edit decision thresholds and the phrases matched during inspection.", Rules],
} as const;
type Route = keyof typeof routes;
const navigation = Object.keys(routes) as Route[];

function getRoute(): Route {
  const route = window.location.hash.slice(1);
  return navigation.find(key => key === route) ?? "playground";
}

function App() {
  const [route, setRoute] = useState(getRoute);
  const [dark, setDark] = useState(() => localStorage.getItem("firewall-theme") === "dark");
  const health = useData<{status: string}>("/api/health", 8000);
  const [title, description, Page] = routes[route];
  useEffect(() => {
    const onHashChange = () => {
      setRoute(getRoute());
      window.scrollTo({top: 0});
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("firewall-theme", dark ? "dark" : "light");
  }, [dark]);
  return <div className="shell">
    <a className="skip-link" href="#content" onClick={event => {
      event.preventDefault();
      document.getElementById("content")?.focus();
    }}>Skip to content</a>
    <aside className="sidebar">
      <a className="brand" href="#playground">
        <span className="brand-logo" aria-hidden="true"><i /><i /><i /></span>
        <span className="brand-name"><span>Prompt</span>{" "}<span>Firewall</span></span>
      </a>
      <nav aria-label="Console">{navigation.map(key =>
        <a key={key} href={`#${key}`} aria-current={route === key ? "page" : undefined}>
          <span className={`nav-icon icon-${key}`} aria-hidden="true" />{routes[key][0]}
        </a>
      )}</nav>
    </aside>
    <div className="workspace">
      <header className="toolbar">
        <span className="connection" data-online={health.data?.status === "ok" && !health.error}>
          <i aria-hidden="true" />{health.error ? "API offline" : health.data ? "Local API online" : "Connecting"}
        </span>
        <button type="button" className="mode" onClick={() => setDark(!dark)} aria-pressed={dark}>{dark ? "Light mode" : "Dark mode"}</button>
      </header>
      <main id="content" className="content" tabIndex={-1}>
        <div className="page-heading"><h1>{title}</h1><p>{description}</p></div>
        <Page />
      </main>
    </div>
  </div>;
}

createRoot(document.getElementById("root")!).render(<App />);
