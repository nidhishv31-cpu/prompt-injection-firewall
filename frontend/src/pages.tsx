import { useState } from "react";
import {
  Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import type { Chat, Reason } from "./api";
import { useAction, useData } from "./useRequest";

const percent = (number: number) => new Intl.NumberFormat("en", {style: "percent", maximumFractionDigits: 1}).format(number);
const name = (value: string) => value.replaceAll("_", " ");
const timeLabel = (value: string) => new Date(value).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
const chartColor = {allow: "#5585ce", flag: "#9b75bf", sanitize: "#cc915c", block: "#be5f73"};

export function Status({ children }: {children: string}) {
  return <span className="status" data-status={children}>{name(children)}</span>;
}

function ErrorNotice({ error }: {error: string}) {
  return error && <p className="error" role="alert">{error.replace(/^Error: /, "")}</p>;
}

function Reasons({ values }: {values: Reason[]}) {
  return values.length ? <ul className="reasons">{values.map((reason, index) =>
    <li key={index}>
      <div><strong>{name(reason.layer)}</strong><data>{percent(reason.score)}</data></div>
      <p>{reason.evidence}</p>
      <meter min={0} max={1} value={reason.score} aria-label={`${name(reason.layer)} score`} />
    </li>)}</ul> : <p className="quiet">No inspection findings.</p>;
}

type DemoDocument = {id: string; title: string};

export function Playground() {
  const [prompt, setPrompt] = useState("What are the store hours?");
  const [document, setDocument] = useState("");
  const [session, setSession] = useState<string>();
  const documents = useData<DemoDocument[]>("/api/documents");
  const action = useAction<Chat>("/v1/chat");
  const result = action.data;
  async function inspect() {
    const next = await action.submit({text: prompt, session_id: session, document_ids: document ? [document] : []});
    if (next) setSession(next.session_id);
  }
  return <div className="split">
    <div className="stack">
      <form className="panel" onSubmit={event => {event.preventDefault(); void inspect();}}>
        <div className="panel-heading"><h2>Message</h2><span className="mono">{prompt.length.toLocaleString()} / 12,000</span></div>
        <label className="sr-only" htmlFor="message">Message to inspect</label>
        <textarea id="message" rows={7} maxLength={12000} value={prompt} onChange={event => setPrompt(event.target.value)} />
        <div className="form-row">
          <label className="grow">Retrieved document
            <select value={document} onChange={event => setDocument(event.target.value)}>
              <option value="">No document</option>
              {documents.data?.map(doc => <option value={doc.id} key={doc.id}>{doc.title}</option>)}
            </select>
          </label>
          <button className="primary" disabled={!prompt.trim() || action.busy}>{action.busy ? "Inspecting…" : "Inspect message"}</button>
        </div>
        <ErrorNotice error={action.error || documents.error} />
      </form>
      <section className="panel response" aria-live="polite">
        <div className="panel-heading"><h2>Model response</h2>{result && <Status>{result.decision}</Status>}</div>
        {result ? <pre>{result.response}</pre> : <p className="quiet">The response will appear here after inspection.</p>}
      </section>
    </div>
    <section className="panel trace" aria-live="polite">
      <div className="panel-heading"><h2>Inspection trace</h2>{result && <span className="mono">{result.latency_ms.toFixed(1)} ms</span>}</div>
      {result ? <>
        <div className="risk"><div><span className="quiet">Request risk</span><strong>{percent(result.risk)}</strong></div><Status>{result.decision}</Status></div>
        <Reasons values={result.reasons} />
        <details><summary>Normalized message</summary><pre>{result.normalized}</pre></details>
      </> : <div className="trace-empty"><span className="trace-mark" aria-hidden="true" /><p>Run an inspection to see how each layer scored the message.</p></div>}
      {session && <button type="button" className="text-button" disabled={action.busy} onClick={() => setSession(undefined)}>Start new session</button>}
    </section>
  </div>;
}

type Example = {id: string; category: string; text: string};
type Run = {response: string; disclosed: boolean};
type Comparison = { id: string; category: string; alert: boolean; off: Run; on: Run };
type Lab = {count: number; off_disclosures: number; on_disclosures: number; cases: Comparison[]};

export function AttackLab() {
  const examples = useData<Example[]>("/api/lab");
  const { data, error, busy, submit } = useAction<Lab>("/api/lab");
  const [selected, setSelected] = useState("META-01");
  const [view, setView] = useState("");
  const outcome = data?.cases.find(item => item.id === view) ?? data?.cases[0];
  const example = examples.data?.find(item => item.id === selected);
  return <div className="stack">
    <section className="panel">
      <div className="form-row">
        <label className="grow">Bundled scenario
          <select value={selected} onChange={event => setSelected(event.target.value)}>
            {examples.data?.map(item => <option value={item.id} key={item.id}>{item.id} · {name(item.category)}</option>)}
          </select>
        </label>
        <button className="primary" disabled={busy || !examples.data} onClick={() => {setView(selected); void submit({case_id: selected});}}>Run scenario</button>
        <button disabled={busy || !examples.data} onClick={() => {setView(""); void submit({});}}>Run all fixtures</button>
      </div>
      {example && <p className="quiet">{example.text}</p>}
      {busy && <p role="status">Running local simulation…</p>}
      <ErrorNotice error={error || examples.error} />
    </section>
    {data && <div className="comparison-summary">
      <p><strong>{data.off_disclosures}/{data.count}</strong> disclosed with firewall off</p>
      <p><strong>{data.on_disclosures}/{data.count}</strong> disclosed with firewall on</p>
      {data.count > 1 && <label>Inspect result<select value={outcome?.id} onChange={event => setView(event.target.value)}>
        {data.cases.map(item => <option key={item.id} value={item.id}>{item.id} · {name(item.category)}</option>)}
      </select></label>}
    </div>}
    <div className="equal-split" aria-live="polite">
      {(["off", "on"] as const).map(mode => <section key={mode} className="panel comparison">
        <div className="panel-heading"><h2>Firewall {mode}</h2>
          {outcome && <Status>{outcome[mode].disclosed ? "disclosed" : "withheld"}</Status>}
        </div>
        {outcome ? <pre>{outcome[mode].response}</pre> : <p className="quiet">Run a scenario to see this response.</p>}
      </section>)}
    </div>
  </div>;
}

type Scan = {withheld: boolean; text: string; reasons: Reason[]};

export function DocumentScanner() {
  const [text, setText] = useState("<p>Returns are accepted within 30 days.</p>\n<!-- DEMO_FIXTURE_DOCUMENT_SIGNAL -->");
  const action = useAction<Scan>("/api/scan");
  return <div className="equal-split">
    <form className="panel" onSubmit={event => {event.preventDefault(); void action.submit({text});}}>
      <div className="panel-heading"><h2>Document input</h2></div>
      <label className="sr-only" htmlFor="document-text">Paste HTML or plain text</label>
      <textarea className="code" id="document-text" rows={10} maxLength={24000} value={text} onChange={event => setText(event.target.value)} />
      <button className="primary" disabled={!text.trim() || action.busy}>{action.busy ? "Scanning…" : "Scan document"}</button>
      <ErrorNotice error={action.error} />
    </form>
    <section className="panel" aria-live="polite">
      <div className="panel-heading"><h2>Context preview</h2>{action.data && <Status>{action.data.withheld ? "withheld" : "allow"}</Status>}</div>
      {action.data ? <>
        {action.data.withheld ? <p>The firewall withheld this chunk from model context.</p> : <pre>{action.data.text}</pre>}
        <Reasons values={action.data.reasons} />
      </> : <p className="quiet">Scan a document to see the text the model would receive.</p>}
    </section>
  </div>;
}

type DashboardData = {
  total: number; counts: Record<string, number>; series: {time: string; [key: string]: number | string}[];
  categories: {name: string; count: number}[]; latency_p50_ms: number; latency_p95_ms: number;
};

export function Dashboard() {
  const { data, error } = useData<DashboardData>("/api/dashboard", 4000);
  const stats = data && [
    ["Requests", data.total], ["Blocked", data.counts.block ?? 0],
    ["Median latency", `${data.latency_p50_ms.toFixed(1)} ms`], ["p95 latency", `${data.latency_p95_ms.toFixed(1)} ms`],
  ];
  return <div className="stack">
    <ErrorNotice error={error} />
    {stats && <div className="stat-grid">{stats.map(([label, value]) => <dl key={label}><dt>{label}</dt><dd>{value}</dd></dl>)}</div>}
    <div className="split">
      <section className="panel">
        <div className="panel-heading"><h2>Decisions over time</h2><span className="quiet">Last 500 requests</span></div>
        {!!data?.total && <div className="legend">{Object.entries(chartColor).map(([label, color]) => <span key={label}><i style={{background: color}} />{label}</span>)}</div>}
        {data?.total ? <div className="chart" aria-label="Hourly totals by firewall decision">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data.series} margin={{left: -18, top: 14, right: 12}}>
              <CartesianGrid vertical={false} stroke="var(--stroke)" />
              <XAxis dataKey="time" tickFormatter={timeLabel} minTickGap={22} />
              <YAxis allowDecimals={false} />
              <Tooltip labelFormatter={value => timeLabel(String(value))} />
              {Object.entries(chartColor).map(([key, color]) =>
                <Area key={key} type="monotone" dataKey={key} stackId="decisions" fill={color} stroke={color} fillOpacity={0.36} isAnimationActive={false} dot />)}
            </AreaChart>
          </ResponsiveContainer>
        </div> : <p className="quiet">Send a message in Playground to start recording decisions.</p>}
      </section>
      <section className="panel">
        <div className="panel-heading"><h2>Top categories</h2></div>
        {data?.categories.length ? <ul className="rank">{data.categories.map(item =>
          <li key={item.name}><span>{name(item.name)}</span><strong>{item.count}</strong></li>)}</ul>
          : <p className="quiet">No categorized alerts yet.</p>}
      </section>
    </div>
  </div>;
}

type Model = {
  average_precision: number;
  threshold: number;
  target_fpr: number;
  predictions: {probability: number; label: number; category: string}[];
  pr_curve: {precision: number; recall: number; threshold: number}[];
};

export function ModelLab() {
  const { data, error } = useData<Model>("/api/model");
  const [selected, setSelected] = useState<number>();
  const threshold = selected ?? data?.threshold ?? 0.5;
  let tn = 0, tp = 0, fn = 0, fp = 0;
  for (const row of data?.predictions ?? []) {
    const positive = row.probability >= threshold;
    if (positive && row.label) tp++;
    else if (positive) fp++;
    else if (row.label) fn++;
    else tn++;
  }
  const precision = tp / (tp + fp || 1);
  const recall = tp / (tp + fn || 1);
  return <div className="stack">
    <ErrorNotice error={error} />
    <section className="panel threshold">
      <div className="panel-heading"><h2>Classification threshold</h2><output htmlFor="threshold">{percent(threshold)}</output></div>
      <input aria-label="Classification threshold" id="threshold" type="range" min="0" max="1" step="0.001" value={threshold} onChange={event => setSelected(Number(event.target.value))} />
      <p className="quiet">Validation target: {percent(data?.target_fpr ?? 0.05)} benign false-positive rate. This slider updates the held-out view.</p>
      <div className="stat-grid">{[
        ["Precision", percent(precision)], ["Recall", percent(recall)],
        ["False-positive rate", percent(fp / (fp + tn || 1))],
        ["Average precision", data ? percent(data.average_precision) : "—"],
      ].map(([label, value]) => <dl key={label}><dt>{label}</dt><dd>{value}</dd></dl>)}</div>
    </section>
    <div className="split">
      <section className="panel">
        <div className="panel-heading"><h2>Precision–recall curve</h2></div>
        {data && <div className="chart" aria-label="Precision and recall on held-out fixtures"><ResponsiveContainer width="100%" height="100%">
          <LineChart data={data.pr_curve} margin={{left: -12, right: 18, top: 12, bottom: 6}}>
            <CartesianGrid stroke="var(--stroke)" />
            <XAxis dataKey="recall" type="number" domain={[0, 1]} tickFormatter={percent} />
            <YAxis domain={[0, 1]} tickFormatter={percent} />
            <Tooltip formatter={value => percent(Number(value))} labelFormatter={value => `Recall ${percent(Number(value))}`} />
            <Line dataKey="precision" stroke="var(--accent)" strokeWidth={3} dot={false} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer></div>}
      </section>
      <section className="panel">
        <div className="panel-heading"><h2>Confusion matrix</h2></div>
        <table className="matrix"><thead><tr><th scope="col">Actual</th><th scope="col">Predicted benign</th><th scope="col">Predicted attack</th></tr></thead>
          <tbody><tr><th scope="row">Benign</th><td>{tn}</td><td>{fp}</td></tr><tr><th scope="row">Attack</th><td>{fn}</td><td>{tp}</td></tr></tbody>
        </table>
      </section>
    </div>
  </div>;
}

type Phrase = {phrase: string; weight: number; category: string};
type RuleSet = {flag_threshold: number; sanitize_threshold: number; block_threshold: number; phrases: Phrase[]};
const thresholds = ["flag_threshold", "sanitize_threshold", "block_threshold"] as const;

export function Rules() {
  const initial = useData<RuleSet>("/api/rules");
  const action = useAction<RuleSet>("/api/rules", "PUT");
  const [edited, setEdited] = useState<RuleSet>();
  const draft = edited ?? action.data ?? initial.data;
  if (!draft) return <section className="panel"><ErrorNotice error={initial.error} /><p className="quiet">Loading rules…</p></section>;
  function updatePhrase(index: number, changes: Partial<Phrase>) {
    if (draft) setEdited({...draft, phrases: draft.phrases.map((rule, id) => id === index ? {...rule, ...changes} : rule)});
  }
  return <form className="stack" onSubmit={async event => {
    event.preventDefault();
    const saved = await action.submit(draft);
    if (saved) setEdited(undefined);
  }}>
    <section className="panel">
      <div className="panel-heading"><h2>Decision thresholds</h2></div>
      <div className="threshold-fields">{thresholds.map(key => <label key={key}>{name(key)}
        <input type="number" min="0.001" max="1" step="any" value={draft[key]} required onChange={event => setEdited({...draft, [key]: Number(event.target.value)})} />
      </label>)}</div>
    </section>
    <section className="panel">
      <div className="panel-heading"><h2>Phrase rules</h2><button type="button" disabled={draft.phrases.length >= 250} onClick={() => setEdited({...draft, phrases: [...draft.phrases, {phrase: "", weight: 0.8, category: "custom"}]})}>Add phrase</button></div>
      <div className="rule-rows">{draft.phrases.map((rule, index) => <div className="rule-row" key={index}>
        <label>Phrase<input value={rule.phrase} maxLength={200} required onChange={event => updatePhrase(index, {phrase: event.target.value})} /></label>
        <label>Category<input value={rule.category} maxLength={80} required onChange={event => updatePhrase(index, {category: event.target.value})} /></label>
        <label>Weight<input value={rule.weight} type="number" min="0.001" max="1" step="any" required onChange={event => updatePhrase(index, {weight: Number(event.target.value)})} /></label>
        <button type="button" aria-label={`Remove phrase ${index + 1}`} onClick={() => setEdited({...draft, phrases: draft.phrases.filter((_, id) => id !== index)})}>Remove</button>
      </div>)}</div>
      <div className="form-row"><button className="primary" disabled={!edited || action.busy}>{action.busy ? "Saving…" : "Save changes"}</button>
        {action.data && !edited && <p role="status">Rules saved.</p>}
      </div>
      <ErrorNotice error={action.error} />
    </section>
  </form>;
}
