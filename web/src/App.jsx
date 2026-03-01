import { useEffect, useState } from "react";

const apiBase =
  window.__SECRET_ENGINE_CONFIG__?.apiBaseUrl ||
  import.meta.env.VITE_API_BASE_URL ||
  "http://localhost:8080";

const defaultState = {
  token: "",
  mount: "kv",
  path: "apps/demo/password",
  value: "",
  readResult: "",
  listPrefix: "apps/",
  listItems: [],
  health: "checking"
};

export function App() {
  const [state, setState] = useState(defaultState);
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetch(`${apiBase}/health`)
      .then((response) => response.json())
      .then((payload) => setState((current) => ({ ...current, health: payload.status })))
      .catch(() => setState((current) => ({ ...current, health: "offline" })));
  }, []);

  async function request(method, path, body) {
    const response = await fetch(`${apiBase}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${state.token}`
      },
      body: body ? JSON.stringify(body) : undefined
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(error || `request failed (${response.status})`);
    }

    if (response.status === 204) {
      return null;
    }

    return response.json();
  }

  async function onWrite(event) {
    event.preventDefault();
    try {
      const payload = await request(
        "POST",
        `/api/v1/kv/${state.mount}/${state.path}`,
        { value: state.value }
      );
      setMessage(`Stored version ${payload.version}`);
      setState((current) => ({ ...current, value: "" }));
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function onRead() {
    try {
      const payload = await request("GET", `/api/v1/kv/${state.mount}/${state.path}`);
      setState((current) => ({ ...current, readResult: payload.value }));
      setMessage(`Loaded version ${payload.version}`);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function onList() {
    const query = state.listPrefix ? `?prefix=${encodeURIComponent(state.listPrefix)}` : "";
    try {
      const payload = await request("GET", `/api/v1/kv/${state.mount}${query}`);
      setState((current) => ({ ...current, listItems: payload.items }));
      setMessage(`Found ${payload.items.length} entries`);
    } catch (error) {
      setMessage(error.message);
    }
  }

  return (
    <div className="page-shell">
      <main className="console">
        <section className="hero">
          <p className="eyebrow">Secret Engine</p>
          <h1>Vault-style secret storage with a minimal control plane.</h1>
          <p className="subtle">
            API status: <strong>{state.health}</strong>
          </p>
        </section>

        <section className="panel">
          <label>
            Admin token
            <input
              type="password"
              value={state.token}
              onChange={(event) => setState((current) => ({ ...current, token: event.target.value }))}
              placeholder="dev-root-token"
            />
          </label>

          <div className="grid">
            <label>
              Mount
              <input
                value={state.mount}
                onChange={(event) => setState((current) => ({ ...current, mount: event.target.value }))}
              />
            </label>
            <label>
              Secret path
              <input
                value={state.path}
                onChange={(event) => setState((current) => ({ ...current, path: event.target.value }))}
              />
            </label>
          </div>

          <form onSubmit={onWrite}>
            <label>
              Secret value
              <textarea
                value={state.value}
                onChange={(event) => setState((current) => ({ ...current, value: event.target.value }))}
                rows="4"
                placeholder="paste secret material"
              />
            </label>
            <div className="actions">
              <button type="submit">Write</button>
              <button type="button" className="ghost" onClick={onRead}>
                Read
              </button>
              <button type="button" className="ghost" onClick={onList}>
                List
              </button>
            </div>
          </form>

          <label>
            List prefix
            <input
              value={state.listPrefix}
              onChange={(event) => setState((current) => ({ ...current, listPrefix: event.target.value }))}
            />
          </label>

          <div className="output">
            <p className="output-label">Message</p>
            <pre>{message || "No requests yet."}</pre>
          </div>

          <div className="output">
            <p className="output-label">Read result</p>
            <pre>{state.readResult || "Nothing loaded."}</pre>
          </div>

          <div className="output">
            <p className="output-label">List result</p>
            <pre>
              {state.listItems.length
                ? state.listItems.map((item) => `${item.path}/${item.key} (v${item.version})`).join("\n")
                : "No results."}
            </pre>
          </div>
        </section>
      </main>
    </div>
  );
}
