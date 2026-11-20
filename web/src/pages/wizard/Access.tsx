import { Plus, Trash2 } from "lucide-react";
import { Button, Card, Field, Input, Textarea } from "../../components/ui";
import type { Identity, Patch, WizardState } from "../../lib/wizard";
import { Choice } from "./parts";

const BLANK: Identity = { username: "", password: "", login_url: "" };

export default function Access({ s, patch, errors }: {
  s: WizardState; patch: Patch; errors: Record<string, string>;
}) {
  const login = s.login;
  const setLogin = (p: Partial<typeof login>) => patch({ login: { ...login, ...p } });
  const setIdentity = (i: number, p: Partial<Identity>) =>
    patch({ identities: s.identities.map((x, idx) => (idx === i ? { ...x, ...p } : x)) });

  return (
    <>
      <Card title="How should checks get in?" description="Without credentials only the unauthenticated surface is assessed.">
        <div role="radiogroup" aria-label="Access" className="grid gap-2 sm:grid-cols-3">
          <Choice name="access" checked={s.access === "none"} onChange={() => patch({ access: "none" })}
            title="No access" hint="Public surface only." />
          <Choice name="access" checked={s.access === "login"} onChange={() => patch({ access: "login" })}
            title="Login flow" hint="One recorded form login, replayed by the browser runtime." />
          <Choice name="access" checked={s.access === "identities"} onChange={() => patch({ access: "identities" })}
            title="Test accounts" hint="Credential pairs handed to the authenticated checks." />
        </div>

        {s.access === "login" && (
          <div className="mt-4 border-t border-line pt-4">
            {errors.login && <p className="mb-2 text-xs text-sev-high">{errors.login}</p>}
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Base URL" htmlFor="w-lf-base" hint="The in-scope origin the session belongs to.">
                <Input id="w-lf-base" value={login.base_url} placeholder="https://app.example.com"
                  onChange={(e) => setLogin({ base_url: e.target.value })} />
              </Field>
              <Field label="Login URL" htmlFor="w-lf-url" hint="Must be inside scope.">
                <Input id="w-lf-url" value={login.login_url} placeholder="https://app.example.com/login"
                  onChange={(e) => setLogin({ login_url: e.target.value })} />
              </Field>
              <Field label="Username" htmlFor="w-lf-user">
                <Input id="w-lf-user" value={login.username} autoComplete="off" onChange={(e) => setLogin({ username: e.target.value })} />
              </Field>
              <Field label="Password" htmlFor="w-lf-pass" hint="Used for the login attempt only, never saved in the browser.">
                <Input id="w-lf-pass" type="password" autoComplete="new-password" value={login.password}
                  onChange={(e) => setLogin({ password: e.target.value })} />
              </Field>
              <Field label="Success assertion" htmlFor="w-lf-assert" hint="CSS selector that exists only after login.">
                <Input id="w-lf-assert" value={login.success} placeholder="[data-testid=dashboard]"
                  onChange={(e) => setLogin({ success: e.target.value })} />
              </Field>
              <Field label="Field selectors (JSON)" htmlFor="w-lf-sel" error={errors.selectors}
                hint='Optional, e.g. {"username":"#user"}.'>
                <Input id="w-lf-sel" value={login.selectors} className="font-mono text-xs" placeholder='{"username":"#user"}'
                  error={!!errors.selectors} onChange={(e) => setLogin({ selectors: e.target.value })} />
              </Field>
            </div>
          </div>
        )}

        {s.access === "identities" && (
          <div className="mt-4 border-t border-line pt-4">
            {errors.identities && <p className="mb-2 text-xs text-sev-high">{errors.identities}</p>}
            <p className="mb-2 text-xs text-ink-500">Passwords are sealed server-side and never returned by the API.</p>
            {s.identities.map((x, i) => (
              <div key={i} className="mb-2 grid gap-2 sm:grid-cols-[1fr_1fr_1.4fr_auto]">
                <Input aria-label={`Identity ${i + 1} username`} placeholder="username" value={x.username} autoComplete="off"
                  onChange={(e) => setIdentity(i, { username: e.target.value })} />
                <Input aria-label={`Identity ${i + 1} password`} type="password" autoComplete="new-password" placeholder="password"
                  value={x.password} onChange={(e) => setIdentity(i, { password: e.target.value })} />
                <Input aria-label={`Identity ${i + 1} login url`} placeholder="https://app.example.com/login" value={x.login_url}
                  onChange={(e) => setIdentity(i, { login_url: e.target.value })} />
                <Button type="button" variant="ghost" aria-label={`Remove identity ${i + 1}`} icon={<Trash2 size={14} />}
                  onClick={() => patch({ identities: s.identities.filter((_, idx) => idx !== i) })} />
              </div>
            ))}
            <Button type="button" size="sm" icon={<Plus size={13} />} onClick={() => patch({ identities: [...s.identities, { ...BLANK }] })}>
              Add account
            </Button>
          </div>
        )}
      </Card>

      <Card title="API specs" description="Optional, and independent of the access choice. They turn on schema-driven checks.">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="OpenAPI file" htmlFor="w-openapi" error={errors.openapi}
            hint="Server-side path to an OpenAPI 3 JSON or YAML file. Enables BOLA, BFLA, mass assignment and exposure checks.">
            <Input id="w-openapi" value={s.openapi} className="font-mono text-xs" placeholder="/srv/spec/openapi.json"
              error={!!errors.openapi} onChange={(e) => patch({ openapi: e.target.value })} />
          </Field>
          <Field label="GraphQL endpoint" htmlFor="w-graphql" error={errors.graphql}
            hint="In-scope URL. Enables introspection, injection, field-authz and depth/alias/batch abuse checks.">
            <Input id="w-graphql" value={s.graphql} className="font-mono text-xs" placeholder="https://app.example.com/graphql"
              error={!!errors.graphql} onChange={(e) => patch({ graphql: e.target.value })} />
          </Field>
        </div>
      </Card>

      <Card title="Advanced" description="Raw inputs most engagements never need.">
        <details className="group">
          <summary className="inline-flex cursor-pointer items-center gap-1 text-sm text-ink-700 hover:text-ink-900">
            Planner hints and workflow JSON
          </summary>
          <div className="mt-3 space-y-3">
            <Field label="Test hints (JSON)" htmlFor="w-hints" error={errors.hints}
              hint="Forwarded to the planner as structured, non-executable context.">
              <Textarea id="w-hints" rows={4} value={s.hints} className="font-mono text-xs" error={!!errors.hints}
                placeholder={'{\n  "focus": "authentication"\n}'} onChange={(e) => patch({ hints: e.target.value })} />
            </Field>
            <Field label="Workflow name" htmlFor="w-wf-name">
              <Input id="w-wf-name" value={s.workflow.name} placeholder="checkout funnel"
                onChange={(e) => patch({ workflow: { ...s.workflow, name: e.target.value } })} />
            </Field>
            <Field label="Workflow steps (JSON array)" htmlFor="w-wf-steps" error={errors.steps}
              hint="actions: navigate | click | fill | submit | extract | assert. Every navigation is scope-checked.">
              <Textarea id="w-wf-steps" rows={5} value={s.workflow.steps} className="font-mono text-xs" error={!!errors.steps}
                placeholder={'[\n  {"action":"navigate","url":"https://app.example.com/"},\n  {"action":"assert","selector":".invoice"}\n]'}
                onChange={(e) => patch({ workflow: { ...s.workflow, steps: e.target.value } })} />
            </Field>
          </div>
        </details>
      </Card>
    </>
  );
}