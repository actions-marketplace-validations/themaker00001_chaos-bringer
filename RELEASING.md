# Releasing to PyPI

chaos-bringer publishes to PyPI through GitHub Actions using **trusted
publishing** (OpenID Connect). No API token is stored anywhere: GitHub and
PyPI authenticate each other directly. The workflow is
`.github/workflows/publish.yml`.

## One-time setup on PyPI

Do this once. Because the project doesn't exist on PyPI yet, use a **pending
publisher**, which also creates the project on the first successful upload.

1. Sign in at https://pypi.org and go to
   **Account → Publishing** (https://pypi.org/manage/account/publishing/).
2. Under "Add a new pending publisher", fill in exactly:
   - **PyPI Project Name:** `chaos-bringer`
   - **Owner:** `themaker00001`
   - **Repository name:** `chaos-bringer`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `pypi`
3. Save.

(Optional, recommended) In the GitHub repo, go to
**Settings → Environments → New environment**, name it `pypi`, and add any
protection rules you want, e.g. require a manual approval before a publish.
The workflow already targets this environment.

## Cut a release

1. Bump the version in `pyproject.toml` (PyPI refuses a version that already
   exists), e.g. `version = "0.1.1"`. Commit and push.
2. On GitHub, **Releases → Draft a new release**, create a tag like `v0.1.1`,
   write notes, and **Publish release**.
3. The workflow runs: tests → build → `twine check` → upload. Watch it under
   the **Actions** tab. When it's green, the version is live:

   ```bash
   pip install chaos-bringer
   chaos-agents plugins
   ```

That's it — every future release is just "bump version, publish a GitHub
Release." You can also trigger the workflow manually from the Actions tab
(**Run workflow**) once a release exists.

## Notes

- The install name is `chaos-bringer`; the command stays `chaos-agents` and
  the import package stays `chaos_agents`.
- A published version is permanent — you can't re-upload `0.1.0`, only yank
  it. Always bump the version.
- No token is ever needed for CI publishing. If you ever upload by hand
  instead, use `twine upload dist/*` with `__token__` as the username and your
  own PyPI token as the password — and never share that token.
