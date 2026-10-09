# browser-use and Goose

[browser-use](https://github.com/browser-use/browser-use) and [Goose](https://github.com/block/goose) can both act on websites through your vault. In both setups the vault's MCP tools are the only way the agent can act: their own tools that could reach a website are switched off. Every sign-in, payment or post then goes through your phone.

Start with the vault:

```sh
pip install "authyouragent[mcp]"
authyouragent vault up --agent-id ag_... --key /path/to/agent-key.pem
```

`AYA_AGENT_ID` and the key come from **Agents → Add an agent** in the app. The env values below are file paths and an id, not secrets. See [Take over](/docs/developers/takeover) for a vault on another machine.

## browser-use

Tested with browser-use 0.13.11.

browser-use is a browser agent with its own browser. The setup below gives its `Agent` the vault's tools and removes every built-in browser and file action, so the model can only act through the vault.

```python
import asyncio
from browser_use import Agent, Tools
from browser_use.browser.profile import BrowserProfile
from browser_use.llm.openai.chat import ChatOpenAI
from browser_use.mcp.client import MCPClient

# every built-in action except `done`
BUILT_IN = ["click", "close", "dropdown_options", "evaluate", "extract", "find_elements",
            "find_text", "go_back", "input", "navigate", "read_file", "replace_file",
            "save_as_pdf", "screenshot", "scroll", "search", "search_page",
            "select_dropdown", "send_keys", "switch", "upload_file", "wait", "write_file"]

async def main(task):
    tools = Tools(exclude_actions=BUILT_IN)
    vault = MCPClient(server_name="authyouragent", command="authyouragent-mcp", env={
        "AYA_AGENT_ID": "ag_...",
        "AYA_KEY_FILE": "/path/to/agent-key.pem",
        "AYA_VAULT_URL": "http://127.0.0.1:7801",
        "AYA_VAULT_TOKEN_FILE": "/home/you/.authyouragent/vault/token",
    })
    await vault.register_to_tools(tools, prefix="aya_")
    agent = Agent(
        task=task + " Your only tools are the aya_ tools (aya_navigate, aya_read_page, "
                    "aya_click, ...) and done.",
        llm=ChatOpenAI(model="...", base_url="...", api_key="..."),
        tools=tools,
        browser_profile=BrowserProfile(headless=True),
        use_vision=False,
        directly_open_url=False,
        step_timeout=900,
    )
    await agent.run(max_steps=40)
    await vault.disconnect()

asyncio.run(main("Buy me the Brass lighthouse lamp from https://demo.authyouragent.com "
                 "and tell me if the order is paid."))
```

Why each setting is there:

- `prefix="aya_"`: the vault's `navigate`, `click`, `scroll`, `go_back` and `screenshot` have the same names as browser-use's built-in actions. Removing a built-in also removes a vault tool with the same name, so the vault's tools need their own prefix.
- `directly_open_url=False`: otherwise browser-use opens the task's URL with its own `navigate`, which is removed.
- `step_timeout=900`: a vault click that needs your approval waits for your tap. The default of 180 seconds cancels it while you decide.
- browser-use still starts its own browser, so it needs Chrome or Chromium installed. The model has no action that can use it.
- After upgrading browser-use, print `sorted(tools.registry.registry.actions.keys())`. A new built-in action not in the list above gives the model a way around the vault.

If your model server does not support JSON-schema output (llama.cpp and similar servers answer `response_format` with an error), add `dont_force_structured_output=True, add_schema_to_system_prompt=True` to `ChatOpenAI`. Some models then wrap their answer in a <code>```json</code> block, which browser-use rejects; strip it before browser-use parses the reply.

## Goose

Tested with Goose 1.54.0.

Goose has no browser of its own, but it turns on several built-in extensions by default. One of them, `developer`, gives the model a shell, and a shell can reach any website without the vault. In `~/.config/goose/config.yaml`, add the vault and switch the built-ins off:

```yaml
extensions:
  authyouragent:
    enabled: true
    type: stdio
    name: authyouragent
    description: Auth Your Agent vault
    cmd: authyouragent-mcp
    args: []
    envs:
      AYA_AGENT_ID: ag_...
      AYA_KEY_FILE: /path/to/agent-key.pem
      AYA_VAULT_URL: http://127.0.0.1:7801
      AYA_VAULT_TOKEN_FILE: /home/you/.authyouragent/vault/token
    timeout: 900
  developer: {enabled: false, type: platform, name: developer}
  summon: {enabled: false, type: platform, name: summon}
  analyze: {enabled: false, type: platform, name: analyze}
  skills: {enabled: false, type: platform, name: skills}
  tom: {enabled: false, type: platform, name: tom}
  apps: {enabled: false, type: platform, name: apps}
  extensionmanager: {enabled: false, type: platform, name: Extension Manager}
  scheduler: {enabled: false, type: platform, name: scheduler}
  code_execution: {enabled: false, type: platform, name: code_execution}
  todo: {enabled: false, type: platform, name: todo}
  chatrecall: {enabled: false, type: platform, name: chatrecall}
  summarize: {enabled: false, type: platform, name: summarize}
  orchestrator: {enabled: false, type: platform, name: orchestrator}
```

Merge this into your own config. Keep `developer` on if the agent needs a shell for other work, but then the vault no longer covers everything the agent can do on the web.

- `timeout: 900` must be longer than an approval wait, or Goose drops the call while you decide.
- `extensionmanager` can switch other extensions back on during a session, so it is off too.
- One-off alternative: `goose run --no-profile --with-extension "authyouragent:AYA_AGENT_ID=... AYA_KEY_FILE=... AYA_VAULT_URL=... AYA_VAULT_TOKEN_FILE=... authyouragent-mcp"` loads only the vault for that run.

Check it: ask Goose to list its tools. The list should be the vault's tools only, each named `authyouragent__...`.

## Try it

```sh
goose run -t "Buy me the Brass lighthouse lamp from https://demo.authyouragent.com and tell me if the order is paid."
```

[Demo Shop](https://demo.authyouragent.com) charges nothing. Your phone gets the cards in turn: the sign-in, the vault's check on Buy, then the shop's own payment request. In our runs both agents waited through the cards, read the order page and reported "Paid. The owner confirmed on their phone". If you bought the lamp in the last hour, the shop says so and offers **Buy another**.

## What this does not cover

- Switching off an agent's own tools keeps the model on the vault. It does not stop other software on the same machine from reaching the web.
- An agent running as root, or as the vault's user, can read the vault's files. To keep them out of its reach, run the vault on another machine ([Take over: the vault on another machine](/docs/developers/takeover)).
