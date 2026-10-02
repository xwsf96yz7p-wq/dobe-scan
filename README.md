[README.md](https://github.com/user-attachments/files/32945776/README.md)
# DOBE Scan — Cloudflare

Token risk checker + Solana low-cap screener.

## Structure

```
public/
  index.html      — Risk checker (original DOBE)
  screener.html   — Auto-updating filtered token list
functions/
  check.js        — Security scan API
  screener.js     — Screener API (DexScreener filters)
wrangler.toml
```

## Deploy (Cloudflare Pages)

1. Create a new Pages project.
2. Connect this repo / upload the folder.
3. Build command: leave empty (static + Functions).
4. Output directory: `public`
5. Functions root: `functions`

Or with Wrangler:

```bash
npx wrangler pages deploy public --project-name=dobe-scan
```

## Endpoints

- `GET /check?address=...&network=solana&lang=en`
- `GET /screener` — filtered Solana tokens

## Notes

- No mandatory API keys (public sources).
- Screener uses DexScreener free endpoints only.
- Optional env vars: `GOPLUS_API_KEY`, `RUGCHECK_API_KEY`, `TOKENSNIFFER_API_KEY`
