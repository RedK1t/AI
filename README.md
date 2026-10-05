<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/RedK1t/RedKit/main/docs/assets/logo-light.svg">
    <img src="https://raw.githubusercontent.com/RedK1t/RedKit/main/docs/assets/logo-dark.svg" alt="RedKit" width="96">
  </picture>
</p>

<h1 align="center">RedKit AI Scanner</h1>

<p align="center">SQL injection and reflected XSS scanner with LLM analysis, ML severity classification and report generation.<br>
Part of <a href="https://github.com/RedK1t/RedKit"><b>RedKit</b></a>, a modular, web-based penetration-testing framework.</p>

---

## What it does

- **Scanner** (WebSocket, `:3006`): crawls a target and tests parameters for SQLi and reflected XSS, streaming findings live.
- **Report API** (REST, `:3007`): builds and downloads a report from the latest scan.
- **Analysis**: rule-based checks plus LLM explanations (Cohere / Gemini) and an ML severity classifier (`analyzer/severity_ml/`).

## Run

```bash
cp template.env .env        # add your COHERE_API_KEY / GEMINI_API_KEY
docker build -t redkit-ai . && docker run --env-file .env -p 3006:3006 -p 3007:3007 redkit-ai
```

Or locally (Python 3.10):

```bash
pip install -r requirements.txt
python api.py
```

## Docs

- [API_DOCUMENTATION.md](API_DOCUMENTATION.md): WebSocket and REST reference
- [analyzer/severity_ml/README.md](analyzer/severity_ml/README.md): severity model training and evaluation

## License

[MIT](LICENSE). For authorized security testing and education only. Only scan systems you own or have written permission to test.
