# Local verification

Start from `C:\hackathon`:

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000/. The server respects `HOST` and `PORT` environment variables and runs without the debug reloader.

Run backend checks against a separate database (existing tests write sample data):

```powershell
$env:DATABASE_URL = 'sqlite:///C:/hackathon/data/debug-verification.db'
python -m unittest discover -s . -p "test_*.py"
node --test test_frontend.cjs
Remove-Item Env:DATABASE_URL
```

Regression coverage includes failed and skipped scan sources, readable provider failures, review persistence and CSRF, zero risk scores, unavailable evidence, and actual brand switching with filtered findings.

Browser verification could not be completed in the debugging session: local HTTP connections timed out even though Flask logged successful startup. Flask test-client checks and JavaScript controller tests passed. These checks do not verify live third-party credentials or provider access.
