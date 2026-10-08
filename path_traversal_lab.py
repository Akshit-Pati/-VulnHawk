from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pathlib import Path

app = FastAPI(title="VulnHawk Path Traversal Lab")

BASE_DIR = Path(__file__).resolve().parent / "lab_files"
BASE_DIR.mkdir(exist_ok=True)

(BASE_DIR / "hello.txt").write_text(
    "VulnHawk Path Traversal Lab\n",
    encoding="utf-8"
)


@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>VulnHawk Path Traversal Test Lab</title>
</head>
<body>
    <h1>VulnHawk Path Traversal Test Lab</h1>
    <p>Local-only security testing endpoint.</p>
    <a href="/download?file=hello.txt">
        Download test file
    </a>
</body>
</html>
"""


@app.get("/download", response_class=PlainTextResponse)
def download(file: str = Query(...)):
    requested = BASE_DIR / file

    # Intentionally vulnerable local test endpoint.
    try:
        return requested.read_text(encoding="utf-8")
    except Exception:
        if ".." in file or "%2e" in file.lower():
            return (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "vulnhawk-lab-test\n"
            )

        return "File not found"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=9001,
        reload=False
    )