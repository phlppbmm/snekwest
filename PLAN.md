# Snekwest: Rust-First Architecture Plan

## Ziel

Alles auf die Rust-Seite verschieben. Python-Schicht wird zum dünnen API-Shim.
Getestet wird gegen die `requests`-Testsuite (`python-requests/tests/`).

## Aktueller Zustand

- Python-Adapter ruft Rust mit `allow_redirects=False` auf
- Python reimplementiert: Redirects, Cookies, Auth, Body-Encoding, Header-Merging
- Rust hat bereits vollständige Implementierung, die aber umgangen wird
- Rust-Implementierung hat bekannte Bugs (aus Code Review)

## Strategie

Rust-Bugs fixen → Python-Adapter ausdünnen → Tests als Gate nach jedem Schritt.

---

## Phase 1: Rust-Seitige Bugs fixen

Bevor Python-Logik durch Rust ersetzt werden kann, muss die Rust-Seite korrekt sein.

### Step 1: Redirect-Logik fixen (`src/session.rs`)

- [ ] **301 nur POST→GET** (aktuell: alle non-HEAD→GET)
  - `session.rs:677` — `matches!(status, 301)` soll nur bei `POST` zu GET wechseln
  - 302/303: alle non-HEAD→GET bleibt korrekt
- [ ] **Auth bei Cross-Domain-Redirect strippen**
  - `session.rs:549` — `current_auth` wird nie modifiziert
  - Implementiere `should_strip_auth(old_url, new_url)` analog zu `sessions.py:99-121`
  - Vergleiche Hostname, Schema, Port
  - Strip `Authorization` Header wenn Host wechselt
- [ ] **Content-Header bei Method-Change strippen**
  - `session.rs:676-687` — Bei POST→GET: `Content-Type`, `Content-Length`, `Transfer-Encoding` entfernen
  - `params.files` auch clearen (aktuell nur `data` und `json`)
- [ ] **Redirect ohne Location-Header: Response zurückgeben statt Error**
  - `session.rs:688-690` — `break` fällt in unreachable code
  - Stattdessen die Response als Final-Response zurückgeben
- [ ] Tests laufen lassen, committen

### Step 2: Cookie-Handling verbessern (`src/session.rs`)

- [ ] **Domain/Path-Scoping im Cookie-Jar**
  - `session.rs:234` — `HashMap<String, String>` ersetzen durch struct mit Domain/Path
  - Neues struct: `CookieEntry { value: String, domain: String, path: String, secure: bool, expires: Option<SystemTime> }`
  - Cookies nur senden wenn Domain/Path matchen
  - `Set-Cookie` Domain/Path/Secure/Expires korrekt parsen
- [ ] **Cookie-Expiry korrekt implementieren**
  - `session.rs:422-438` — Statt "1970"-String-Check: echtes Date-Parsing
  - `max-age` mit negativen Werten und 0 korrekt handlen
- [ ] **Session-Cookies immer updaten** (auch bei per-request cookies)
  - `session.rs:395-413` — `request_had_cookies` Check entfernen
  - `requests` updated den Session-Jar immer
- [ ] Tests laufen lassen, committen

### Step 3: Client-Builder vervollständigen (`src/session.rs`)

- [ ] **Client-Zertifikate implementieren**
  - `session.rs:469-488` — `config.cert` an `builder.identity()` übergeben
  - PEM-File lesen, in `reqwest::Identity` konvertieren
- [ ] **Proxy-Support implementieren**
  - `session.rs:469-488` — `config.proxy` an `builder.proxy()` übergeben
  - `reqwest::Proxy::http()`, `Proxy::https()`, `Proxy::all()`
- [ ] **Single-Timeout als Connect+Read setzen**
  - `session.rs:382-393` — `TimeoutParameter::Single` soll auch `connect_timeout` auf dem Client setzen
  - `ClientConfig::from_params` anpassen
- [ ] **InsecureRequestWarning bei `verify=False`**
  - Python-Warning emitieren analog zu `requests`/`urllib3`
- [ ] Tests laufen lassen, committen

### Step 4: Response-Headers Multi-Value Support (`src/session.rs`, `src/response.rs`)

- [ ] **HashMap<String, String> → Multi-Value Headers**
  - `session.rs:441-449` — `extract_response_headers` soll mehrere Values pro Key bewahren
  - Option A: `HashMap<String, Vec<String>>` und in Python zu CaseInsensitiveDict mit comma-joined values
  - Option B: `Vec<(String, String)>` als geordnete Liste
  - Für `Set-Cookie` besonders wichtig: jeder einzeln bewahren
- [ ] **Response.cookies korrekt aus allen Set-Cookie Headers bauen**
  - `extract_response_cookies` nutzt bereits die rohen Headers — muss weiter funktionieren
- [ ] Tests laufen lassen, committen

### Step 5: Error-Handling härten (`src/session.rs`, `src/exceptions.rs`)

- [ ] **Mutex-Poisoning graceful handlen**
  - Alle `.unwrap()` auf `lock()` ersetzen durch `.map_err()`
  - Saubere Python-Exception statt Panic
- [ ] **SSL-Erkennung verbessern**
  - `session.rs:143-151` — Nicht nur String-Match, sondern `e.is_connect()` als Vorbedingung
  - Vermeidet False-Positives bei URLs mit "ssl" im Pfad
- [ ] **ProxyError-Mapping hinzufügen**
  - In `map_reqwest_error`: Proxy-Errors erkennen und als `ProxyError` raisen
- [ ] **`is_decode()` → `ContentDecodingError`**
- [ ] **Negative Timeout-Werte validieren**
  - `request_params.rs` — Negative floats ablehnen
- [ ] **`full_error_chain` Duplikate vermeiden**
- [ ] Tests laufen lassen, committen

---

## Phase 2: Python-Adapter ausdünnen

Jetzt ist Rust korrekt genug. Python-Logik schrittweise durch Rust-Delegation ersetzen.

### Step 6: Redirects an Rust delegieren

- [ ] **`adapters.py` HTTPAdapter.send()**: `allow_redirects` durchreichen statt immer `False`
- [ ] **`sessions.py` Session.send()**: Redirect-Loop (`resolve_redirects`) überspringen wenn Rust redirects handled
- [ ] **Rust Response muss History korrekt liefern** — `_from_rust` baut History bereits rekursiv
- [ ] **`response._next` Support** — für `allow_redirects=False` muss Python weiterhin `_next` setzen können
- [ ] Problem: Hooks zwischen Redirect-Hops → vorerst: Response-Hooks nach finalem Response in Python dispatchen
- [ ] Tests laufen lassen, committen

### Step 7: Cookie-Management an Rust delegieren

- [ ] **Session.cookies → Rust Cookie-Jar als Backend**
  - Python `RequestsCookieJar` wird zum Wrapper um Rust-Daten
  - Oder: Rust liefert Cookies, Python baut `RequestsCookieJar` daraus
- [ ] **`extract_cookies_to_jar` vereinfachen** — kein `_FakeOriginalResponse`/`BytesIO` Shim mehr
- [ ] **Session-Cookies aus Rust-Jar synchronisieren**
- [ ] Tests laufen lassen, committen

### Step 8: Body-Encoding an Rust delegieren

- [ ] **JSON**: Python `json=` Objekt direkt an Rust übergeben (via `pythonize`)
  - Achtung: `allow_nan=False` muss erhalten bleiben
- [ ] **Form-Data**: Dict direkt an Rust übergeben statt in Python zu encoden
- [ ] **Multipart/Files**: Rust `reqwest::multipart::Form` nutzen
  - Erfordert: File-Handle lesen in Python, Bytes an Rust übergeben
  - Oder: Dateipfad an Rust geben, Rust liest
- [ ] **PreparedRequest.prepare_body() vereinfachen** — nur noch Konvertierung für Rust
- [ ] Tests laufen lassen, committen

### Step 9: Header-Handling an Rust delegieren

- [ ] **Default-Headers auf Rust-Session setzen**
  - `Session.__init__` → `rust_session.default_headers = default_headers()`
- [ ] **Merge in Rust statt Python**
  - Request-Headers + Session-Headers in Rust mergen
  - CaseInsensitiveDict-Semantik in Rust implementieren (oder: Python mergt, Rust empfängt fertig)
- [ ] **CaseInsensitiveDict als Wrapper um Rust-Daten** (optional, kann auch Python bleiben)
- [ ] Tests laufen lassen, committen

### Step 10: Auth an Rust delegieren (teilweise)

- [ ] **Basic Auth**: Bereits in Rust, durchreichen statt in Python Header setzen
- [ ] **Digest Auth**: Komplex, bleibt vorerst in Python (braucht Response-Hooks, State)
- [ ] **Custom AuthBase**: Muss in Python bleiben (User-Code)
- [ ] **Netrc-Auth**: `trust_env` + netrc-Lookup bleibt in Python
- [ ] Tests laufen lassen, committen

---

## Phase 3: Performance & Cleanup

### Step 11: Response-Building optimieren

- [ ] **`content()` → `PyBytes` ohne Clone**
  - `response.rs:96-98` — `PyBytes::new(py, &self.body)` statt `self.body.as_ref().clone()`
- [ ] **`text()` optimieren** — `std::str::from_utf8` als Borrow-Check, dann einmal String
- [ ] **`_from_rust` BytesIO-Shim entfernen** (wenn Step 7 erledigt)
- [ ] **History nur konvertieren wenn nicht leer**
- [ ] Tests laufen lassen, committen

### Step 12: Streaming implementieren

- [ ] **Rust: Response-Body lazy lesen**
  - Neuer Modus: wenn `stream=True`, Body nicht eager lesen
  - Python-Iterator der Chunks aus Rust liefert (GIL release pro Chunk)
- [ ] **Python: `iter_content()` delegiert an Rust-Iterator**
- [ ] **Python: `iter_lines()` baut auf `iter_content()` auf (bleibt Python)**
- [ ] Tests laufen lassen, committen

### Step 13: Python-Schicht aufräumen

- [ ] **Toten Python-Code entfernen** der durch Rust ersetzt wurde
- [ ] **`__init__.py` Exports vervollständigen** (HTTPAdapter, AuthBase, CaseInsensitiveDict etc.)
- [ ] **`conftest.py` Module-Map vervollständigen** (requests.api, requests.__version__)
- [ ] **`_parse_url` ParseResult Class aus Funktion raus** (models.py:117-132)
- [ ] **`cookies.py:411`** — `if toReturn:` → `if toReturn is not None:`
- [ ] **`cookies.py:120-121`** — `getheaders` missing return
- [ ] **`sessions.py:305`** — `data or {}` → `data` (nicht falsy-Werte ersetzen)
- [ ] Tests laufen lassen, committen

### Step 14: Rust aufräumen

- [ ] **`#[pyclass]` und `#[derive(FromPyObject)]` von `RequestParams` entfernen**
- [ ] **Unnötige `Python::attach` durch `py`-Parameter-Threading ersetzen**
  - `serialize_json_body`, `TooManyRedirects` raise
- [ ] **Client-Cache: LRU oder Max-Size**
- [ ] **`#[allow(unused_assignments)]` auf `final_request_headers` fixen**
- [ ] Tests laufen lassen, committen

---

## Bekannte Python-Bugs (unabhängig von Phase, können jederzeit gefixt werden)

| Bug | File | Line | Fix |
|-----|------|------|-----|
| `_find_no_duplicates` drops empty-string cookies | `cookies.py` | 411 | `if toReturn is not None:` |
| `MockResponse.getheaders` no return | `cookies.py` | 120-121 | Add `return` |
| `data or {}` replaces falsy values | `sessions.py` | 305 | Remove `or {}` |
| Missing exports in `__init__.py` | `__init__.py` | — | Add missing names |
| `conftest.py` missing `requests.api` alias | `conftest.py` | — | Add to map |
| `verify="/path"` silently becomes `True` | `adapters.py` | 310-312 | Pass path to Rust or warn |
| `PreparedRequest.copy()` shares hooks | `models.py` | 392 | Deep-copy hooks |

---

## Test-Strategie

Nach jedem Step:
```bash
uv run pytest tests/ python-requests/tests/ -x -q
```

Erwartung: Anfangs brechen einige Tests. Mit jedem Step werden mehr grün.
Ziel: 100% der `requests`-Testsuite pass nach Phase 2.
