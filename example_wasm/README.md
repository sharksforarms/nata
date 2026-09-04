
# nata WASM

This browser example loads a legacy PCAP capture from a local file or URL,
parses every frame with Nata, and prints a pretty Rust `Debug` dump.

## Building/Running

From the repository root, build and serve the example on port 8000:

```bash
just wasm-serve
```

Pass another port when needed, for example `just wasm-serve 9000`.

The equivalent manual commands are:

```bash
wasm-pack build --target web
```

```bash
python3 -m http.server .
```

Then open `http://localhost:8000/`. Remote captures must be served with a
Cross-Origin Resource Sharing (CORS) policy that permits requests from the
example's origin.
