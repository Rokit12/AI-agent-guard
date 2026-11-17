"""
Serve Llama Prompt Guard 2 locally in the Hugging Face text-classification format that
Agent Shield expects (POST {"inputs": text} -> [{"label", "score"}, ...]).

  pip install transformers torch
  huggingface-cli login            # the model is gated: accept Meta's licence on its page first
  python scripts/prompt-guard-server.py  [--model meta-llama/Llama-Prompt-Guard-2-86M] [--port 4620]
  PROMPT_GUARD_URL=http://127.0.0.1:4620 npm run serve
"""
import argparse, json
from http.server import BaseHTTPRequestHandler, HTTPServer
from transformers import pipeline

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="meta-llama/Llama-Prompt-Guard-2-22M")
ap.add_argument("--port", type=int, default=4620)
args = ap.parse_args()
clf = pipeline("text-classification", model=args.model, top_k=None)

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        out = clf(str(body.get("inputs", "")), truncation=True)
        data = json.dumps(out[0] if out and isinstance(out[0], list) else out).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass

print(f"Prompt Guard 2 ({args.model}) on http://127.0.0.1:{args.port}")
HTTPServer(("127.0.0.1", args.port), H).serve_forever()
