import { createHash, randomBytes } from "node:crypto";

class HeadersPolyfill {
  constructor(init = undefined) {
    this.values = new Map();
    if (init instanceof HeadersPolyfill) {
      for (const [key, value] of init.entries()) this.set(key, value);
    } else if (Array.isArray(init)) {
      for (const [key, value] of init) this.append(key, value);
    } else if (init) {
      for (const [key, value] of Object.entries(init)) this.set(key, value);
    }
  }

  append(name, value) {
    const key = String(name).toLowerCase();
    const next = String(value);
    this.values.set(key, this.values.has(key) ? `${this.values.get(key)}, ${next}` : next);
  }

  set(name, value) { this.values.set(String(name).toLowerCase(), String(value)); }
  get(name) { return this.values.get(String(name).toLowerCase()) ?? null; }
  has(name) { return this.values.has(String(name).toLowerCase()); }
  delete(name) { this.values.delete(String(name).toLowerCase()); }
  entries() { return this.values.entries(); }
  keys() { return this.values.keys(); }
  valuesIterator() { return this.values.values(); }
  [Symbol.iterator]() { return this.entries(); }
}

class RequestPolyfill {
  constructor(input, init = {}) {
    this.url = String(input instanceof RequestPolyfill ? input.url : input);
    this.method = String(init.method || (input instanceof RequestPolyfill ? input.method : "GET")).toUpperCase();
    this.headers = new HeadersPolyfill(init.headers || (input instanceof RequestPolyfill ? input.headers : undefined));
    this._body = init.body === undefined || init.body === null ? "" : String(init.body);
  }

  async text() { return this._body; }
  async json() { return JSON.parse(this._body); }
  clone() { return new RequestPolyfill(this.url, { method: this.method, headers: this.headers, body: this._body }); }
}

class ResponsePolyfill {
  constructor(body = "", init = {}) {
    this.status = Number(init.status || 200);
    this.statusText = init.statusText || "";
    this.headers = new HeadersPolyfill(init.headers);
    this._body = body === undefined || body === null ? "" : String(body);
    this.ok = this.status >= 200 && this.status < 300;
  }

  async text() { return this._body; }
  async json() { return JSON.parse(this._body); }

  static json(value, init = {}) {
    const headers = new HeadersPolyfill(init.headers);
    if (!headers.has("content-type")) headers.set("content-type", "application/json; charset=utf-8");
    return new ResponsePolyfill(JSON.stringify(value), { ...init, headers });
  }
}

function uuid() {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const value = bytes.toString("hex");
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

export function installWebApiPolyfill() {
  if (!globalThis.Headers) globalThis.Headers = HeadersPolyfill;
  if (!globalThis.Request) globalThis.Request = RequestPolyfill;
  if (!globalThis.Response) globalThis.Response = ResponsePolyfill;
  if (!globalThis.crypto) {
    globalThis.crypto = {
      randomUUID: uuid,
      subtle: {
        async digest(algorithm, bytes) {
          const normalized = String(typeof algorithm === "string" ? algorithm : algorithm.name).replace("-", "").toLowerCase();
          const digest = createHash(normalized).update(Buffer.from(bytes)).digest();
          return digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength);
        },
      },
    };
  }
  if (!globalThis.TextEncoder) {
    globalThis.TextEncoder = class TextEncoderPolyfill {
      encode(value) { return Uint8Array.from(Buffer.from(String(value), "utf8")); }
    };
  }
}

export { HeadersPolyfill, RequestPolyfill, ResponsePolyfill };
