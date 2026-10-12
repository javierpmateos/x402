import type { HttpPaymentCall } from "@x402/core/types";

/**
 * Returns the reason an aborted signal carries, or a standard AbortError.
 *
 * @param signal - An aborted signal
 * @returns The abort reason
 */
function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
}

/**
 * Reads a body stream to the end. Rejects as soon as any signal aborts, also
 * while a read is pending, and cancels the stream so its source stops.
 *
 * @param stream - The body stream
 * @param signals - Signals that abort the read
 * @returns The body bytes
 */
async function readStream(
  stream: ReadableStream<Uint8Array>,
  signals: AbortSignal[],
): Promise<Uint8Array> {
  const already = signals.find(signal => signal.aborted);
  if (already) throw abortReason(already);

  const reader = stream.getReader();
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => {
      const signal = signals.find(s => s.aborted);
      const reason = signal ? abortReason(signal) : new Error("aborted");
      reject(reason);
      reader.cancel(reason).catch(() => undefined);
    };
  });
  aborted.catch(() => undefined);
  for (const signal of signals) signal.addEventListener("abort", onAbort!, { once: true });

  try {
    const chunks: Uint8Array[] = [];
    let length = 0;
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), aborted]);
      if (done) break;
      chunks.push(value);
      length += value.byteLength;
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    for (const signal of signals) signal.removeEventListener("abort", onAbort!);
  }
}

/**
 * Describes a fetch request as the call a payment is created for.
 *
 * Method, URL and headers are captured now, before any payment header is
 * added. The body is not touched until a scheme calls `getBody`: only then is
 * `bodySource` invoked to obtain a request whose body can be consumed, so a
 * client whose schemes never bind the body pays no extra clone or read. The
 * first read is shared by later calls, which receive their own copy of the
 * bytes; a failed or aborted read stays failed rather than being retried on a
 * partially consumed stream. The read stops when the request's own signal or
 * the signal passed to `getBody` aborts.
 *
 * @param request - The original request
 * @param bodySource - Returns a request whose body may be consumed
 * @returns The HTTP payment call
 */
export function httpPaymentCall(request: Request, bodySource: () => Request): HttpPaymentCall {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, name) => {
    headers[name] = value;
  });

  const call: HttpPaymentCall = { kind: "http", method: request.method, url: request.url, headers };
  if (request.body === null) return call;

  let read: Promise<Uint8Array> | undefined;
  call.getBody = (signal?: AbortSignal) => {
    if (!read) {
      read = (async () => {
        const signals = signal ? [request.signal, signal] : [request.signal];
        const already = signals.find(s => s.aborted);
        if (already) throw abortReason(already);
        const source = bodySource();
        if (source.bodyUsed) throw new Error("request_body_already_used");
        if (source.body === null) return new Uint8Array(0);
        return readStream(source.body, signals);
      })();
      read.catch(() => undefined);
    }
    return read.then(bytes => bytes.slice());
  };
  return call;
}
