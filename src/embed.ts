/**
 * embed.ts — bge-m3 embedder adapter. Primary: @forge/hf (cloud, unlimited,
 * free). Fallback: local bge-server (:8765-style OpenAI-compat) when offline.
 * Both produce 1024-dim vectors; callers treat them as interchangeable.
 */
export interface EmbedAdapter { (inputs: string[]): Promise<number[][]> }

export async function forgeEmbed(inputs: string[]): Promise<number[][]> {
  const hf = await import("/home/toxic/pens/barn/products/forge/hf/hf.ts");
  return hf.embedMany(inputs, { batchSize: 64 });
}

export async function localEmbed(inputs: string[]): Promise<number[][]> {
  // local-bge-server (pens/netrace) OpenAI-compatible embeddings
  const res = await fetch("http://127.0.0.1:8765/v1/embeddings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "bge-m3", input: inputs }),
  });
  if (!res.ok) throw new Error(`local bge http ${res.status}`);
  const j = await res.json() as { data: Array<{ embedding: number[] }> };
  return j.data.map(d => d.embedding);
}

/** Try forge first; on any failure fall back to local. */
export async function embedAuto(inputs: string[]): Promise<number[][]> {
  try { return await forgeEmbed(inputs); }
  catch { return await localEmbed(inputs); }
}

export function cosine(a: number[], b: number[]): number {
  if (a.length !== b.length) throw new Error(`dim mismatch ${a.length} vs ${b.length}`);
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  const d = Math.sqrt(na) * Math.sqrt(nb);
  return d === 0 ? 0 : dot / d;
}
