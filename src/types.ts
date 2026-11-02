export type AuditEvent = Record<string, any>;

export interface EmbedOptions {
  model?: string;
  batchSize?: number;
  baseUrl?: string;
}

export interface Embedder {
  (inputs: string[]): Promise<number[][]>;
}

export interface CorrelationResult {
  event: AuditEvent;
  doc: string;
  cls: string;
  scores: Record<string, number>;
}

export interface KinPair {
  flagged: CorrelationResult;
  nearest: CorrelationResult;
  score: number;
}

export interface CorrelateOutput {
  results: CorrelationResult[];
  misfits: CorrelationResult[];
  kin: KinPair[];
}
