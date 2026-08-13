import fs from 'fs';
import path from 'path';
import { PolicyEngine } from './engine.js';
import { PolicyConfig } from '../types.js';

export interface PolicyWatcherOptions {
  policyPath: string;
  engine: PolicyEngine;
  onReload?: (newPolicy: PolicyConfig) => void;
  onError?: (error: Error) => void;
}

export class PolicyWatcher {
  private watcher?: fs.FSWatcher;
  private policyPath: string;
  private engine: PolicyEngine;
  private onReload?: (newPolicy: PolicyConfig) => void;
  private onError?: (error: Error) => void;

  constructor(options: PolicyWatcherOptions) {
    this.policyPath = path.resolve(options.policyPath);
    this.engine = options.engine;
    this.onReload = options.onReload;
    this.onError = options.onError;
  }

  public start(): void {
    if (this.watcher) return;

    if (!fs.existsSync(this.policyPath)) {
      const err = new Error(`Policy file not found at path: ${this.policyPath}`);
      if (this.onError) this.onError(err);
      return;
    }

    this.watcher = fs.watch(this.policyPath, (eventType) => {
      if (eventType === 'change' || eventType === 'rename') {
        this.reload();
      }
    });
  }

  public reload(): boolean {
    try {
      if (!fs.existsSync(this.policyPath)) {
        return false;
      }
      const raw = fs.readFileSync(this.policyPath, 'utf-8');
      const parsed = JSON.parse(raw) as PolicyConfig;

      this.engine.updatePolicy(parsed);

      if (this.onReload) {
        this.onReload(parsed);
      }
      return true;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (this.onError) {
        this.onError(error);
      }
      return false;
    }
  }

  public stop(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = undefined;
    }
  }
}
