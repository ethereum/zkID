import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

/** Where a registry's state lives between restarts. */
export interface StateStore<S> {
  /** `undefined` when nothing has been saved yet. */
  load(): Promise<S | undefined>;
  save(state: S): Promise<void>;
}

export class MemoryStore<S> implements StateStore<S> {
  private state: S | undefined;

  constructor(initial?: S) {
    this.state = initial;
  }

  async load(): Promise<S | undefined> {
    return this.state === undefined ? undefined : structuredClone(this.state);
  }

  async save(state: S): Promise<void> {
    this.state = structuredClone(state);
  }
}

/** One JSON file, replaced atomically by writing a temporary file and renaming it. */
export class FileStore<S> implements StateStore<S> {
  constructor(readonly path: string) {}

  async load(): Promise<S | undefined> {
    let text: string;
    try {
      text = await readFile(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
    return JSON.parse(text) as S;
  }

  async save(state: S): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const temporary = `${this.path}.tmp`;
    await writeFile(temporary, JSON.stringify(state), { mode: 0o600 });
    await rename(temporary, this.path);
  }
}
