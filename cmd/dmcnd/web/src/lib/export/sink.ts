// Where an export's bytes go.
//
// Where the browser can save to a file as it goes (the File System Access API, Chromium on a
// desktop), the export is written there message by message and never held whole. Elsewhere each
// message becomes its own Blob, which the browser is free to keep outside the page's memory, and
// the file is handed over as one download once the last message is in. Either way a cancelled
// export leaves nothing behind: a file being written is discarded, and no download starts.

import { bufferSource } from '../crypto/bytes';

export interface Sink {
  write(bytes: Uint8Array): Promise<void>;
  /** Finish the file: the written one is kept, or the download starts. */
  close(): Promise<void>;
  /** Give up: nothing is kept. */
  abort(): Promise<void>;
  /** True when bytes go to disk as they are written. */
  readonly streaming: boolean;
}

interface WritableLike {
  write(data: BufferSource | Blob): Promise<void>;
  close(): Promise<void>;
  abort(): Promise<void>;
}
type SavePicker = (opts: {
  suggestedName: string;
  types: Array<{ description: string; accept: Record<string, string[]> }>;
}) => Promise<{ createWritable(): Promise<WritableLike> }>;

const MBOX_TYPE = 'application/mbox';

/**
 * openSink asks where to save `filename`, and resolves null when the person closed the save dialog
 * without choosing. Call it straight from the click: the save dialog needs the gesture, and any
 * await before it may use that up.
 */
export async function openSink(filename: string): Promise<Sink | null> {
  const picker = (globalThis as { showSaveFilePicker?: SavePicker }).showSaveFilePicker;
  if (typeof picker !== 'function') return downloadSink(filename);
  let writable: WritableLike;
  try {
    const handle = await picker({ suggestedName: filename, types: [{ description: 'Mailbox (mbox)', accept: { [MBOX_TYPE]: ['.mbox'] } }] });
    writable = await handle.createWritable();
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') return null;
    // Refused for some other reason (a policy, a sandboxed frame): the download still works.
    console.warn('export: cannot save as it goes; collecting the file instead', err);
    return downloadSink(filename);
  }
  return {
    streaming: true,
    write: bytes => writable.write(bufferSource(bytes)),
    close: () => writable.close(),
    abort: () => writable.abort().catch(() => undefined),
  };
}

function downloadSink(filename: string): Sink {
  let parts: Blob[] = [];
  return {
    streaming: false,
    write: async bytes => { parts.push(new Blob([bufferSource(bytes)])); },
    close: async () => {
      const url = URL.createObjectURL(new Blob(parts, { type: MBOX_TYPE }));
      parts = [];
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      // Not at once: a browser still starting the download would find the file gone.
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    },
    abort: async () => { parts = []; },
  };
}

/** exportFilename names a folder's file: the address, the folder and the day. */
export function exportFilename(address: string, folder: string, now: Date = new Date()): string {
  const safe = address.replace(/[^a-z0-9._@-]/gi, '_');
  const day = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  return `dmcn-${safe}-${folder}-${day}.mbox`;
}
