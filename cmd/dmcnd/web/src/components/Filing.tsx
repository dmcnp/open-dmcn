import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { Button, Dialog, Input } from '../ds';
import { ColorSwatches } from './ColorSwatches';
import { Icon } from './Icon';
import { useMessages, type Preview } from '../lib/hooks/useMessages';
import { useFlags } from '../lib/hooks/useFlags';
import { useLabels, LABEL_COLORS } from '../lib/hooks/useLabels';
import { useSettings } from '../lib/hooks/useSettings';
import { useMailFilter } from '../lib/hooks/useMailFilter';
import { useAuth } from '../lib/hooks/useAuth';
import { useContacts } from '../lib/hooks/useContacts';
import { useUndo } from '../lib/hooks/useUndo';
import { lookupIdentity } from '../lib/api/client';
import { directoryKey } from '../lib/trust/senderKind';
import { controlSubjects } from '../lib/unread';
import { placeOf, type Place, type PlaceContext } from '../lib/mailView';
import {
  asksAboutSender, autoFilingCandidates, filingChoices, filingDelta, filingSender, normalizedAddress,
  restoreRule, ruleFor, rulesOf, sameSenderMail, unfilingDelta, withoutRule, withRule,
  type Fileable, type FilingRule, type SwipeFiling,
} from '../lib/filing';

// Filing for the whole mail shell: moving a message to a folder or back to the Inbox, the question
// about the sender's other mail, labels from a row, Undo after a move, delete or archive, and the
// sender rules that file new mail as it arrives. The Apple client does the same with the same
// synced settings (lib/filing.ts), so either one can make a rule and both apply it.
//
// Rows, the reader and swipes all call in here, so the question and the Undo bar read the same
// wherever the move began.

interface FilingContextValue {
  /** Where a message lives now, or null for what filing can't see (Sent, control mail). */
  placeOfMessage: (m: Preview) => Place | null;
  /** "Inbox", "Archive", a folder's name. */
  placeName: (p: Place) => string;
  /** The folder picker's choices for a message. */
  choices: (m: Preview) => { includeInbox: boolean; folders: { id: string; name: string }[] };
  /** Moves a message to a folder, or to the Inbox with undefined. May ask about the sender first. */
  file: (m: Preview, folderId: string | undefined) => void;
  /** Asks for a folder name, makes the folder, and files the message in it. */
  newFolderFor: (m: Preview) => void;
  /** Opens the folder list in a dialog: what a full swipe right does on the phone, where a web page
   *  can't open the phone's own picker without a tap on it. */
  pickFolderFor: (m: Preview) => void;
  /** Asks for a label name and colour, makes the label, and puts it on the message. */
  newLabelFor: (m: Preview) => void;
  /** Puts a label on, or takes it off. */
  toggleLabel: (m: Preview, labelId: string) => void;
  /** Moves to Deleted, with Undo. */
  trashWithUndo: (hashes: string[]) => Promise<void>;
  /** Archives or brings back from Archive, with Undo. */
  setArchivedWithUndo: (hashes: string[], archived: boolean) => Promise<void>;
}

const FilingContext = createContext<FilingContextValue | null>(null);

/** The question that "always" answers, held until the owner answers it. */
interface Offer {
  message: Preview;
  sender: string;
  senderName: string;
  folderId: string | undefined;
  folderName: string;
  fromName: string;
  others: string[];
}

type Naming = { kind: 'folder' | 'label'; message: Preview } | null;

function offerText(o: Offer) {
  const toInbox = o.folderId === undefined;
  const title = toInbox ? `Move mail from ${o.senderName} back to the Inbox?` : `Move mail from ${o.senderName} to ${o.folderName}?`;
  const answer = toInbox ? 'Always use the Inbox' : `Always move to ${o.folderName}`;
  const later = toInbox
    ? `new mail from ${o.senderName} will arrive in the Inbox again.`
    : `new mail from ${o.senderName} will go there automatically.`;
  const there = `from ${o.senderName} in ${o.fromName}`;
  const summary = o.others.length === 0 ? `From now on, ${later}`
    : o.others.length === 1 ? `1 other message ${there} will move there now, and ${later}`
    : `${o.others.length} other messages ${there} will move there now, and ${later}`;
  return { title, answer, summary };
}

export function FilingProvider({ children }: { children: ReactNode }) {
  const { messages, loaded: mailLoaded } = useMessages();
  const { flags, synced: flagsSynced, setFlag, trash } = useFlags();
  const { folders, knownFolderIds, ready: labelsReady, folderById, createFolder, createLabel } = useLabels();
  const { settings, loaded: settingsLoaded, changeSettings } = useSettings();
  const { filter, ready: filterReady } = useMailFilter();
  const { address } = useAuth();
  const { nameFor } = useContacts();
  const { offerUndo } = useUndo();

  const swipeFiling: SwipeFiling | undefined = settings.swipeFiling;
  const control = controlSubjects();
  const ctx: PlaceContext = { address, flags, filter, control, knownFolderIds };
  // The latest of each, for the callbacks that run after a wait (the directory, the question).
  const live = useRef({ ctx, messages, flags, swipeFiling });
  live.current = { ctx, messages, flags, swipeFiling };

  const [offer, setOffer] = useState<Offer | null>(null);
  const [naming, setNaming] = useState<Naming>(null);
  const [picking, setPicking] = useState<Preview | null>(null);
  const [newName, setNewName] = useState('');
  const [newColor, setNewColor] = useState(LABEL_COLORS[0]);
  const [nameBusy, setNameBusy] = useState(false);
  const [nameErr, setNameErr] = useState('');

  const placeName = useCallback((p: Place): string => {
    if (p.startsWith('folder:')) return folderById(p.slice('folder:'.length))?.name ?? 'a folder';
    return p === 'inbox' ? 'Inbox' : p === 'archive' ? 'Archive' : p === 'sent' ? 'Sent' : 'Deleted';
  }, [folderById]);
  const folderName = (id: string | undefined) => (id ? folderById(id)?.name ?? 'a folder' : 'the Inbox');

  const placeOfMessage = (m: Preview) => placeOf(m, ctx);
  const choices = (m: Preview) => filingChoices(placeOf(m, ctx), folders);

  // Moves by hand, with Undo: each message goes back to where it was, Archive included. `rule` is
  // the sender's rule before an "always", which Undo puts back.
  const moveWithUndo = useCallback(async (hashes: string[], folderId: string | undefined, rule?: { sender: string; before: FilingRule | undefined }) => {
    const before = new Map(hashes.map(h => [h, live.current.flags.get(h)]));
    const delta = filingDelta(folderId);
    await Promise.all(hashes.map(h => setFlag(h, delta).catch(() => { /* the next sync shows it */ })));
    const place = folderName(folderId);
    offerUndo(hashes.length > 1 ? `Moved ${hashes.length} messages to ${place}` : `Moved to ${place}`, async () => {
      await Promise.all([...before].map(([h, f]) => setFlag(h, unfilingDelta(f)).catch(() => {})));
      if (rule) await changeSettings(cur => ({ swipeFiling: restoreRule(cur.swipeFiling, rule.before, rule.sender) }));
    });
  }, [setFlag, offerUndo, changeSettings, folderById]);

  // Asks first whether the rest of the sender's mail should follow, and moves nothing until
  // answered. Files straight away when the owner turned the question off, or there is nothing to
  // ask: a sender filing can't follow, one a rule already files there, or (for the Inbox) no rule
  // and nothing else to move.
  const file = useCallback((m: Preview, folderId: string | undefined) => {
    if (!asksAboutSender(live.current.swipeFiling)) { void moveWithUndo([m.hash], folderId); return; }
    const addr = normalizedAddress(m.senderAddress);
    void directoryKey(addr, lookupIdentity).then(dirKey => {
      const { ctx: c, messages: all, swipeFiling: sf } = live.current;
      const senderOf = (o: Fileable) => filingSender(o, normalizedAddress(o.senderAddress) === addr ? dirKey : null);
      const sender = senderOf(m);
      if (!sender) { void moveWithUndo([m.hash], folderId); return; }
      const rule = ruleFor(sf, sender);
      const others = sameSenderMail(m, folderId, all, c, senderOf);
      if (folderId && rule?.folderId === folderId) { void moveWithUndo([m.hash], folderId); return; }
      if (!folderId && !rule && others.length === 0) { void moveWithUndo([m.hash], folderId); return; }
      const from = placeOf(m, c);
      setOffer({
        message: m, sender, senderName: nameFor(m.senderAddress), folderId,
        folderName: folderName(folderId),
        fromName: !from || from === 'inbox' ? 'the Inbox' : placeName(from),
        others,
      });
    });
  }, [moveWithUndo, nameFor, placeName]);

  // Always: this message and the sender's other mail move now, and from here on their new mail is
  // filed there by a rule, or, for the Inbox, simply isn't filed any more.
  const acceptOffer = async (o: Offer) => {
    setOffer(null);
    const before = ruleFor(live.current.swipeFiling, o.sender);
    await moveWithUndo([o.message.hash, ...o.others], o.folderId, { sender: o.sender, before });
    const now = Math.floor(Date.now() / 1000);
    await changeSettings(cur => ({
      swipeFiling: o.folderId ? withRule(cur.swipeFiling, o.sender, o.folderId, now) : withoutRule(cur.swipeFiling, o.sender),
    })).catch(() => { /* the rule is not saved; the move stands */ });
  };
  const justThisOne = (o: Offer) => { setOffer(null); void moveWithUndo([o.message.hash], o.folderId); };

  const toggleLabel = useCallback((m: Preview, labelId: string) => {
    const cur = live.current.flags.get(m.hash)?.labelIds ?? [];
    const next = cur.includes(labelId) ? cur.filter(id => id !== labelId) : [...cur, labelId];
    void setFlag(m.hash, { labelIds: next }).catch(() => {});
  }, [setFlag]);

  const trashWithUndo = useCallback(async (hashes: string[]) => {
    const before = new Map(hashes.map(h => [h, live.current.flags.get(h)?.trashedAt]));
    await Promise.all(hashes.map(h => trash(h).catch(() => {})));
    offerUndo('Moved to Deleted', async () => {
      await Promise.all([...before].map(([h, t]) => setFlag(h, { trashedAt: t }).catch(() => {})));
    });
  }, [trash, setFlag, offerUndo]);

  const setArchivedWithUndo = useCallback(async (hashes: string[], archived: boolean) => {
    const before = new Map(hashes.map(h => [h, live.current.flags.get(h)?.archived]));
    await Promise.all(hashes.map(h => setFlag(h, { archived }).catch(() => {})));
    offerUndo(archived ? 'Archived' : 'Moved out of Archive', async () => {
      await Promise.all([...before].map(([h, a]) => setFlag(h, { archived: a }).catch(() => {})));
    });
  }, [setFlag, offerUndo]);

  const beginNaming = (kind: 'folder' | 'label', message: Preview) => {
    setNaming({ kind, message }); setNewName(''); setNewColor(LABEL_COLORS[0]); setNameErr('');
  };
  const confirmNaming = async () => {
    const n = newName.trim();
    if (!naming || !n) return;
    setNameBusy(true); setNameErr('');
    try {
      if (naming.kind === 'folder') {
        const id = await createFolder(n);
        setNaming(null);
        file(naming.message, id);
      } else {
        const id = await createLabel(n, newColor);
        setNaming(null);
        toggleLabel(naming.message, id);
      }
    } catch (e) {
      setNameErr(e instanceof Error ? e.message : String(e));
    } finally {
      setNameBusy(false);
    }
  };

  // Sender rules, applied to new mail as it arrives in this tab. Waits until every input has
  // really loaded: an untouched message is recognised by having no flag record, so a flag list
  // that failed to load would make every message look untouched.
  const inFlight = useRef(new Set<string>());
  const rules = rulesOf(swipeFiling);
  useEffect(() => {
    if (!mailLoaded || !flagsSynced || !labelsReady || !filterReady || !settingsLoaded || !rules.length) return;
    const due = autoFilingCandidates(messages, rules, ctx).filter(c => !inFlight.current.has(c.hash));
    for (const c of due) {
      inFlight.current.add(c.hash);
      void directoryKey(c.message.senderAddress, lookupIdentity)
        .then(dirKey => {
          // Checked again now the directory has answered: the owner may have touched it meanwhile.
          if (live.current.flags.has(c.hash)) return;
          if (!filingSender(c.message, dirKey)) return;
          return setFlag(c.hash, filingDelta(c.folderId));
        })
        .catch(() => { /* tried again on the next change */ })
        .finally(() => inFlight.current.delete(c.hash));
    }
  // ctx is rebuilt each render from the values listed here.
  }, [messages, flags, swipeFiling, knownFolderIds.size, mailLoaded, flagsSynced, labelsReady, filterReady, settingsLoaded, filter, address]);

  const o = offer ? offerText(offer) : null;
  const value: FilingContextValue = {
    placeOfMessage, placeName, choices, file,
    newFolderFor: m => beginNaming('folder', m),
    pickFolderFor: m => setPicking(m),
    newLabelFor: m => beginNaming('label', m),
    toggleLabel, trashWithUndo, setArchivedWithUndo,
  };

  return (
    <FilingContext.Provider value={value}>
      {children}
      <Dialog
        open={!!offer}
        onClose={() => setOffer(null)}
        title={o?.title}
        footer={offer && o ? (
          <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'flex-end', gap: 'var(--space-2)', width: '100%' }}>
            <Button variant="ghost" onClick={() => setOffer(null)}>Cancel</Button>
            <Button variant="secondary" onClick={() => justThisOne(offer)}>Just this one</Button>
            <Button variant="primary" onClick={() => void acceptOffer(offer)}>{o.answer}</Button>
          </div>
        ) : null}
      >
        {o?.summary}
      </Dialog>
      <Dialog
        open={!!picking}
        onClose={() => setPicking(null)}
        title="Move to folder"
        footer={<Button variant="ghost" onClick={() => setPicking(null)}>Cancel</Button>}
      >
        {picking && (() => {
          const c = choices(picking);
          const pick = (folderId: string | undefined) => { const m = picking; setPicking(null); file(m, folderId); };
          const row = { justifyContent: 'flex-start', width: '100%' } as const;
          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {c.includeInbox && (
                <Button variant="secondary" leftIcon={<Icon name="inbox" size={16} />} onClick={() => pick(undefined)} style={row}>Inbox</Button>
              )}
              {c.folders.map(f => (
                <Button key={f.id} variant="secondary" leftIcon={<Icon name="folder" size={16} />} onClick={() => pick(f.id)} style={row}>{f.name}</Button>
              ))}
              <Button variant="ghost" leftIcon={<Icon name="plus" size={16} />} onClick={() => { const m = picking; setPicking(null); beginNaming('folder', m); }} style={row}>New folder…</Button>
            </div>
          );
        })()}
      </Dialog>
      <Dialog
        open={!!naming}
        onClose={() => setNaming(null)}
        title={naming?.kind === 'label' ? 'New label' : 'New folder'}
        footer={(
          <>
            <Button variant="ghost" onClick={() => setNaming(null)}>Cancel</Button>
            <Button variant="primary" disabled={nameBusy || !newName.trim()} onClick={() => void confirmNaming()}>
              {naming?.kind === 'label' ? 'Add label' : 'Move to new folder'}
            </Button>
          </>
        )}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <Input
            value={newName}
            onChange={e => setNewName(e.target.value)}
            placeholder={naming?.kind === 'label' ? 'Label name' : 'Folder name'}
            aria-label={naming?.kind === 'label' ? 'Label name' : 'Folder name'}
            autoFocus
            onKeyDown={e => { if (e.key === 'Enter') void confirmNaming(); }}
          />
          {naming?.kind === 'label' && <ColorSwatches selected={newColor} onPick={setNewColor} />}
          {nameErr && <div style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)' }}>{nameErr}</div>}
        </div>
      </Dialog>
    </FilingContext.Provider>
  );

}

export function useFiling(): FilingContextValue {
  const ctx = useContext(FilingContext);
  if (!ctx) throw new Error('useFiling must be used within FilingProvider');
  return ctx;
}
