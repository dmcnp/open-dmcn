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
import { controlSubjects } from '../lib/unread';
import { placeOf, type Place, type PlaceContext } from '../lib/mailView';
import {
  SENDER_CHECK_MS, asksAboutSender, autoFilingCandidates, checkSender, filingChoices, filingDelta, filingSender, normalizedAddress,
  restoreRule, ruleFor, rulesOf, sameSenderMail, withoutRule, withRule,
  type Fileable, type SenderCheck, type SwipeFiling,
} from '../lib/filing';
import { moveAlwaysWithUndo, moveWithUndo, setArchivedWithUndo, trashWithUndo, type ActionDeps } from '../lib/filingActions';

// Filing for the whole mail shell: moving a message to a folder or back to the Inbox, the question
// about the sender's other mail, labels from a row, Undo after a move, delete or archive, and the
// sender rules that file new mail as it arrives. The Apple client does the same with the same
// synced settings (lib/filing.ts), so either one can make a rule and both apply it. The steps of
// each action, and what Undo restores, are in lib/filingActions.ts.
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
  /**
   * Moves a message to a folder, or to the Inbox with undefined. May ask about the sender first.
   * `folderName` names a folder made a moment ago, which the folder list may not hold yet.
   */
  file: (m: Preview, folderId: string | undefined, folderName?: string) => void;
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

/**
 * The question that "always" answers, held until the owner answers it. What it would move with the
 * message is not kept here: it is worked out from the mail as it is when the question shows and
 * again when it is answered, since a question waiting in line can outlive the state it was asked
 * in (an earlier answer may have moved some of that mail somewhere else).
 */
interface Offer {
  message: Preview;
  sender: string;
  senderName: string;
  check: SenderCheck;
  folderId: string | undefined;
  folderName: string;
}

type Naming = { kind: 'folder' | 'label'; message: Preview } | null;

function offerText(o: Offer, others: string[], fromName: string) {
  const toInbox = o.folderId === undefined;
  const title = toInbox ? `Move mail from ${o.senderName} back to the Inbox?` : `Move mail from ${o.senderName} to ${o.folderName}?`;
  const answer = toInbox ? 'Always use the Inbox' : `Always move to ${o.folderName}`;
  const later = toInbox
    ? `new mail from ${o.senderName} will arrive in the Inbox again.`
    : `new mail from ${o.senderName} will go there automatically.`;
  const there = `from ${o.senderName} in ${fromName}`;
  const summary = others.length === 0 ? `From now on, ${later}`
    : others.length === 1 ? `1 other message ${there} will move there now, and ${later}`
    : `${others.length} other messages ${there} will move there now, and ${later}`;
  return { title, answer, summary };
}

export function FilingProvider({ children }: { children: ReactNode }) {
  const { messages, loaded: mailLoaded } = useMessages();
  const { flags, synced: flagsSynced, setFlag, setFlagIfAbsent } = useFlags();
  const { folders, knownFolderIds, ready: labelsReady, folderById, createFolder, createLabel } = useLabels();
  const { settings, loaded: settingsLoaded, changeSettings } = useSettings();
  const { filter, ready: filterReady } = useMailFilter();
  const { address } = useAuth();
  const { nameFor } = useContacts();
  const { offerUndo } = useUndo();

  const swipeFiling: SwipeFiling | undefined = settings.swipeFiling;
  const control = controlSubjects();
  const ctx: PlaceContext = { address, flags, filter, control, knownFolderIds };
  // The latest of each, for the callbacks that run after a wait (the directory, the question):
  // a closure made before the wait would hold the values from before it.
  const live = useRef({ ctx, messages, flags, swipeFiling, address, folderById });
  live.current = { ctx, messages, flags, swipeFiling, address, folderById };
  // The directory's definite answers about senders, for this tab. Failures are not kept.
  const senderCache = useRef(new Map<string, SenderCheck>());
  const senderPending = useRef(new Map<string, Promise<SenderCheck>>());
  const askDirectory = (a: string) =>
    checkSender(a, lookupIdentity, senderCache.current, SENDER_CHECK_MS, senderPending.current);

  // Questions wait in line, so moving a second message before the first one's question is
  // answered asks both, in order, instead of dropping one.
  const [offers, setOffers] = useState<Offer[]>([]);
  const offer = offers[0] ?? null;
  const [naming, setNaming] = useState<Naming>(null);
  const [picking, setPicking] = useState<Preview | null>(null);
  const [newName, setNewName] = useState('');
  const [newColor, setNewColor] = useState(LABEL_COLORS[0]);
  const [nameBusy, setNameBusy] = useState(false);
  const [nameErr, setNameErr] = useState('');

  // Nothing waits across accounts: a question about one mailbox is never answered in another.
  useEffect(() => { setOffers([]); setPicking(null); setNaming(null); }, [address]);

  const placeName = useCallback((p: Place): string => {
    if (p.startsWith('folder:')) return folderById(p.slice('folder:'.length))?.name ?? 'a folder';
    return p === 'inbox' ? 'Inbox' : p === 'archive' ? 'Archive' : p === 'sent' ? 'Sent' : 'Deleted';
  }, [folderById]);
  const folderLabel = (id: string | undefined, given?: string) =>
    (id ? given ?? live.current.folderById(id)?.name ?? 'a folder' : 'the Inbox');

  const placeOfMessage = (m: Preview) => placeOf(m, ctx);
  const choices = (m: Preview) => filingChoices(placeOf(m, ctx), folders);

  const deps = useCallback((): ActionDeps => ({
    setFlag,
    flagOf: h => live.current.flags.get(h),
    notify: offerUndo,
    account: () => live.current.address,
  }), [setFlag, offerUndo]);

  // Asks first whether the rest of the sender's mail should follow, and moves nothing until
  // answered. Moves straight away when the owner turned the question off, or there is nothing to
  // ask: a sender filing can't follow (including one the directory couldn't be asked about within
  // a few seconds), one a rule already files there, or (for the Inbox) no rule and nothing else to
  // move.
  const file = useCallback((m: Preview, folderId: string | undefined, givenName?: string) => {
    const place = folderLabel(folderId, givenName);
    const moveOne = () => { void moveWithUndo(deps(), [m.hash], folderId, place); };
    if (!asksAboutSender(live.current.swipeFiling)) { moveOne(); return; }
    const account = live.current.address;
    const addr = normalizedAddress(m.senderAddress);
    void askDirectory(addr).then(check => {
      if (live.current.address !== account) return; // another account now: nothing moves
      const { ctx: c, messages: all, swipeFiling: sf } = live.current;
      const senderOf = (o: Fileable) => filingSender(o, normalizedAddress(o.senderAddress) === addr ? check : 'unchecked');
      const sender = senderOf(m);
      if (!sender) { moveOne(); return; }
      const rule = ruleFor(sf, sender);
      const others = sameSenderMail(m, folderId, all, c, senderOf);
      if (folderId && rule?.folderId === folderId) { moveOne(); return; }
      if (!folderId && !rule && others.length === 0) { moveOne(); return; }
      const next: Offer = { message: m, sender, senderName: nameFor(m.senderAddress), check, folderId, folderName: place };
      setOffers(q => [...q.filter(x => x.message.hash !== m.hash), next]);
    });
  // folderLabel reads the live ref, so it needs no dependency of its own.
  }, [deps, nameFor, placeName]);

  // The sender's other mail the question would move, and where it is, from the mail as it is now.
  const othersFor = (o: Offer) => {
    const { ctx: c, messages: all } = live.current;
    const addr = normalizedAddress(o.message.senderAddress);
    const senderOf = (x: Fileable) => filingSender(x, normalizedAddress(x.senderAddress) === addr ? o.check : 'unchecked');
    return sameSenderMail(o.message, o.folderId, all, c, senderOf);
  };
  const fromNameOf = (o: Offer) => {
    const from = placeOf(o.message, live.current.ctx);
    return !from || from === 'inbox' ? 'the Inbox' : placeName(from);
  };

  // Takes an answered question out of the line. Once its move is done, later questions about
  // messages it actually moved go too; one about a message whose move failed stays.
  const answered = (o: Offer) => setOffers(q => q.filter(x => x !== o));
  const movedAway = (done: string[]) => setOffers(q => q.filter(x => !done.includes(x.message.hash)));

  // Always: this message and the sender's other mail move now, and from here on their new mail is
  // filed there by a rule, or, for the Inbox, simply isn't filed any more.
  const acceptOffer = (o: Offer) => {
    const hashes = [o.message.hash, ...othersFor(o)];
    answered(o);
    const before = ruleFor(live.current.swipeFiling, o.sender);
    const now = Math.floor(Date.now() / 1000);
    void moveAlwaysWithUndo(deps(), hashes, o.folderId, o.folderName,
      () => changeSettings(cur => ({
        swipeFiling: o.folderId ? withRule(cur.swipeFiling, o.sender, o.folderId, now) : withoutRule(cur.swipeFiling, o.sender),
      })),
      () => changeSettings(cur => ({ swipeFiling: restoreRule(cur.swipeFiling, before, o.sender) })),
    ).then(r => movedAway(r.done));
  };
  const justThisOne = (o: Offer) => {
    answered(o);
    void moveWithUndo(deps(), [o.message.hash], o.folderId, o.folderName).then(r => movedAway(r.done));
  };
  const cancelOffer = (o: Offer) => answered(o);

  const toggleLabel = useCallback((m: Preview, labelId: string) => {
    const cur = live.current.flags.get(m.hash)?.labelIds ?? [];
    const next = cur.includes(labelId) ? cur.filter(id => id !== labelId) : [...cur, labelId];
    void setFlag(m.hash, { labelIds: next }).catch(() =>
      offerUndo("Couldn't change the labels. Check your connection and try again."));
  }, [setFlag, offerUndo]);

  const trash = useCallback(async (hashes: string[]) => { await trashWithUndo(deps(), hashes, Date.now()); }, [deps]);
  const archive = useCallback(async (hashes: string[], archived: boolean) => {
    await setArchivedWithUndo(deps(), hashes, archived);
  }, [deps]);

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
        // The name goes with it: the folder list here is from before the folder existed.
        file(naming.message, id, n);
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
  // that failed to load would make every message look untouched. Each write first checks the
  // store itself for a record (setFlagIfAbsent), so mail another device has just read or starred
  // isn't reset. A sender the directory couldn't be asked about isn't filed; the next change to
  // the mail or the flags tries again.
  const inFlight = useRef(new Set<string>());
  const rules = rulesOf(swipeFiling);
  useEffect(() => {
    if (!mailLoaded || !flagsSynced || !labelsReady || !filterReady || !settingsLoaded || !rules.length) return;
    const account = address;
    const due = autoFilingCandidates(messages, rules, ctx).filter(c => !inFlight.current.has(c.hash));
    for (const c of due) {
      inFlight.current.add(c.hash);
      void askDirectory(c.message.senderAddress)
        .then(check => {
          if (live.current.address !== account || live.current.flags.has(c.hash)) return false;
          if (!filingSender(c.message, check)) return false;
          return setFlagIfAbsent(c.hash, filingDelta(c.folderId));
        })
        .catch(() => { /* tried again on the next change */ })
        .finally(() => inFlight.current.delete(c.hash));
    }
  // ctx is rebuilt each render from the values listed here.
  }, [messages, flags, swipeFiling, knownFolderIds.size, mailLoaded, flagsSynced, labelsReady, filterReady, settingsLoaded, filter, address]);

  const o = offer ? offerText(offer, othersFor(offer), fromNameOf(offer)) : null;
  const value: FilingContextValue = {
    placeOfMessage, placeName, choices, file,
    newFolderFor: m => beginNaming('folder', m),
    pickFolderFor: m => setPicking(m),
    newLabelFor: m => beginNaming('label', m),
    toggleLabel, trashWithUndo: trash, setArchivedWithUndo: archive,
  };

  return (
    <FilingContext.Provider value={value}>
      {children}
      <Dialog
        open={!!offer}
        onClose={() => { if (offer) cancelOffer(offer); }}
        title={o?.title}
        footer={offer && o ? (
          <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'flex-end', gap: 'var(--space-2)', width: '100%' }}>
            <Button variant="ghost" onClick={() => cancelOffer(offer)}>Cancel</Button>
            <Button variant="secondary" onClick={() => justThisOne(offer)}>Just this one</Button>
            <Button variant="primary" onClick={() => acceptOffer(offer)}>{o.answer}</Button>
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
