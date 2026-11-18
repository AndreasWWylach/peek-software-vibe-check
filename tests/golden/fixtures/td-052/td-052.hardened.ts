import { collection, onSnapshot } from 'firebase/firestore';

// Read-only listener: render from the snapshot in place, never write back.
export function watchMessages(db: any) {
  onSnapshot(collection(db, 'messages'), (snap) => {
    const unread = snap.docs.filter((doc) => !doc.data().read).length;
    paintUnreadBadge(unread);
  });
}

function paintUnreadBadge(count: number) {
  // In-place DOM update — no route re-render, no write.
  void count;
}
