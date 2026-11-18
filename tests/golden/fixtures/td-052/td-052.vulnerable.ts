import { collection, onSnapshot, updateDoc } from 'firebase/firestore';

// A listener that writes back to the collection it observes: each snapshot
// mutates docs, which re-fires the listener → an unbounded read/write loop.
export function watchMessages(db: any) {
  onSnapshot(collection(db, 'messages'), (snap) => {
    snap.docs.forEach((doc) => updateDoc(doc.ref, { read: true }));
  });
}
