// VULNERABLE — multer configured without a fileFilter: every uploaded file
// lands on disk regardless of type.
const multer = require('multer');

// dest-only: no type validation anywhere in the config.
export const uploadAvatar = multer({ dest: 'uploads/avatars/' });

// storage-based: same gap, even with a custom disk destination.
export const uploadDocs = multer({
  storage: multer.diskStorage({ destination: 'uploads/docs/' }),
});
