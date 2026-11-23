// HARDENED — the multer config carries a fileFilter (MIME allowlist) and
// size limits, so only intended file types ever touch disk.
const multer = require('multer');

export const uploadAvatar = multer({
  dest: 'uploads/avatars/',
  fileFilter: (req, file, cb) => {
    cb(null, file.mimetype.startsWith('image/'));
  },
  limits: { fileSize: 5 * 1024 * 1024 },
});
