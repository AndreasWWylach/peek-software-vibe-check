// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

const { execFile } = require('child_process');

app.post('/thumbnail', (req, res) => {
  execFile('convert', [req.body.filename, '-resize', '200x200', 'out.png'], (err) => {
    res.send(err ? 'failed' : 'ok');
  });
});
