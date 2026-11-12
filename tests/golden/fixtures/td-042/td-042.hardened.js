const { execFile } = require('child_process');

app.post('/thumbnail', (req, res) => {
  execFile('convert', [req.body.filename, '-resize', '200x200', 'out.png'], (err) => {
    res.send(err ? 'failed' : 'ok');
  });
});
