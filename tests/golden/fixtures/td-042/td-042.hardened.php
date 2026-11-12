<?php

// ✅ HARDENED: no shell command — use an in-process image library instead.
$filename = $_GET['filename'];
$image = new Imagick($filename);
$image->thumbnailImage(200, 200);
$image->writeImage('out.png');
