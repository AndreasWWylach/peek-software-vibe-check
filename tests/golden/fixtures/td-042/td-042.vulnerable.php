<?php

$filename = $_GET['filename'];
system("convert $filename -resize 200x200 out.png");
