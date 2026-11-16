<?php

class OrderFixture
{
    public function total(): float
    {
        return $this->calculateTotl(); // undefined method (typo)
    }
}

$missing = new NonExistentClass(); // undefined class
$result = str_replacee('a', 'b', 'c'); // undefined function
