// Golden fixture: eval hygiene rules must fire on dynamic code execution.
const sum = eval('2 + 2');
const double = new Function('a', 'return a * 2');
