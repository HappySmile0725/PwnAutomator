const fs = require('fs');
const path = require('path');

const findDockerContext = (baseDir) => {
    if (!fs.existsSync(baseDir)) {
        return null;
    }
    const queue = [baseDir];
    while (queue.length > 0) {
        const currentDir = queue.shift();
        const entries = fs.readdirSync(currentDir, { withFileTypes: true });
        if (entries.some((entry) => entry.isFile() && entry.name === 'Dockerfile')) {
            return currentDir;
        }
        for (const entry of entries) {
            if (entry.isDirectory()) {
                queue.push(path.join(currentDir, entry.name));
            }
        }
    }
    return null;
};

module.exports = { findDockerContext };