const fs = require('fs');
const path = require('path');

const readStateFile = (filePath, fallback) => {
    try {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (error) {
        return fallback;
    }
};

const writeStateFile = (filePath, state) => {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(state, null, 2), 'utf8');
    return state;
};

module.exports = {
    readStateFile,
    writeStateFile
};
