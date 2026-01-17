const fs = require('fs');
const path = require('path');

const aiDataPath = path.join(__dirname, '..', '..', '..', 'data', 'ai.json');

const getTrackData = async () => {
    try {
        const raw = fs.readFileSync(aiDataPath, 'utf8');
        const parsed = JSON.parse(raw);
        const files = Array.isArray(parsed.files) ? parsed.files : [];
        const output = Array.isArray(parsed.output) ? parsed.output : [];
        return { files, output, ...parsed };
    } catch (error) {
        return { files: [], output: [] };
    }
};

module.exports = { getTrackData };
