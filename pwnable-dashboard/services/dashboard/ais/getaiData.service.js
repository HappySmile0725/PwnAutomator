const fs = require('fs');
const path = require('path');

const aiDataPath = path.join(__dirname, '..', '..', '..', 'data', 'ai.json');

const getAIData = async () => {
    const raw = fs.readFileSync(aiDataPath, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return { status: 'nothing' };
    }
    return { status: 'nothing', ...parsed };

};

module.exports = { getAIData };
