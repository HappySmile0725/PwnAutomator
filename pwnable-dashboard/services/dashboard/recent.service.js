const fs = require('fs');
const path = require('path');

const recentData = path.join(__dirname, '..', '..', 'data', 'recent.json');

const getRecentData = async () => {
    const data = fs.readFileSync(recentData, 'utf8');
    const parsed = JSON.parse(data);
    if (Array.isArray(parsed) && parsed.length === 0) {
        return null;
    }
    return parsed;
};

module.exports = { getRecentData };
