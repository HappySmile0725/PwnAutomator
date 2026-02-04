const fs = require('fs').promises;
const { existsSync } = require('fs');
const path = require('path');

const recentData = path.join(__dirname, '..', '..', 'data', 'recent.json');

const getRecentData = async () => {
    if (!existsSync(recentData)) {
        const dir = path.dirname(recentData);
        await fs.mkdir(dir, { recursive: true });
        await fs.writeFile(recentData, '[]', 'utf8');
    }

    const data = await fs.readFile(recentData, 'utf8');
    const parsed = JSON.parse(data);
    if (Array.isArray(parsed) && parsed.length === 0) {
        return null;
    }
    return parsed;
};

module.exports = { getRecentData };
