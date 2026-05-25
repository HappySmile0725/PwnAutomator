const fs = require('fs').promises;
const path = require('path');

const recentData = path.join(__dirname, '..', '..', 'data', 'recent.json');

const getRecentData = async () => {
    try {
        const data = await fs.readFile(recentData, 'utf8');
        const parsed = JSON.parse(data || '[]');
        return Array.isArray(parsed) && parsed.length > 0 ? parsed : null;
    } catch (error) {
        if (error.code === 'ENOENT') {
            return null;
        }
        throw error;
    }
};

module.exports = { getRecentData };
