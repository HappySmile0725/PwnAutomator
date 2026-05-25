const fs = require('fs').promises;
const path = require('path');

const statisticPath = path.join(__dirname, '..', '..', 'data', 'statistic.json');
const defaultStats = { stack: 0, heap: 0, kernel: 0, iot: 0 };

const getStatisticData = async () => {
    try {
        const data = await fs.readFile(statisticPath, 'utf8');
        const parsed = JSON.parse(data);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            return defaultStats;
        }
        return {
            stack: Number(parsed.stack) || 0,
            heap: Number(parsed.heap) || 0,
            kernel: Number(parsed.kernel) || 0,
            iot: Number(parsed.iot) || 0
        };
    } catch (error) {
        if (error.code === 'ENOENT') {
            return defaultStats;
        }
        throw error;
    }
};

module.exports = { getStatisticData };
