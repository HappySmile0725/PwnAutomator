const fs = require('fs');
const path = require('path');

const statisticPath = path.join(__dirname, '..', '..', 'data', 'statistic.json');

const getStatisticData = async () => {
    try {
        const data = fs.readFileSync(statisticPath, 'utf8');
        const parsed = JSON.parse(data);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            return { stack: 0, heap: 0, kernel: 0, iot: 0 };
        }
        return {
            stack: Number(parsed.stack) || 0,
            heap: Number(parsed.heap) || 0,
            kernel: Number(parsed.kernel) || 0,
            iot: Number(parsed.iot) || 0
        };
    } catch (error) {
        return { stack: 0, heap: 0, kernel: 0, iot: 0 };
    }
};

module.exports = { getStatisticData };
