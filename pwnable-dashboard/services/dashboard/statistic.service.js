const fs = require('fs').promises;
const { existsSync } = require('fs');
const path = require('path');

const statisticPath = path.join(__dirname, '..', '..', 'data', 'statistic.json');

const getStatisticData = async () => {
    if (!existsSync(statisticPath)) {
        const dir = path.dirname(statisticPath);
        await fs.mkdir(dir, { recursive: true });
        const defaultData = { stack: 0, heap: 0, kernel: 0, iot: 0 };
        await fs.writeFile(statisticPath, JSON.stringify(defaultData, null, 2), 'utf8');
        return defaultData;
    }

    const data = await fs.readFile(statisticPath, 'utf8');
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
};

module.exports = { getStatisticData };
