const hardware = require('./hardware.service')
const recentData = require('./recent.service')
const statisticData = require('./statistic.service')

const getDashboardData = async () => {
    const hwStatus = await hardware.getHardwareStatus();
    const recentStatus = await recentData.getRecentData();
    const statistics = await statisticData.getStatisticData();

    if (!hwStatus) {
        return null;
    }

    return {
        hardware: hwStatus,
        recent: recentStatus,
        statistics
    };
}

module.exports = { getDashboardData };
