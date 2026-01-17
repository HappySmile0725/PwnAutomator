const fs = require('fs');
const path = require('path');
const Docker = require('dockerode');
const { setRunActive } = require('./runtimeState');

const aiDataPath = path.join(__dirname, '..', '..', '..', 'data', 'ai.json');
const dockerClient = new Docker();
const containerName = 'chal';

const isContainerRunning = async () => {
    const container = dockerClient.getContainer(containerName);
    return container
        .inspect()
        .then((info) => Boolean(info?.State?.Running))
        .catch(() => false);
};

const getAIData = async () => {
    let parsed = {};
    try {
        const raw = fs.readFileSync(aiDataPath, 'utf8');
        parsed = JSON.parse(raw);
    } catch (error) {
        parsed = {};
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        parsed = {};
    }

    const running = await isContainerRunning();
    if (!running) {
        setRunActive(false);
    }

    const status = running ? 'operational' : 'Nothing';

    return { ...parsed, status, containerRunning: running };
};

module.exports = { getAIData };
