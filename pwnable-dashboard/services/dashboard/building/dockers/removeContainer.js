const Docker = require('dockerode');

const dockerClient = new Docker();
const containerName = 'chal';

const removeExistingContainer = async () => {
    try {
        const container = dockerClient.getContainer(containerName);
        const info = await container.inspect();
        if (info?.State?.Running) {
            await container.stop({ t: 5 });
        }
        await container.remove({ force: true });
    } catch (error) {
        if (error.statusCode !== 404) {
            throw error;
        }
    }
};

module.exports = { removeExistingContainer };