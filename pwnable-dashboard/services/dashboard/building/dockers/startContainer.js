const Docker = require('dockerode');
const { removeExistingContainer } = require('./removeContainer');

const dockerClient = new Docker();
const containerName = 'chal';

const startContainer = async (imageTag) => {
    await removeExistingContainer();
    const container = await dockerClient.createContainer({
        name: containerName,
        Image: imageTag,
        Tty: true
    });
    await container.start();
    return container;
};

module.exports = { startContainer };
