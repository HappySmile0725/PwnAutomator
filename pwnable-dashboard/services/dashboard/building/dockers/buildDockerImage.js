const fs = require('fs');
const path = require('path');
const Docker = require('dockerode');

const dockerClient = new Docker();

const collectContextFiles = (currentDir, baseDir, out) => {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
            collectContextFiles(fullPath, baseDir, out);
            continue;
        }
        if (!entry.isFile()) {
            continue;
        }
        out.push(path.relative(baseDir, fullPath));
    }
};

const getContextFiles = (contextDir) => {
    const files = [];
    collectContextFiles(contextDir, contextDir, files);
    return files;
};

const buildDockerImage = async (contextDir, dockerfilePath, imageTag, onLog) => {
    const src = getContextFiles(contextDir);
    if (src.length === 0) {
        return Promise.reject(new Error('Build context is empty.'));
    }
    const tarStream = await dockerClient.buildImage({
        context: contextDir,
        src
    }, {
        t: imageTag,
        dockerfile: dockerfilePath
    });
    return new Promise((resolve, reject) => {
        const output = [];
        dockerClient.modem.followProgress(tarStream, (err, res) => {
            if (err) {
                return reject(err);
            }
            const failed = (res || []).find((item) => item?.error || item?.errorDetail?.message);
            if (failed) {
                return reject(new Error(failed.error || failed.errorDetail.message));
            }
            return resolve(res);
        }, (event) => {
            output.push(event);
            const streamText = event?.stream || '';
            const errorText = event?.error || '';
            if (streamText) {
                process.stdout.write(streamText);
            }
            if (errorText) {
                process.stderr.write(errorText);
            }
            const logText = streamText || errorText;
            if (logText && typeof onLog === 'function') {
                const lines = logText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
                for (const line of lines) {
                    onLog(line);
                }
            }
        });
    });
};

module.exports = { buildDockerImage };
