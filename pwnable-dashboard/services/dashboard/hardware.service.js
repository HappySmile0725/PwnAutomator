const { execFile } = require('child_process');

const execGpuQuery = (command) => new Promise((resolve) => {
    execFile(
        command,
        ['--query-gpu=name,utilization.gpu,memory.used,memory.total', '--format=csv,noheader,nounits'],
        { windowsHide: true },
        (error, stdout) => {
            if (error) {
                return resolve(null);
            }
            return resolve(stdout);
        }
    );
});

const getGpuInfo = async () => {
    const output = await execGpuQuery('nvidia-smi') || await execGpuQuery('nvidia-smi.exe');
    if (!output) {
        return null;
    }

    const lines = output.trim().split(/\r?\n/).filter(Boolean);
    if (lines.length === 0) {
        return null;
    }

    return lines.map((line) => {
        const parts = line.split(',').map((part) => part.trim());
        const name = parts[0] || 'Unknown';
        const memoryUsed = Number(parts[2]);
        const memoryTotal = Number(parts[3]);

        return {
            name,
            memoryTotal,
            memoryUsed
        };
    });
};

const getHardwareStatus = async () => {
    const gpu = await getGpuInfo();

    return {
        gpu
    };
};

module.exports = { getHardwareStatus };
