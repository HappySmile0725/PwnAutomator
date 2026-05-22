const { inspectContainer } = require('./docker.service');

const mapPorts = (ports) => Object.entries(ports || {}).flatMap(([containerPort, bindings]) => {
    if (!Array.isArray(bindings) || bindings.length === 0) {
        return [{ containerPort, hostIp: null, hostPort: null }];
    }

    return bindings.map((binding) => ({
        containerPort,
        hostIp: binding.HostIp || '127.0.0.1',
        hostPort: binding.HostPort || null
    }));
});

const inspectRuntime = async (containerIdOrName) => {
    const info = await inspectContainer(containerIdOrName);
    return {
        inspectedAt: new Date().toISOString(),
        containerId: info.Id,
        name: String(info.Name || '').replace(/^\//, ''),
        image: info.Config?.Image || info.Image,
        state: {
            status: info.State?.Status || 'unknown',
            running: Boolean(info.State?.Running),
            startedAt: info.State?.StartedAt || null,
            exitCode: info.State?.ExitCode ?? null
        },
        process: {
            entrypoint: info.Config?.Entrypoint || [],
            command: info.Config?.Cmd || [],
            workingDir: info.Config?.WorkingDir || '/'
        },
        network: {
            ports: mapPorts(info.NetworkSettings?.Ports)
        },
        environment: info.Config?.Env || []
    };
};

module.exports = { inspectRuntime };
