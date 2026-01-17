const fs = require('fs');

const setupLines = [
    'RUN apt-get update && apt-get install -y tzdata',
    'RUN ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime && dpkg-reconfigure -f noninteractive tzdata',
    '',
    'RUN apt-get update',
    'RUN apt-get install net-tools -y',
    'RUN apt-get install git -y',
    'RUN apt-get install vim -y',
    'RUN git clone https://github.com/longld/peda.git ~/peda',
    'RUN echo "source ~/peda/peda.py" >> ~/.gdbinit',
    'RUN apt-get install openssh-server -y',
    '',
    'RUN apt-get install python3 -y',
    'RUN apt-get install python3-pip -y',
    'RUN apt-get install python3-venv -y',
    'RUN python3 -m venv /opt/venv',

    'ENV PATH="/opt/venv/bin:$PATH"',
    'RUN pip install --upgrade pip',
    'RUN python3 -m pip install --upgrade pip',
    'RUN python3 -m pip install pwntools',
    'RUN cd ~/',
    'RUN git clone https://github.com/scwuaptx/Pwngdb.git'
];

const applyDockerfileSetup = (dockerfilePath) => {
    const content = fs.readFileSync(dockerfilePath, 'utf8');
    if (content.includes('https://github.com/longld/peda.git') || content.includes('https://github.com/scwuaptx/Pwngdb.git')) {
        return;
    }

    const lineEnding = content.includes('\r\n') ? '\r\n' : '\n';
    const lines = content.split(/\r?\n/);
    const insertIndex = Math.min(2, lines.length);
    lines.splice(insertIndex, 0, ...setupLines);
    fs.writeFileSync(dockerfilePath, lines.join(lineEnding));
};

module.exports = { applyDockerfileSetup };