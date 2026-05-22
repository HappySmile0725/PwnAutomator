const fs = require('fs').promises;
const path = require('path');

const credPath = path.join(__dirname, '..', '..', 'data', 'cred.json');

const readUsers = async () => {
    try {
        const rawData = await fs.readFile(credPath, 'utf-8');
        const users = JSON.parse(rawData || '[]');
        return Array.isArray(users) ? users : [];
    } catch (error) {
        if (error.code === 'ENOENT') {
            return [];
        }
        throw error;
    }
};

const writeUsers = async (users) => {
    await fs.mkdir(path.dirname(credPath), { recursive: true });
    await fs.writeFile(credPath, JSON.stringify(users, null, 2), 'utf-8');
};

module.exports = {
    readUsers,
    writeUsers
};
