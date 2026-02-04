const fs = require('fs').promises;
const path = require('path');

const getUsername = async (id) => {
    try {
        const dataPath = path.join(__dirname, '..', '..', 'data', 'cred.json');

        // Initial check if file exists to prevent error on first read
        try {
            await fs.access(dataPath);
        } catch {
            return null;
        }

        const rawData = await fs.readFile(dataPath, 'utf-8');
        if (!rawData || rawData.trim().length === 0) {
            return null;
        }
        const usersData = JSON.parse(rawData);

        return usersData.filter(user => user.id === id);
    } catch (error) {
        console.error('Error in getUsername:', error);
        return null;
    }
};

const writeUser = async (id, hashedPassword) => {
    try {
        const dataPath = path.join(__dirname, '..', '..', 'data', 'cred.json');
        let usersData = [];

        try {
            const rawData = await fs.readFile(dataPath, 'utf-8');
            if (rawData && rawData.trim().length > 0) {
                usersData = JSON.parse(rawData);
            }
        } catch (error) {
            // Ignore error if file doesn't exist, start with empty array
            if (error.code !== 'ENOENT') {
                console.error('Error reading user data for write:', error);
            }
        }

        usersData.push({ id, password: hashedPassword });
        await fs.writeFile(dataPath, JSON.stringify(usersData, null, 2), 'utf-8');
        return true;
    } catch (error) {
        console.error('Error in writeUser:', error);
        return false;
    }
}

module.exports = { getUsername, writeUser };
