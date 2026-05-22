const bcrypt = require('bcrypt');
const { getUsername, writeUser } = require('./user.service');

const register = async (id, password) => {
    const existingUsers = await getUsername(id);
    if (existingUsers.length > 0) {
        return { success: false, message: 'ID already exists' };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await writeUser(id, hashedPassword);
    return { success: true };
};

module.exports = register;
