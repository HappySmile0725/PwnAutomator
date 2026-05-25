const bcrypt = require('bcrypt');
const { addUser, getUserById } = require('./user.service');

const register = async (id, password) => {
    if (await getUserById(id)) {
        return { success: false, message: 'ID already exists' };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await addUser(id, hashedPassword);
    return { success: true };
};

module.exports = register;
