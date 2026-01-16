const bcrypt = require('bcrypt');
const { writeUser } = require('../user.service');

const register = async (id, password) => {
    const hashedPassword = await bcrypt.hash(password, 10);
    await writeUser(id, hashedPassword);
    return { success: true };
};

module.exports = register;
