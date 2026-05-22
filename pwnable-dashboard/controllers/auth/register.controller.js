const registerService = require('../../services/auth/register.service');

const showRegister = (req, res) => {
    res.render('auth/register', { title: 'Register' });
};

const register = async (req, res) => {
    const { id, pwd } = req.body;

    if (!id || !pwd) {
        return res.status(400).render('auth/register', {
            title: 'Register',
            error: 'ID and Password are required.'
        });
    }

    const result = await registerService(id, pwd);
    if (!result.success) {
        return res.status(409).render('auth/register', {
            title: 'Register',
            error: result.message || 'ID already exists.'
        });
    }

    return res.status(201).redirect('/auth/login');
};

module.exports = {
    register,
    showRegister
};
