const loginService = require('../../services/auth/login.service');

const showLogin = (req, res) => {
    res.render('auth/login', { title: 'Login' });
};

const login = async (req, res) => {
    const { id, pwd } = req.body;

    if (!id || !pwd) {
        return res.status(400).render('auth/login', {
            title: 'Login',
            error: 'ID and Password are required.'
        });
    }

    const result = await loginService(id, pwd);
    if (!result.success) {
        return res.status(401).render('auth/login', {
            title: 'Login',
            error: 'Invalid ID or Password.'
        });
    }

    req.session.user = { id: result.user.id };
    req.session.save(() => res.status(200).redirect('/dashboard'));
};

const logout = (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/auth/login');
    });
};

module.exports = {
    login,
    logout,
    showLogin
};
