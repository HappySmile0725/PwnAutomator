const express = require('express');
const router = express.Router();

const login = require('../../services/auth/login.service');

router.get('/login', (req, res) => {
    res.render('auth/login');
});

router.post('/login', async(req, res) => {
    const { id, pwd } = req.body;
    
    if(!id || !pwd) {
        return res.status(400).render('auth/login', {
            title: 'Login',
            error: 'ID and Password are required.'
        });
    }

    const result = await login(id, pwd);

    if(result.success) {
        req.session.user = { id: result.user.id };
        req.session.save();

        return res.status(200).redirect('/dashboard');
    } else {
        return res.status(401).render('auth/login', {
            title: 'Login',
            error: 'Invalid ID or Password.'
        });
    }
});

router.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        return res.redirect('/auth/login');
    });
});

module.exports = router;
