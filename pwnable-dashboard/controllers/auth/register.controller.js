const express = require('express');
const router = express.Router();

const register = require('../../services/auth/register.service');

router.get('/register', async(req, res) => {
    res.render('auth/register');
});

router.post('/register', async(req, res) => {
    const { id, pwd } = req.body;
    if(!id || !pwd) {
        return res.status(400).render('auth/register', {
            title: 'Register',
            error: 'ID and Password are required.'
        });
    }

    const result = await register(id, pwd);

    if(result.success) {
        return res.status(201).redirect('/auth/login');
    } else {
        return res.status(409).render('auth/register', {
            title: 'Register',
            error: 'ID already exists.'
        });
    }
});

module.exports = router;