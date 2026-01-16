const express = require('express');
const router = express.Router();

router.get('/result', function(req, res) {
    res.render('dashboard/result', {
        title: 'Dashboard',  
    });
});

module.exports = router;