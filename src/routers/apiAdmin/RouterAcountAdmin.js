const express = require('express');
const router = express.Router();
const acountAdminController = require('../../app/Controller/adminController/AcountAdminController');
const CheckLoginAdmin = require('../../app/Middleware/CheckLoginAdmin');
router.post('/login', acountAdminController.login);
router.get('/', CheckLoginAdmin, acountAdminController.check);
router.get('/logout', acountAdminController.logout);

module.exports = router;
