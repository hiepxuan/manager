const express = require('express');
const router = express.Router();
const acountAdminController = require('../../app/Controller/admin/AcountAdmin');
const CheckLoginAdmin = require('../../app/Middleware/CheckLoginAdmin');
router.post('/login', acountAdminController.login);
router.get('/', CheckLoginAdmin, acountAdminController.check);

module.exports = router;
