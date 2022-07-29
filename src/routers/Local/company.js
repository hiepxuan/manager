<<<<<<< HEAD
const express = require('express');
const router = express.Router();
const companyController = require('../../app/Controller/CompanyController');
const sortMiddleware = require('../../app/Middleware/SortMiddlewar');
const multipartUpload = require('../../app/Middleware/multipleUploadMiddleware');
const multipart = require('connect-multiparty');
const multipartMiddleware = multipart();

router.get('/', sortMiddleware, companyController.index);
router.get('/add', companyController.add);
router.post('/add', multipartUpload, companyController.store);
router.delete('/delete/:id', companyController.del);
module.exports = router;
=======
const express = require('express')
const router = express.Router()
const companyController = require('../../app/Controller/CompanyController')
const sortMiddleware = require('../../app/Middleware/SortMiddlewar')
const multipartUpload = require('../../app/Middleware/multipleUploadMiddleware')
const multipart = require('connect-multiparty');
const multipartMiddleware = multipart();

router.get('/', sortMiddleware, companyController.index)
router.get('/add', companyController.add)
router.post('/add', multipartUpload, companyController.store)
router.delete('/delete/:id', companyController.del)
module.exports = router
>>>>>>> 9976f261982f6fd2df5b85cfcaee3acac0ed7665
