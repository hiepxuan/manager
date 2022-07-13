<<<<<<< HEAD
const express = require('express')
const router = express.Router()
const postController = require('../../app/Controller/PostController')
const sortMiddleware = require('../../app/Middleware/SortMiddlewar')
const multipartUpload = require('../../app/Middleware/multipleUploadMiddleware')
const multipart = require('connect-multiparty');
const multipartMiddleware = multipart();

router.get('/', sortMiddleware, postController.index)
router.get('/add', postController.add)
router.post('/add', multipartUpload, postController.store)
router.delete('/delete/:id', postController.del)
module.exports = router
=======
const express = require('express');
const router = express.Router();
const postController = require('../../app/Controller/PostController');
const sortMiddleware = require('../../app/Middleware/SortMiddlewar');
const multipartUpload = require('../../app/Middleware/multipleUploadMiddleware');
const multipart = require('connect-multiparty');
const multipartMiddleware = multipart();

router.get('/', sortMiddleware, postController.index);
router.get('/add', postController.add);
router.post('/add', multipartUpload, postController.store);
router.delete('/delete/:id', postController.del);
module.exports = router;
>>>>>>> 824002c33fca7156164424210b4addd4c4fcf576
