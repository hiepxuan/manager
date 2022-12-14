const jwt = require('jsonwebtoken');
const createError = require('http-errors');

function CheckLoginAdmin(req, res, next) {
    const authHeader = req.header('Authorization');
    if (authHeader) {
        
        const token = authHeader.split(' ')[0];
        jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
            if (err) next(createError(403, 'Token not valid'));
            req.user = user;
            const { exp, isAdmin, email } = user;
            if (exp * 1000 < Date.now()) {
                next(createError(401, 'Token not valid'));
            }
            next();
        });
    } else {
        next(createError(401, 'Bạn chưa đăng nhập0'));
    }
}
module.exports = CheckLoginAdmin;
