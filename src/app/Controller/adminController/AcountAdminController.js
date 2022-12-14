const db = require('../../../../models');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const salt = bcrypt.genSaltSync(saltRounds);
const jwt = require('jsonwebtoken');
const createError = require('http-errors');

class AcountAdmin {
    login = async (req, res, next) => {
        // try {
            const { email, password } = req.body;
            const user = await db.User.findOne({
                where: { email },
            });

            if (!user) {
                next(createError(400, 'Mật khẩu hoặc email Không chính xác!'));

            } else {
                const { verified } = user;
                if (!verified) {
                    next(
                        createError(
                            400,
                            'Mật khẩu hoặc email Không chính xác!',
                        ),
                    );

                } else {
                    const { isAdmin } = user;
                    if (!isAdmin) {
                        next(
                            createError(
                                401,
                                'Permission denied!',
                            ),
                        );

                    }
                    const valiPassWord = await bcrypt.compareSync(
                        password,
                        user.password,
                    );
                    if (!valiPassWord) {
                        next(
                            createError(
                                401,
                                'Mật khẩu hoặc email Không chính xác!',
                            ),
                        );

                    }
                    const token = await jwt.sign(
                        {
                            id: user.id,
                            email: user.email,
                            isAdmin: true,
                            roles:user.roles
                        },
                        process.env.SECRET_KEY,
                        { expiresIn: '1d' },
                    );

                    return res.status(200).json({
                        message: 'Đăng nhập thành công!',
                        success: true,
                        token: token,
                        name: user.name,
                        roles: user.roles,
                        isAdmin
                    });
                }
            }
        // } catch (error) {
        //     next(createError.InternalServerError('Kết nối đến server looi'));
        // }
    };
    check = async (req, res, next) => {
        try {
            const user = req.user;
            const { exp, isAdmin, email } = user;
          
                if (!isAdmin) {
                    next(createError(401, 'Bạn chưa đăng nhập2'));
                }
                const data = await db.User.findOne({
                    where: { email },
                    attributes: { exclude: ['password'] },
                });
                const { verified } = data;
                if (!verified) {
                    next(createError(401, 'Bạn chưa đăn nhập3'));
                }
                if (data) {
                    return res.status(200).json({
                        success: true,
                        data,
                        exp,
                    });
                } else {
                    next(createError(401, 'Chưa đăng nhập'));
            }
        } catch (error) {
            next(createError(500, 'Không thể kết nối tới server'));
        }
    };
    logout = (req,res)=>{
return  res.status(200).json({
    success:true,
    message:'logout'
})
    }
}
module.exports = new AcountAdmin();
