const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('server', 'root', '123456@', {
    host: '127.0.0.1',
    dialect: 'mysql' /* one of 'mysql' | 'mariadb' | 'postgres' | 'mssql' */,
});
// const sequelize = new Sequelize(
//     'd598v9c7csf6te',
//     'gwmfbmdxxossol',
//     'f793beeaa429b93627166b5482f326e15d63dd2a7253ae2c2c7482ff0cef74a2',
//     {
//         host: 'ec2-54-161-255-125.compute-1.amazonaws.com',
//         dialect:
//             'postgres' /* one of 'mysql' | 'mariadb' | 'postgres' | 'mssql' */,

//         logging: false,
//         dialectOptions: {
//             ssl: {
//                 require: true,
//                 rejectUnauthorized: false,
//             },
//         },
//     },
// );
const connectDB = async () => {
    try {
        await sequelize.authenticate();
        console.log('Connection has been established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
};
module.exports = connectDB;
