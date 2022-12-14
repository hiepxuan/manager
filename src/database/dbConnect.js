
const mysql = require('mysql')
const config = require('../config/db')
const db = mysql.createConnection(config.mysql);

module.exports = {
    load: sql => {
        return new Promise((resolve, reject) => {
            db.connect()
            db.query(sql, (error, results, fields) => {
                if (error) {
                    reject(error)
                } else {
                    resolve(results)
                }
                db.end()
            })

        })
    },
    // add: (tableName, )
}
module.exports = db
