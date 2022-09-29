const mysql = require ('mysql');

var pool = mysql.createPool({
    "user": "root",
    "password" : "root",
    "database" : "learnote",
    "host" : "localhost", 
    "port" : 3306
});

exports.pool= pool;