const express = require('express');
const router = express.Router();
const mysql = require('./mysql').pool;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const storage = multer.diskStorage({
    destination: function(req, file, cb){
        cb(null, './uploads/');
    },
    filename: function(req, file, cb){
        cb(null, new Date().toISOString() + file.originalname)
    }
});

const fileFilter = (req,file, cb)=>{
    if(file.nimetype === 'image/png' || file.nimetype === 'image/jpeg' ){
        cb(null, true);

    }else{
        cb(null, false);
    }
    
}

const upload = multer({ storage: storage,
    limits:{
        fieldSize: 1024 * 1024 *5
    },
    fileFilter: fileFilter

});



//const { response } = require('express');


router.post('/cadastro', (req, res, next)=>{
  
    mysql.getConnection((error, conn)=>{
        if(error) {return res.status(500).send({error2:error})}
        bcrypt.hash(req.body.usu_senha, 16, (errBcrypt,hash)=>{
            if(errBcrypt){return res.status(500).send({ error1:errBcrypt})}

            conn.query(' INSERT INTO usu_usuario(usu_nome, usu_email,usu_senha,per_codigo) VALUES(?,?,?,?)',[req.body.usu_nome,req.body.usu_email,hash,req.body.per_codigo],
             (error,results) =>{
                conn.release();
                if(error) {return res.status(500).send({error3:error})}
                response= {
                    mensagem: 'Usuário criado com sucesso',
                    usuariocriado: {
                        usu_codigo:results.INSERTid,
                        nome : req.body.usu_nome,
                        email: req.body.usu_email,
                        status: req.body.usu_status,
                        perfil: req.body.per_codigo,
                        
                    }
                }
                return res.status(201).send(response);

             } 
            )

        });
    });
})

router.post('/login', (req, res, next) => {
    mysql.getConnection((error, conn) => {
        if (error) { return res.status(500).send({ error: error })}
        const query = `SELECT * FROM usuario WHERE email = ?`;
        conn.query(query,[req.body.usu_email],(error, results, fiels) => {
            conn.release();
            if (error) { return res.status(500).send({ error: error })}
            if (results.length < 1) {
                return res.status(401).send({ mensagem: 'Falha na autenticação' })
            }
            bcrypt.compare(req.body.usu_senha, results[0].usu_senha, (err, result) => {
                if (err) {
                    return res.status(401).send({ mensagem: 'Falha na autenticação' }) 
                }
                if (result) {
                    const token = jwt.sign({
                        id_usuario: results[0].id_usuario,
                        email: results[0].usu_email
                    }, process.env.JWT_KEY,
                    {
                       expiresIn: "1h" 
                    })
                    return res.status(200).send({ mensagem: 'Autenticado com sucesso',
                    token: token
                 })
                }
                return res.status(401).send({ mensagem: 'Falha na autenticação' })
            })
        })
    })
})

module.exports = router;
