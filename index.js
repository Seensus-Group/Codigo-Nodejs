//Import gerenciador de ambiente
require("dotenv").config();

//Import dos mmódulos
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

/* ----------------------- Warning ---------------------------------
Apesar de aceitar uma String, havia um erro na criptografia da senha que foi resolvido da seguinte maneira:
É preciso converter a quantidade de rounds que estamos passando via env para número. Pois quando passamos com o env,
Ele é interpretado como String, e o bcrypt não está conseguindo reconhecer o valor. Então para resolver o problema
foi criada uma constante de saltos que teve seu valor convertido para int.
*/
const salt = parseInt(process.env.SALT);

//Instância do express representada por app
const app = express();

//Ativar a manipulação de dados em json
app.use(express.json());

//Adicionar o cors ao projeto
app.use(cors());


//Criação da conexão com o banco de dados MySQL
const con = mysql.createConnection({
    host: process.env.HOST_DB,
    database: process.env.NAME_DB,
    user: process.env.USER_DB,
    password: process.env.PASS_DB,
    port: process.env.PORT_DB
});

//Ativar conexão
con.connect((erro) => {
    if (erro) {
        return console.error(`Unexpected error at connection -> ${erro}`)
    }
    console.log(`Connection stabilized ${con.threadId}`)
});

/*
   ------------- LOJAS -----------------
*/
//Rota para inserir novas lojas
app.post("/store/insert", (req, res) => {
    //Criptografia da senha
    let sh = req.body.senha;
    bcrypt.hash(sh, salt, (error, result) => {
        if (!error) {
            //Devolucao da senha criptografada
            req.body.senha = result;
            con.query("INSERT INTO loja SET ?", [req.body], (error, result) => {
                if (!error)
                    return res.status(201).send({ output: `Inserted`, data: result });
                else return res.status(500).send({ output: `Internal error during request process`, erro: error });
            });
        }
        else return res.status(500).send({ output: `Unexpected internal error in password`, erro: error });
    });
});

//Rota para atualizar dados da loja (Senha, Email)
app.put("/store/update/:id", (req, res) => {
    let sh = req.body.senha;
    bcrypt.hash(sh, salt, (error, result) => {
        if (!error) {
            req.body.senha = result;
            con.query("UPDATE loja SET ? WHERE idloja=?", [req.body, req.params.id], (error, result) => {
                if (!error)
                    return res.status(202).send({ output: `Updated`, data: result });
                else return res.status(500).send({ output: `Internal error during request process`, erro: error });
            });
        }
        else return res.status(500).send({ output: `Unexpected internal error in password`, erro: error });
    });
});

//Rota para realizar login
app.post("/store/login", (req, res) => {
    con.query("SELECT * FROM loja WHERE email=?", [req.body.email], (error, result) => {
        if (!error) {
            if (!result || result == "" || result == null) {
             return res.status(400).send({ output: `Username or Password incorrect` });
            }
            bcrypt.compare(req.body.senha, result[0].senha, (err, equals) => {
                if (equals) {
                    const token = criarToken(result[0].idusuario, result[0].nomeusuario, result[0].email);
                    return res.status(200).send({ output: `Authenticated`, token: token });
                }
                else {
                    return res.status(400).send({ output: `Username or Password incorrect` });
                }
            })
        }
        else if (!result) {
            return res.status(400).send({ output: `Username or Password incorrect` });
        }
        else {
            return res.status(500).send({ output: `Unexpected internal error in password`, erro: error });
        }
    })
})

/*
   ------------- Avaliações -----------------
*/
//Rota para inserir novcas avaliações
app.post("/avaliacoes/insert", (req, res) => {
    con.query("INSERT INTO avaliacao SET ?", [req.body], (error, result) => {
        if (!error)
            return res.status(200).send({ output: `Inserted`, data: result})
        else return res.status(500).send({ output: `Internal error during request process`, erro: error})
    })
})
/*
   ------------- ROTAS DE LISTAGEM E CONSULTA -----------------
*/
//Rota para listar lojas
app.get("/store/list", (req, res) => {
    con.query("SELECT * FROM loja", (error, result) => {
        if (!error)
            return res.status(200).send({ output: `Ok`, data: result });
        else return res.status(500).send({ output: `Internal error during request process`, erro: error });
    });
});
app.get("/store/listbycategory", (req, res) => {
    let consulta = req.body.categoria
    con.query("SELECT * FROM loja WHERE categoria LIKE ?", [`%${consulta}%`], (error, result) => {
        if (!error)
            return res.status(200).send({ output: `Ok`, data: result });
        else return res.status(500).send({ output: `Internal error during request process`, erro: error });
    });
});
app.get("/store/listbyname", (req, res) => {
    let consulta = req.body.nome
    con.query("SELECT * FROM loja WHERE nome LIKE ?", [`%${consulta}%`], (error, result) => {
        if (!error)
            return res.status(200).send({ output: `Ok`, data: result });
        else return res.status(500).send({ output: `Internal error during request process`, erro: error });
    });
});



/*
   ------------- TOKEN -----------------
*/
//Criação do token para o usuário
function criarToken(id, email, nome) {
    return jwt.sign({ idloja: id, email: email, nome: nome}, process.env.JWT_KEY, {
        expiresIn: process.env.JWT_EXPIRES, algorithm: process.env.JWT_ALGORITHM
    });
};

//Verificar token existente
function verificarToken(req, res, next) {
    const token_enviado = req.headers.token;

    if (!token_enviado)
        return res.status(401).send({ output: `Access Denied` });

    jwt.verify(token_enviado, process.env.JWT_KEY, (error, result) => {
        if (error){
            return res.status(500).send({ output: `Internal error to verify token` });
        }
        else {
            req.content = {
                idloja: result.idloja,
                email: result.email,
                nome: result.nome
            };
            next();
        }
    });
};




app.listen(process.env.PORT, () => console.log(`Server online at: ${process.env.HOST_DB}:${process.env.PORT}`));