require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const app = express();

//config JSON response
app.use(express.json()); //understand json files

//Models
const User = require('./models/User')

// Open route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a API!' });
});

// Private Route
app.get('/user/:id', async (req, res) => {
    const id = req.params.id;

    //check if user exist
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ msg: 'usuario nao encontrado' })
    }
})

//Register user
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body

    //validations
    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório' });
    }
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório' });
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatório' });
    }
    if (password !== confirmpassword) {
        return res.status(422).json({ msg: 'A senhas não são iguais' });
    }

    // check if user exist
    const userExist = await User.findOne({ email: email }) // find email


    if (userExist) {
        return res.status(422).json({ msg: 'Utilize outro email' });
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user

    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save()

        res.status(201).json({ msg: 'Usuario criado com sucesso' })

    } catch (error) {
        res.status(500)
            .json({
                msg: 'Aconteceu um erro no servidor',
            })
    }
});

app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    // validations
    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório!" });
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória!" });
    }

    // check if user exists
    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida" });
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret
        );

        res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
    } catch (error) {
        res.status(500).json({ msg: "Autenticação sem sucesso!", token });
    }
});



// Credencials
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.iorpwks.mongodb.net/?retryWrites=true&w=majority`,)
    .then(() => {
        app.listen(3000);
        console.log('Conectou ao banco!');
    })
    .catch((err) => console.log(err));