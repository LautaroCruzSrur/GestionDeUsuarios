import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import jtw from 'jsonwebtoken';
import {UserRepository} from './user-repositori.js';


dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());//para que express pueda leer el body de las peticiones
app.use(cookieParser());

app.use((req, res, next) => {
    const token = req.cookies.access_token;

    req.session = {user: null};//inicializamos la sesion
    try{
        data = jtw.verify(token, process.env.SECRET);
        req.session.user = data;//guardamos el usuario en la sesion
    }catch(error){ 
        req.session.user = null;//si hay un error limpiamos la sesion
    }
    next(); //segimos con la siguiente funcion
})

app.get('/', (req, res) => { 
    console.log("Hola mundo");
});


app.post('/login', async(req, res) => { 
    const {username, password} = req.body;
    try{
        const user = await UserRepository.login({username, password});
        const token = jtw.sign({id: user._id, username: user.username}, process.env.SECRET,{expiresIn: '1h'});

        res
        .cookie('access_token', token, {httpOnly: true //solo se puede acceder desde el servidor 
        , secure: true,//solo se puede acceder desde https
        sameSite:'strict',//solo se puede acceder desde el mismo dominio
        maxAge: 1000 * 60 *60}) //la cookie expira en 1 hora
        .send({user, token});
    }catch(error){
        res.status(400).json({error: error.message});
    }
});

app.post('/register', (req, res) => {
    const {username, password} = req.body;
    try {
        const id =  UserRepository.create({username, password});
        res.json({id});
    } catch (error) {
        res.status(400).json({error: error.message});
    }
});
app.post('/logout', (req, res) => {
    res.clearCookie('access_token').send().json({message: 'sesion cerrada'});
});

app.get('/protected', (req, res) => {
    const {user} = req.session;
    if(!user) {
        return res.status(403).json({error: 'no autorizado'});
    }
    res.status(200).json({message: 'contenido protegido'});

});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
