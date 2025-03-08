import dbLocal from "db-local";
import { randomUUID } from "crypto";
import bcrypt from 'bcrypt';
const {Schema} = new dbLocal({path: './db'});


const User = Schema('User' ,{
    id:{type: String , require: true},
    username:{type: String , require: true},
    password:{type: String , require: true},
})

export class UserRepository{
    static  create({username, password}) {
        //1 Validaciones de username (opcional : zod)
        Validation.username(username);
        Validation.password(password);

        //2 Asegurarse que el username no exista
        const user = User.findOne({username});
        if(user) {
            throw new Error('username ya existe');
        }
        const id = randomUUID();
        const hashedPassword = bcrypt.hash(password, 10);

        User.create({_id: id, username, password:hashedPassword}).save();

        return id;
    };
    static async login({username, password}) {
        Validation.username(username);
        Validation.password(password);
        const user = User.findOne({username});
        if(!user) {
            throw new Error('username no existe');
        }
        const isValid = await bcrypt.compareSync(password, user.password);
        if(!isValid) {
            throw new Error('password invalido');
        }

        const { password:_, ...publicUser} = user;

        return publicUser;
    };
}

class Validation {
    static username(username){
        if(typeof username !== 'string' || username.length < 4) {
            throw new Error('username invalido');
        }
    }
    static password(password){
        if(typeof password !== 'string' || password.length < 6) {
            throw new Error('username invalido');
        }
    }
}