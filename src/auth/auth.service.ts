import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';


@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name)
        private userModel:Model<User>,
        private jwtService :JwtService
    ){}
    async signUp(signUpDto:SignUpDto){
        const {name ,email,password}=signUpDto

        const existingUser = await this.userModel.findOne({email});
        if (existingUser) {
           if (existingUser) {
             throw new ConflictException('User already exists');
           }
        }


        const hashedPassword= await bcrypt.hash(password,10);

        const user =await this.userModel.create({
            name,
            email,
            password:hashedPassword
        })

        return {
          message: 'User registered successfully',
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
          },
        };
    }

    async login (loginUpDto:LoginDto){
        const {email,password}=loginUpDto;

        const user = await this.userModel.findOne({email});

        if(!user){
            throw new UnauthorizedException("User Not Found");
        }

        const isMatchedPassword = await bcrypt.compare(password, user.password);

        if(!isMatchedPassword){
           throw new UnauthorizedException("Invalid Email or Password");
        }
        const token =this.jwtService.sign({id:user._id});
         return {
           message: 'User Login successfully',
           user: {
             id: user._id,
             name: user.name,
             email: user.email,
             token
           },
         };
    }
}
