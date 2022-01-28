/* eslint-disable max-len */
/* eslint-disable prettier/prettier */
/* eslint-disable no-unused-vars */
import User from '../models/user.model';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

//create new user
export const newUser = async (body) => {
  const HashedPassword = await bcrypt.hash(body.password, 10);
  body.password = HashedPassword;
  const data = await User.create(body);
  return data;
};

//Login User
export const login = async (body) => {
  const check = await User.findOne({ email: body.email });
  if (check) {
    const match = await bcrypt.compare(body.password, check.password);
    if (match) {
      const token = jwt.sign({ email: check.email, id: check._id, role: check.role }, process.env.SECRET, { expiresIn: '98h' });
      return token;
    } else {
      return 'Incorrect Password'
    }
  } else {
    return 'Not Registered Yet';
  }
};