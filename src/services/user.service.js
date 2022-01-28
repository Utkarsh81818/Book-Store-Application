/* eslint-disable max-len */
/* eslint-disable prettier/prettier */
/* eslint-disable no-unused-vars */
import User from '../models/user.model';
import bcrypt from 'bcrypt';

//create new user
export const newUser = async (body) => {
  const HashedPassword = await bcrypt.hash(body.password, 10);
  body.password = HashedPassword;
  const data = await User.create(body);
  return data;
};