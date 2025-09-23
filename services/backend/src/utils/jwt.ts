import jwt from 'jsonwebtoken';

const generateToken = (userId: string) => {
  const JWT_SECRET = process.env.JWT_SECRET!;
  return jwt.sign(
    { id: userId }, 
    JWT_SECRET, 
    { expiresIn: '1h' }
  );
};

const verifyToken = (token: string) => {
  const JWT_SECRET = process.env.JWT_SECRET!;
  return jwt.verify(token, JWT_SECRET);
};

export default {
  generateToken,
  verifyToken
}