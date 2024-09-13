import { Router, Request, Response, NextFunction } from 'express';
import { User, IUser } from '../models/user.model';
import bcrypt from 'bcrypt';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { z } from 'zod';

const router = Router();

interface IUserRequest extends Request {
  userData: IUserData
}

interface IUserData {
  id: string;
  email: string;
}

const userSchema = z.object({
  email: z.string().email(),
  password: z.string().min(3)
});

type UserType = z.infer<typeof userSchema>;

const validateUserInput = (input: UserType) : UserType => {
  return userSchema.parse(input);
}

const accessValidation = (req: Request, res: Response, next: NextFunction) => {
  try {
    const validationReq = req as IUserRequest;
    
    const { authorization } = validationReq.headers;
    if (!authorization) throw new Error('Token diperlukan');

    const token: string = authorization.split(' ')[1];
    if (!token) throw new Error('Format token salah');

    const secret: string | undefined = process.env.JWT_SECRET;
    if (!secret) throw new Error('JWT_SECRET di .env masih kosong');

    const jwtDecode: string | JwtPayload = jwt.verify(token, secret);
    if (typeof jwtDecode === 'string') throw new Error('Tipe data jwt adalah object bukan string');
    
    validationReq.userData = {
      id: jwtDecode.id,
      email: jwtDecode.email
    } as IUserData;
    if (!validationReq.userData) throw new Error('userData tidak ada isinya');

    next();

  } catch(e) {
    next(e);
  }
}

router.post('/register', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password }: UserType = validateUserInput(req.body);

    const hashPassword: string = await bcrypt.hash(password, 10);
    const user: IUser = await User.create({
      email,
      password: hashPassword
    });

    res.status(201).json({
      data: {
        user
      }
    });
  } catch (e) {
    next(e);
  }
});

router.post('/login', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password }: UserType = validateUserInput(req.body);

    const user: IUser | null = await User.findOne({
      email: email
    })
    if (!user) throw new Error('Email belum terdaftar');

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) throw new Error('Password salah');

    const payload: JwtPayload = {
      id: user._id,
      email: user.email
    };

    const expiresIn: number = 60 * 60 * 1 // 1 jam;
    const secret: string | undefined = process.env.JWT_SECRET;
    if (!secret) throw new Error('JWT_SECRET di .env masih kosong');

    const token: string = jwt.sign(payload, secret, { expiresIn: expiresIn });

    res.status(200).json({
      data: {
        user
      },
      token: token
    });
  } catch (e) {
    next(e);
  }
});

router.get('/profile', accessValidation, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userReq = req as IUserRequest;
    const user: IUserData | null = await User.findById(userReq.userData.id).select({ _id: 1, email: 1 });
    if (!user) throw new Error('User tidak ditemukan');

    res.status(200).json({
      data: user
    });
  } catch (e) {
    next(e);
  }
});

router.patch('/profile', accessValidation, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const validEmail = z.string().email().parse(req.body.email);
    const userReq = req as IUserRequest;
    const user: IUserData | null = await User.findByIdAndUpdate(userReq.userData.id, { email: validEmail }, { new: true, runValidators: true }).select({ _id: 1, email: 1 });
    if (!user) throw new Error('User tidak ditemukan');

    res.status(200).json({
      data: user
    });
  } catch (e) {
    next(e);
  }
});

export default router;