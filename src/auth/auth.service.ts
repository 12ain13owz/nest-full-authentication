import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { compare, genSalt, hash } from 'bcrypt';
import { AuthDto } from './dto/auth.dto';
import { PrismaService } from 'prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constants';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signup(authDto: AuthDto) {
    const { email, password } = authDto;
    const foundUser = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (foundUser) throw new BadRequestException('Email already exists');

    const user = await this.prismaService.user.create({
      data: {
        email: email,
        password: await this.hashPassword(password),
      },
    });

    const result = this.exclude(user, ['password']);
    return { message: 'Successfully signed up', user: result };
  }

  async signin(authDto: AuthDto, req: Request, res: Response) {
    const { email, password } = authDto;

    const foundUser = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (!foundUser) throw new BadRequestException('Wrong credentials');

    const isCompare = await this.comparePassword(password, foundUser.password);
    if (!isCompare) throw new BadRequestException('Wrong credentials');

    const token = await this.signAccessToken(foundUser.id, foundUser.password);
    if (!token) throw new ForbiddenException();

    res.cookie('token', token);

    return { message: 'Successfully signed in', token: token };
  }

  async signout(req: Request, res: Response) {
    res.clearCookie('token');
    return { message: 'Successfully signed out' };
  }

  async hashPassword(password: string) {
    const salt = await genSalt(10);
    return await hash(password, salt);
  }

  async comparePassword(password: string, hash: string): Promise<boolean> {
    return await compare(password, hash);
  }

  private exclude<User, Key extends keyof User>(
    user: User,
    keys: Key[],
  ): Omit<User, Key> {
    return Object.fromEntries(
      Object.entries(user).filter(([key]) => !keys.includes(key as Key)),
    ) as Omit<User, Key>;
  }

  async signAccessToken(id: string, email: string): Promise<string> {
    const payload = { id, email };
    return this.jwtService.signAsync(payload, { secret: jwtSecret });
  }
}
