import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Request } from 'express';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private prismaSerice: PrismaService) {}

  async getMyUser(id: string, req: Request) {
    const user = await this.prismaSerice.user.findUnique({
      where: { id: id },
      select: { id: true, email: true },
    });

    if (!user) throw new NotFoundException(`User ${id} not found`);

    const decodedUser = req.user as { id: string; email: string };

    if (user.id !== decodedUser.id)
      return new ForbiddenException(`User ${decodedUser.id}`);

    return user;
  }

  async getUsers() {
    return await this.prismaSerice.user.findMany({
      select: { id: true, email: true },
    });
  }
}
