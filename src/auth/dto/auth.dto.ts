import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class AuthDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  @Length(4, 20, { message: 'Password has to be at between 4 and 20 char' })
  password: string;
}
