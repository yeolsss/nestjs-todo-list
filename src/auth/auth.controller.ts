import {
  ClassSerializerInterceptor,
  Controller,
  Headers,
  Post,
  Req,
  Res,
  UseInterceptors,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  registerUser(@Headers('authorization') token: string) {
    return this.authService.register(token);
  }

  @Post('login')
  async login(
    @Headers('authorization') token: string,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.login(token, response);
  }

  @Post('token/issue')
  async rotateAccessToken(@Req() request: Request) {
    const refreshToken = request.headers.cookie;
    const payload = await this.authService.parseRefreshToken(refreshToken);
    const user = { email: payload.sub };

    return {
      accessToken: await this.authService.issueToken(user, false),
    };
  }

  @Post('logout')
  async logout(@Res({ passthrough: true }) response: Response) {
    return this.authService.logout(response);
  }
}
