import { ConfigService } from '@nestjs/config';
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entity/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { envVariableKeys } from 'src/comm/const/env.const';
import { JwtService } from '@nestjs/jwt';
import { splitToken, validateEmail } from 'src/comm/util/util';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  parseBasicToken(rawToken: string) {
    const basicSplit = splitToken(rawToken);

    if (basicSplit.length !== 2) {
      throw new BadRequestException('토큰 포멧이 잘못됐습니다.');
    }

    const [basic, token] = basicSplit;

    if (basic.toLocaleLowerCase() !== 'basic') {
      throw new BadRequestException('토큰 포멧이 잘못됐습니다.');
    }

    const decoded = Buffer.from(token, 'base64').toString('utf-8');

    const tokenSplit = decoded.split(':');

    if (tokenSplit.length !== 2) {
      throw new BadRequestException('토큰 포멧이 잘못됐습니다.');
    }

    const [email, password] = tokenSplit;

    if (!validateEmail(email)) {
      throw new BadRequestException('유효한 이메일 형식이 아닙니다.');
    }

    return {
      email,
      password,
    };
  }

  async parseRefreshToken(rawToken: string) {
    const cookieArray = rawToken.split(';').map((cookie) => cookie.trim());
    const refreshTokenCookie = cookieArray.find((cookie) =>
      cookie.startsWith('refreshToken='),
    );

    if (!refreshTokenCookie) {
      throw new BadRequestException('토큰 포멧이 잘못됐습니다.');
    }

    const refreshToken = refreshTokenCookie.split('=');
    if (refreshToken.length !== 2) {
      throw new BadRequestException('토큰 포멧이 잘못됐습니다.');
    }

    const [refresh, token] = refreshToken;

    if (refresh.toLowerCase() !== 'refreshtoken') {
      throw new BadRequestException('토큰 포멧이 잘못됐습니다.');
    }
    try {
      const payload = await this.jwtService.verify(token, {
        secret: this.configService.get<string>(
          envVariableKeys.refreshTokenSecret,
        ),
      });

      return payload;
    } catch (e) {
      throw new UnauthorizedException(e);
    }
  }

  async parseBearerToken(
    rawToken: string,
    isRefreshToken: boolean,
  ): Promise<any> {
    const basicSplit = splitToken(rawToken);

    if (basicSplit.length !== 2) {
      throw new BadRequestException('토큰 포멧이 잘못됐습니다.');
    }

    const [bearer, token] = basicSplit;
    if (bearer.toLowerCase() !== 'bearer') {
      throw new BadRequestException('토큰 포멧이 잘못됐습니다.');
    }

    try {
      const payload = await this.jwtService.verify(token, {
        secret: this.configService.get<string>(
          isRefreshToken
            ? envVariableKeys.refreshTokenSecret
            : envVariableKeys.accessTokenSecret,
        ),
      });

      if (isRefreshToken) {
        if (payload.type !== 'refresh') {
          throw new BadRequestException('Refresh 토큰을 입력 해주세요.');
        }
      } else {
        if (payload.type !== 'access') {
          throw new BadRequestException('Access 토큰을 입력 해주세요.');
        }
      }

      return payload;
    } catch (e) {
      throw new UnauthorizedException(e);
    }
  }

  async issueToken(user: Partial<User>, isRefreshToken: boolean) {
    const refreshTokenSecret = this.configService.get<string>(
      envVariableKeys.refreshTokenSecret,
    );
    const accessTokenSecret = this.configService.get<string>(
      isRefreshToken
        ? envVariableKeys.refreshTokenSecret
        : envVariableKeys.accessTokenSecret,
    );

    return await this.jwtService.signAsync(
      {
        sub: user.email,
        type: isRefreshToken ? 'refresh' : 'access',
      },
      {
        secret: isRefreshToken ? refreshTokenSecret : accessTokenSecret,
        expiresIn: isRefreshToken ? '30d' : '3h',
      },
    );
  }

  async verifyToken(token: string, isRefreshToken: boolean): Promise<any> {
    const secret = this.configService.get<string>(
      isRefreshToken
        ? envVariableKeys.refreshTokenSecret
        : envVariableKeys.accessTokenSecret,
    );

    try {
      const payload = await this.jwtService.verifyAsync(token, { secret });
      // 토큰 타입 검증
      if (
        (isRefreshToken && payload.type !== 'refresh') ||
        (!isRefreshToken && payload.type !== 'access')
      ) {
        throw new UnauthorizedException('잘못된 토큰 타입입니다.');
      }

      // 사용자 정보 추출
      const user = await this.userRepository.findOne({
        where: { email: payload.sub },
      });

      if (!user) {
        throw new UnauthorizedException('존재하지 않는 사용자입니다.');
      }

      return user;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('토큰이 만료되었습니다.');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('유효하지 않은 토큰입니다.');
      }
      throw error;
    }
  }

  async register(rawToken: string) {
    const { email, password } = this.parseBasicToken(rawToken);

    const user = await this.userRepository.findOne({ where: { email } });

    if (user) {
      throw new BadRequestException('이미 가입된 이메일 입니다');
    }

    const hashPassword = await bcrypt.hash(
      password,
      this.configService.get<string>(envVariableKeys.hashRounds),
    );

    await this.userRepository.save({
      email,
      password: hashPassword,
    });

    return this.userRepository.findOne({ where: { email } });
  }

  async authenticate(email: string, password: string) {
    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new BadRequestException('잘못된 로그인 정보입니다.');
    }
    const passOk = await bcrypt.compare(password, user.password);

    if (!passOk) {
      throw new BadRequestException('잘못된 로그인 정보입니다.');
    }

    return user;
  }

  async login(rawToken: string, response: Response) {
    const { email, password } = this.parseBasicToken(rawToken);

    const user = await this.authenticate(email, password);

    const refreshToken = await this.issueToken(user, true);
    const accessToken = await this.issueToken(user, false);

    const envMode =
      this.configService.get<string>(envVariableKeys.env) !== 'dev';

    // 쿠키 이름에서 역따옴표 제거 및 옵션 조정
    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: envMode ? 'strict' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return {
      accessToken,
      user: {
        email: user.email,
      },
    };
  }

  async logout(response: Response) {
    const envMode =
      this.configService.get<string>(envVariableKeys.env) !== 'dev';
    response.cookie('refreshToken', '', {
      httpOnly: true,
      secure: false,
      sameSite: envMode ? 'strict' : 'lax',
      expires: new Date(0), // 과거 날짜로 설정하여 즉시 만료
      path: '/',
    });

    return {
      success: true,
      message: '로그아웃 되었습니다.',
    };
  }
}
