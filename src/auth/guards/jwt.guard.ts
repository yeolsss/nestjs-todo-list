import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('인증 토큰이 필요합니다.');
    }

    const token = authHeader.split(' ')[1];

    try {
      // AuthService의 verifyToken 메서드를 사용하여 토큰 검증 및 사용자 정보 추출
      // false를 전달하여 액세스 토큰으로 검증
      const user = await this.authService.verifyToken(token, false);

      // 검증 성공 시 요청 객체에 사용자 정보 추가
      request.user = user;
      return true;
    } catch (error) {
      // AuthService에서 토큰 관련 예외처리를 이미 수행하지만, 추가 처리가 필요한 경우
      if (error instanceof UnauthorizedException) {
        throw error; // AuthService에서 발생한 예외 그대로 전달
      }

      // 기타 예외 처리
      throw new UnauthorizedException('인증에 실패했습니다.');
    }
  }
}
