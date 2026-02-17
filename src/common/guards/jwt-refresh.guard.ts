import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtRefreshGuard extends AuthGuard('jwt-refresh') {
  handleRequest<TUser>(err: Error | null, user: TUser) {
    if (err || !user) {
      throw err ?? new UnauthorizedException('Invalid or expired refresh token');
    }
    return user;
  }
}
