import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtConfigService } from '../../../config/jwt/config.service';
import { JwtPayloadInterface } from '../../interfaces/JwtUser.interface';
import { TokenStatusEnum } from '../../enums/tokenStatusEnum';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  // passport-jwt strategy 를 통해서 jwt token 을 검증 & payload 를 추출
  constructor(private jwtConfigService: JwtConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request): string => {
          return req?.cookies?.Authentication;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtConfigService.secret,
    });
  }

  async validate(payload: JwtPayloadInterface) {
    if (payload.status === TokenStatusEnum.SUCCESS) {
      return payload;
    } else {
      throw new UnauthorizedException('invalid token (token is not login token)');
    }
  }
}
